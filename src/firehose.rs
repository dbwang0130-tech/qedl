//! Firehose 协议客户端。对齐 bkerler/edl 的 firehose.py 关键路径:
//! connect / configure / getstorageinfo / get_gpt / read / program / erase / reset / peek / poke。

use crate::gpt::{self, Partition};
use crate::usb::UsbDev;
use crate::xml;
use anyhow::{anyhow, bail, Context, Result};
use std::fs::File;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

const XML_TIMEOUT: Duration = Duration::from_secs(5);
const DATA_TIMEOUT: Duration = Duration::from_secs(15);

pub struct Cfg {
    pub memory_name: String,
    pub sector_size: usize,
    pub max_payload_to_target: usize,
    pub max_payload_from_target: usize,
    pub max_xml: usize,
    pub target_name: String,
    pub block_size: u64,
    pub num_physical: u32,
    pub prod_name: String,
}

impl Cfg {
    pub fn new(memory_name: &str, sector_size: Option<usize>, max_payload: Option<usize>) -> Self {
        let mn = if memory_name.is_empty() {
            "UFS".to_string()
        } else {
            memory_name.to_string()
        };
        let ss = sector_size.unwrap_or_else(|| {
            if mn.eq_ignore_ascii_case("emmc") {
                512
            } else {
                4096
            }
        });
        Cfg {
            memory_name: mn,
            sector_size: ss,
            max_payload_to_target: max_payload.unwrap_or(1048576),
            max_payload_from_target: 8192,
            max_xml: 4096,
            target_name: String::new(),
            block_size: 0,
            num_physical: 0,
            prod_name: String::new(),
        }
    }
}

pub struct Response {
    pub ok: bool,
    pub value: String,
    pub raw: String,
    pub attrs: std::collections::HashMap<String, String>,
    pub logs: Vec<String>,
}

pub struct Firehose<'a> {
    usb: &'a UsbDev,
    pub cfg: Cfg,
    pub supported_functions: Vec<String>,
    pub serial: Option<u32>,
    pub skip_response: bool,
}

impl<'a> Firehose<'a> {
    pub fn new(usb: &'a UsbDev, cfg: Cfg) -> Self {
        Firehose {
            usb,
            cfg,
            supported_functions: Vec::new(),
            serial: None,
            skip_response: false,
        }
    }

    // ---- 底层 xml 交互 ----

    fn write_xml(&self, data: &str) -> Result<()> {
        let b = data.as_bytes();
        let n = b.len().min(self.cfg.max_xml);
        self.usb.write(&b[..n], XML_TIMEOUT)
    }

    /// 持续读取直到出现 `<response value` 或连续多次空读。
    fn read_response(&self) -> Result<Response> {
        let mut rdata = Vec::new();
        let mut empties = 0;
        let deadline = Instant::now() + Duration::from_secs(20);
        loop {
            let tmp = self.usb.read(self.usb.read_buf, XML_TIMEOUT)?;
            if tmp.is_empty() {
                empties += 1;
                if empties > 3 || Instant::now() > deadline {
                    break;
                }
                continue;
            }
            empties = 0;
            rdata.extend_from_slice(&tmp);
            if find(&rdata, b"<response value").is_some() {
                break;
            }
            if Instant::now() > deadline {
                break;
            }
        }
        Ok(self.parse_response(&rdata))
    }

    fn parse_response(&self, rdata: &[u8]) -> Response {
        let raw = xml::to_str(rdata);
        let logs = xml::logs(&raw);
        if let Some((value, attrs)) = xml::response(&raw) {
            let ok = value == "ACK" || value == "true";
            Response {
                ok,
                value,
                raw,
                attrs,
                logs,
            }
        } else {
            Response {
                ok: false,
                value: String::new(),
                raw,
                attrs: Default::default(),
                logs,
            }
        }
    }

    /// 发送 xml 并等待响应。
    fn xmlsend(&self, data: &str) -> Result<Response> {
        self.write_xml(data)?;
        if self.skip_response {
            return Ok(Response {
                ok: true,
                value: "ACK".into(),
                raw: String::new(),
                attrs: Default::default(),
                logs: Vec::new(),
            });
        }
        self.read_response()
    }

    // ---- 连接后读取 loader 启动横幅 ----

    pub fn connect(&mut self) -> Result<()> {
        let mut info: Vec<String> = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(5);
        loop {
            let v = self.usb.read(self.usb.read_buf, Duration::from_millis(400))?;
            if v.is_empty() {
                break;
            }
            let s = xml::to_str(&v);
            if s.contains("response") && s.contains("</data>") {
                for l in xml::logs(&s) {
                    info.push(l);
                }
                break;
            }
            for l in xml::logs(&s) {
                info.push(l);
            }
            if Instant::now() > deadline {
                break;
            }
        }
        self.parse_banner(&info);
        Ok(())
    }

    fn parse_banner(&mut self, info: &[String]) {
        let mut supfunc = false;
        for line in info {
            let low = line.to_lowercase();
            if low.contains("chip serial num") {
                if let Some(pos) = line.find("0x") {
                    let tail = &line[pos + 2..];
                    let hexs: String = tail
                        .chars()
                        .take_while(|c| c.is_ascii_hexdigit())
                        .collect();
                    if let Ok(v) = u32::from_str_radix(&hexs, 16) {
                        self.serial = Some(v);
                    }
                }
            }
            if supfunc && !low.contains("end of supported functions") {
                let rs = line.replace("INFO: ", "").replace('\n', "");
                if !rs.is_empty() {
                    self.supported_functions.push(rs);
                }
            }
            if low.contains("supported functions") {
                supfunc = true;
                if let Some(idx) = line.find("Functions: ") {
                    for v in line[idx + 11..].split(' ') {
                        if !v.is_empty() {
                            self.supported_functions.push(v.to_string());
                        }
                    }
                    supfunc = false;
                }
            }
        }
    }

    // ---- configure ----

    pub fn configure(&mut self) -> Result<()> {
        // 发两次:第一次探测,第二次用协商后的 payload(对齐 python 的递归)。
        for _ in 0..2 {
            let cmd = format!(
                "<?xml version=\"1.0\" encoding=\"UTF-8\" ?><data>\
<configure MemoryName=\"{}\" Verbose=\"0\" AlwaysValidate=\"0\" \
MaxDigestTableSizeInBytes=\"2048\" MaxPayloadSizeToTargetInBytes=\"{}\" \
ZLPAwareHost=\"1\" SkipStorageInit=\"0\" SkipWrite=\"0\"/></data>",
                self.cfg.memory_name, self.cfg.max_payload_to_target
            );
            let rsp = self.xmlsend(&cmd)?;
            // 不论 ACK 与否,都尽量吸收协商参数。
            let a = &rsp.attrs;
            if let Some(v) = a.get("MaxPayloadSizeToTargetInBytes") {
                if let Ok(n) = v.parse() {
                    self.cfg.max_payload_to_target = n;
                }
            }
            if let Some(v) = a.get("MaxPayloadSizeFromTargetInBytes") {
                if let Ok(n) = v.parse() {
                    self.cfg.max_payload_from_target = n;
                }
            }
            if let Some(v) = a.get("MaxXMLSizeInBytes") {
                if let Ok(n) = v.parse() {
                    self.cfg.max_xml = n;
                }
            }
            if let Some(v) = a.get("MemoryName") {
                if !v.is_empty() {
                    self.cfg.memory_name = v.clone();
                }
            }
            if let Some(v) = a.get("TargetName") {
                self.cfg.target_name = v.clone();
            }
            if rsp.ok {
                // 检查是否报了内存类型不支持(eMMC->UFS 切换)
                if rsp.logs.iter().any(|l| l.contains("Not support configure MemoryName eMMC")) {
                    self.cfg.memory_name = "UFS".into();
                    continue;
                }
                continue;
            } else {
                // 非 ACK:看看是不是内存类型问题
                if rsp.logs.iter().any(|l| l.contains("Not support configure MemoryName eMMC")) {
                    self.cfg.memory_name = "UFS".into();
                    continue;
                }
                // 若带了协商参数也算可继续
                if !a.is_empty() {
                    continue;
                }
                bail!("configure 失败: {}", first_err(&rsp));
            }
        }
        Ok(())
    }

    // ---- storageinfo ----

    pub fn get_storage_info(&mut self) -> Result<Vec<String>> {
        let data =
            "<?xml version=\"1.0\" ?><data><getstorageinfo physical_partition_number=\"0\"/></data>";
        let rsp = self.xmlsend(data)?;
        for line in &rsp.logs {
            // storage_info JSON 行
            if line.contains("storage_info") {
                let json = line.replace("INFO:", "");
                if let Some(start) = json.find('{') {
                    if let Ok(val) = serde_json::from_str::<serde_json::Value>(&json[start..]) {
                        if let Some(si) = val.get("storage_info") {
                            if let Some(n) = si.get("num_physical").and_then(|x| x.as_u64()) {
                                self.cfg.num_physical = n as u32;
                            }
                            if let Some(n) = si.get("block_size").and_then(|x| x.as_u64()) {
                                self.cfg.block_size = n;
                            }
                            if let Some(n) = si.get("page_size").and_then(|x| x.as_u64()) {
                                self.cfg.sector_size = n as usize;
                            }
                            if let Some(s) = si.get("mem_type").and_then(|x| x.as_str()) {
                                self.cfg.memory_name = s.to_string();
                            }
                            if let Some(s) = si.get("prod_name").and_then(|x| x.as_str()) {
                                self.cfg.prod_name = s.to_string();
                            }
                        }
                    }
                }
            }
        }
        Ok(rsp.logs)
    }

    /// 根据已知信息推断要扫描的 LUN 列表。
    pub fn luns(&self) -> Vec<u32> {
        if self.cfg.memory_name.eq_ignore_ascii_case("ufs") {
            let n = if self.cfg.num_physical > 0 {
                self.cfg.num_physical
            } else {
                8
            };
            (0..n).collect()
        } else {
            vec![0]
        }
    }

    // ---- 读 ----

    /// 读 lun 上 [start, start+sectors) 到内存(用于 GPT)。
    pub fn read_buffer(&self, lun: u32, start: u64, sectors: u64) -> Result<Vec<u8>> {
        let cmd = format!(
            "<?xml version=\"1.0\" ?><data><read SECTOR_SIZE_IN_BYTES=\"{}\" \
num_partition_sectors=\"{}\" physical_partition_number=\"{}\" start_sector=\"{}\"/>\n</data>",
            self.cfg.sector_size, sectors, lun, start
        );
        let rsp = self.xmlsend(&cmd)?;
        if !rsp.ok {
            bail!("read 被拒: {}", first_err(&rsp));
        }
        let total = self.cfg.sector_size * sectors as usize;
        let data = self.read_raw(total)?;
        let _ = self.read_response()?; // 结束响应
        Ok(data)
    }

    /// 读指定分区(按 lun/start/sectors)到文件。
    pub fn read_to_file(&self, lun: u32, start: u64, sectors: u64, path: &str) -> Result<u64> {
        let cmd = format!(
            "<?xml version=\"1.0\" ?><data><read SECTOR_SIZE_IN_BYTES=\"{}\" \
num_partition_sectors=\"{}\" physical_partition_number=\"{}\" start_sector=\"{}\"/>\n</data>",
            self.cfg.sector_size, sectors, lun, start
        );
        let rsp = self.xmlsend(&cmd)?;
        if !rsp.ok {
            bail!("read 被拒: {}", first_err(&rsp));
        }
        let mut f = File::create(path).with_context(|| format!("创建 {path} 失败"))?;
        let total = self.cfg.sector_size * sectors as usize;
        let mut remaining = total;
        let mut empties = 0;
        while remaining > 0 {
            let want = remaining.min(1 << 20);
            let data = self.usb.read(want, DATA_TIMEOUT)?;
            if data.is_empty() {
                empties += 1;
                if empties > 5 {
                    bail!("读取超时,还差 {remaining} 字节");
                }
                continue;
            }
            empties = 0;
            f.write_all(&data)?;
            remaining -= data.len().min(remaining);
        }
        f.flush()?;
        let fin = self.read_response()?;
        if !fin.value.is_empty() && fin.value != "ACK" {
            bail!("读取结束响应非 ACK: {}", first_err(&fin));
        }
        Ok(total as u64)
    }

    fn read_raw(&self, total: usize) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(total);
        let mut empties = 0;
        while out.len() < total {
            let want = (total - out.len()).min(1 << 20);
            let data = self.usb.read(want, DATA_TIMEOUT)?;
            if data.is_empty() {
                empties += 1;
                if empties > 5 {
                    break;
                }
                continue;
            }
            empties = 0;
            out.extend_from_slice(&data);
        }
        Ok(out)
    }

    // ---- GPT ----

    pub fn get_gpt(&self, lun: u32) -> Result<Option<Vec<Partition>>> {
        // 先读 LBA0+LBA1(2 扇区)拿头
        let head = match self.read_buffer(lun, 0, 2) {
            Ok(d) => d,
            Err(_) => return Ok(None),
        };
        let hdr = match gpt::parse_header(&head, self.cfg.sector_size) {
            Some(h) => h,
            None => return Ok(None),
        };
        let part_table_size = hdr.num_part_entries as usize * hdr.part_entry_size as usize;
        let mut sectors = part_table_size / self.cfg.sector_size;
        if part_table_size % self.cfg.sector_size != 0 {
            sectors += 1;
        }
        if sectors == 0 {
            return Ok(None);
        }
        if sectors > 64 {
            sectors = 64;
        }
        // 读完整:从 LBA0 到 part_entry_start_lba + sectors
        let total_sectors = hdr.part_entry_start_lba + sectors as u64;
        let full = self.read_buffer(lun, 0, total_sectors)?;
        Ok(gpt::parse(&full, self.cfg.sector_size))
    }

    /// 遍历所有 lun 收集分区。
    pub fn list_all(&self) -> Vec<(u32, Partition)> {
        let mut out = Vec::new();
        for lun in self.luns() {
            if let Ok(Some(parts)) = self.get_gpt(lun) {
                for p in parts {
                    out.push((lun, p));
                }
            }
        }
        out
    }

    /// 按分区名定位 (lun, start_sector, num_sectors)。
    pub fn find_partition(&self, name: &str) -> Option<(u32, u64, u64)> {
        for lun in self.luns() {
            if let Ok(Some(parts)) = self.get_gpt(lun) {
                for p in parts {
                    if p.name == name {
                        return Some((lun, p.start_sector, p.num_sectors));
                    }
                }
            }
        }
        None
    }

    // ---- 写 ----

    pub fn program_file(&self, lun: u32, start: u64, path: &str) -> Result<u64> {
        let meta = std::fs::metadata(path).with_context(|| format!("读取 {path} 失败"))?;
        let total = meta.len() as usize;
        let mut num_sectors = total / self.cfg.sector_size;
        if total % self.cfg.sector_size != 0 {
            num_sectors += 1;
        }
        let cmd = format!(
            "<?xml version=\"1.0\" ?><data>\n<program SECTOR_SIZE_IN_BYTES=\"{}\" \
num_partition_sectors=\"{}\" physical_partition_number=\"{}\" start_sector=\"{}\" />\n</data>",
            self.cfg.sector_size, num_sectors, lun, start
        );
        let rsp = self.xmlsend(&cmd)?;
        if !rsp.ok {
            bail!("program 被拒: {}", first_err(&rsp));
        }
        let mut f = File::open(path)?;
        let mut remaining = total;
        let sector = self.cfg.sector_size;
        while remaining > 0 {
            let wlen = remaining.min(self.cfg.max_payload_to_target);
            let mut buf = vec![0u8; wlen];
            f.read_exact(&mut buf)?;
            remaining -= wlen;
            // 补齐到扇区边界
            if wlen % sector != 0 {
                let fill = (wlen / sector * sector) + sector;
                buf.resize(fill, 0);
            }
            self.usb.write(&buf, DATA_TIMEOUT)?;
            self.usb.write_zlp(DATA_TIMEOUT)?;
        }
        let fin = self.read_response()?;
        if !fin.value.is_empty() && fin.value != "ACK" {
            bail!("program 结束响应非 ACK: {}", first_err(&fin));
        }
        Ok((num_sectors * sector) as u64)
    }

    pub fn erase(&self, lun: u32, start: u64, sectors: u64) -> Result<()> {
        if self.supported_functions.iter().any(|f| f == "erase") {
            let cmd = format!(
                "<?xml version=\"1.0\" ?><data>\n<erase SECTOR_SIZE_IN_BYTES=\"{}\" \
num_partition_sectors=\"{}\" physical_partition_number=\"{}\" start_sector=\"{}\" />\n</data>",
                self.cfg.sector_size, sectors, lun, start
            );
            let rsp = self.xmlsend(&cmd)?;
            if !rsp.ok {
                bail!("erase 被拒: {}", first_err(&rsp));
            }
            return Ok(());
        }
        // 回退:写零
        let cmd = format!(
            "<?xml version=\"1.0\" ?><data>\n<program SECTOR_SIZE_IN_BYTES=\"{}\" \
num_partition_sectors=\"{}\" physical_partition_number=\"{}\" start_sector=\"{}\" />\n</data>",
            self.cfg.sector_size, sectors, lun, start
        );
        let rsp = self.xmlsend(&cmd)?;
        if !rsp.ok {
            bail!("erase(program 0) 被拒: {}", first_err(&rsp));
        }
        let total = self.cfg.sector_size * sectors as usize;
        let mut remaining = total;
        let empty = vec![0u8; self.cfg.max_payload_to_target];
        while remaining > 0 {
            let wlen = remaining.min(self.cfg.max_payload_to_target);
            self.usb.write(&empty[..wlen], DATA_TIMEOUT)?;
            self.usb.write_zlp(DATA_TIMEOUT)?;
            remaining -= wlen;
        }
        let fin = self.read_response()?;
        if !fin.value.is_empty() && fin.value != "ACK" {
            bail!("erase 结束响应非 ACK: {}", first_err(&fin));
        }
        Ok(())
    }

    // ---- 复位 ----

    pub fn reset(&self, mode: &str) -> Result<()> {
        let cmd = format!("<?xml version=\"1.0\" ?><data><power value=\"{}\"/></data>", mode);
        let rsp = self.xmlsend(&cmd)?;
        if rsp.ok {
            Ok(())
        } else {
            bail!("reset 失败: {}", first_err(&rsp))
        }
    }

    // ---- peek/poke(best-effort,只支持小块) ----

    pub fn peek(&self, address: u64, size: u64) -> Result<Vec<u8>> {
        let cmd = format!(
            "<?xml version=\"1.0\" ?><data><peek address64=\"{}\" size_in_bytes=\"{}\" /></data>\n",
            address, size
        );
        self.write_xml(&cmd)?;
        let mut out = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        loop {
            let tmp = self.usb.read(self.usb.read_buf, XML_TIMEOUT)?;
            if tmp.is_empty() || Instant::now() > deadline {
                break;
            }
            let s = xml::to_str(&tmp);
            if s.contains("<response") || s.contains("ERROR") {
                break;
            }
            for l in xml::logs(&s) {
                let hexstr: String = l.replace("0x", "").replace(' ', "");
                if let Ok(bytes) = decode_hex(&hexstr) {
                    out.extend_from_slice(&bytes);
                }
            }
        }
        Ok(out)
    }

    pub fn poke(&self, address: u64, data: &[u8]) -> Result<()> {
        // 每次最多 8 字节,little-endian value64。
        let mut pos = 0;
        while pos < data.len() {
            let maxsize = (data.len() - pos).min(8);
            let mut val: u64 = 0;
            for i in 0..maxsize {
                val |= (data[pos + i] as u64) << (8 * i);
            }
            let cmd = format!(
                "<?xml version=\"1.0\" ?><data><poke address64=\"{}\" SizeInBytes=\"{}\" value64=\"0x{:x}\" /></data>\n",
                address + pos as u64,
                maxsize,
                val
            );
            self.write_xml(&cmd)?;
            // 读确认
            let mut acked = false;
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let tmp = self.usb.read(self.usb.read_buf, XML_TIMEOUT)?;
                if tmp.is_empty() || Instant::now() > deadline {
                    break;
                }
                let s = xml::to_str(&tmp);
                if s.contains("NAK") {
                    bail!("poke 被拒 @0x{:x}", address + pos as u64);
                }
                if s.contains("ACK") {
                    acked = true;
                    break;
                }
            }
            let _ = acked;
            pos += maxsize;
        }
        Ok(())
    }
}

fn first_err(rsp: &Response) -> String {
    if !rsp.logs.is_empty() {
        rsp.logs.join("; ")
    } else if !rsp.raw.is_empty() {
        rsp.raw.replace('\n', " ")
    } else {
        "(无响应)".into()
    }
}

fn find(hay: &[u8], needle: &[u8]) -> Option<usize> {
    hay.windows(needle.len()).position(|w| w == needle)
}

fn decode_hex(s: &str) -> Result<Vec<u8>> {
    if s.len() % 2 != 0 {
        return Err(anyhow!("hex 长度非偶"));
    }
    let mut out = Vec::with_capacity(s.len() / 2);
    let b = s.as_bytes();
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).ok_or_else(|| anyhow!("非法 hex"))?;
        let lo = (b[i + 1] as char).to_digit(16).ok_or_else(|| anyhow!("非法 hex"))?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}
