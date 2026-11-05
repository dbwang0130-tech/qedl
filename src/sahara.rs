//! Sahara 协议:握手 + 上传 firehose loader + (命令模式)读 serial/hwid/pkhash。
//! 对齐 bkerler/edl 的 sahara.py / sahara_defs.py。

use crate::usb::UsbDev;
use anyhow::{anyhow, bail, Result};
use std::time::Duration;

// 命令码
const HELLO_REQ: u32 = 0x1;
const HELLO_RSP: u32 = 0x2;
const READ_DATA: u32 = 0x3;
const END_TRANSFER: u32 = 0x4;
const DONE_REQ: u32 = 0x5;
const DONE_RSP: u32 = 0x6;
const RESET_REQ: u32 = 0x7;
const RESET_RSP: u32 = 0x8;
const CMD_READY: u32 = 0xB;
const EXECUTE_REQ: u32 = 0xD;
const EXECUTE_RSP: u32 = 0xE;
const EXECUTE_DATA: u32 = 0xF;
const READ_DATA_64: u32 = 0x12;

// 模式
const MODE_IMAGE_TX_PENDING: u32 = 0x0;
const MODE_COMMAND: u32 = 0x3;

// exec 子命令
const EXEC_SERIAL_NUM_READ: u32 = 0x01;
const EXEC_MSM_HW_ID_READ: u32 = 0x02;
const EXEC_OEM_PK_HASH_READ: u32 = 0x03;

const TIMEOUT: Duration = Duration::from_secs(1);

fn rd_u32(d: &[u8], off: usize) -> u32 {
    u32::from_le_bytes([d[off], d[off + 1], d[off + 2], d[off + 3]])
}
fn rd_u64(d: &[u8], off: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[off..off + 8]);
    u64::from_le_bytes(b)
}

pub struct SaharaInfo {
    pub serial: Option<u32>,
    pub msm_hwid: Option<u64>,
    pub pkhash: Option<String>,
}

pub struct Sahara<'a> {
    usb: &'a UsbDev,
    pub version: u32,
    pub bit64: bool,
}

/// connect 阶段看到的设备模式。
pub enum Mode {
    Sahara,
    Firehose,
    Unknown,
}

impl<'a> Sahara<'a> {
    pub fn new(usb: &'a UsbDev) -> Self {
        Sahara {
            usb,
            version: 2,
            bit64: false,
        }
    }

    fn write(&self, data: &[u8]) -> Result<()> {
        self.usb.write(data, TIMEOUT)
    }

    /// 读一个 sahara 包(或 firehose xml 的开头)。
    fn read_pkt(&self) -> Result<Vec<u8>> {
        self.usb.read(0x1000, TIMEOUT)
    }

    /// 读设备上电后的首包,判定模式。对齐 sahara.connect()。
    pub fn connect(&mut self) -> Result<Mode> {
        let v = self.usb.read_exact_timeout(0x30, TIMEOUT)?;
        if v.len() < 4 {
            // 设备没主动发 hello,尝试探测 firehose:发 nop。
            let nop = b"<?xml version=\"1.0\" ?><data><nop /></data>";
            self.write(nop)?;
            let res = self.usb.read(0x1000, TIMEOUT)?;
            if res.windows(5).any(|w| w == b"<?xml") {
                return Ok(Mode::Firehose);
            }
            return Ok(Mode::Unknown);
        }
        if v.windows(5).any(|w| w == b"<?xml") {
            return Ok(Mode::Firehose);
        }
        let cmd = rd_u32(&v, 0);
        if cmd == HELLO_REQ && v.len() >= 0x30 {
            self.version = rd_u32(&v, 8); // version 字段
            return Ok(Mode::Sahara);
        }
        if cmd == END_TRANSFER {
            bail!("设备处于 Sahara END_TRANSFER 错误态,请重新进入 9008");
        }
        Ok(Mode::Unknown)
    }

    fn hello_rsp(&self, mode: u32) -> Result<()> {
        let mut pkt = Vec::with_capacity(0x30);
        let fields: [u32; 12] = [
            HELLO_RSP, 0x30, self.version, 1, 0, mode, 1, 2, 3, 4, 5, 6,
        ];
        for f in fields {
            pkt.extend_from_slice(&f.to_le_bytes());
        }
        self.write(&pkt)
    }

    /// 上传二进制 loader,成功后设备进入 firehose。
    pub fn upload_loader(&mut self, loader: &[u8]) -> Result<()> {
        self.hello_rsp(MODE_IMAGE_TX_PENDING)?;
        loop {
            let pkt = self.read_pkt()?;
            if pkt.is_empty() {
                continue;
            }
            if pkt.windows(5).any(|w| w == b"<?xml") {
                // 已经是 firehose 输出
                return Ok(());
            }
            let cmd = rd_u32(&pkt, 0);
            match cmd {
                READ_DATA | READ_DATA_64 => {
                    let (offset, len) = if cmd == READ_DATA_64 {
                        self.bit64 = true;
                        // cmd,len, image_id(q), data_offset(q), data_len(q)
                        (rd_u64(&pkt, 16) as usize, rd_u64(&pkt, 24) as usize)
                    } else {
                        self.bit64 = false;
                        // cmd,len,image_id,data_offset,data_len
                        (rd_u32(&pkt, 12) as usize, rd_u32(&pkt, 16) as usize)
                    };
                    let mut chunk = Vec::with_capacity(len);
                    let end = offset.saturating_add(len);
                    if offset < loader.len() {
                        let real_end = end.min(loader.len());
                        chunk.extend_from_slice(&loader[offset..real_end]);
                    }
                    if chunk.len() < len {
                        chunk.resize(len, 0xFF);
                    }
                    self.write(&chunk)?;
                }
                END_TRANSFER => {
                    let status = rd_u32(&pkt, 12);
                    if status != 0 {
                        bail!("Sahara END_TRANSFER 失败,status=0x{:x}(loader 签名未被接受?)", status);
                    }
                    self.cmd_done()?;
                    return Ok(());
                }
                CMD_READY | DONE_RSP => {
                    return Ok(());
                }
                HELLO_REQ => {
                    // 多阶段重握手
                    self.hello_rsp(MODE_IMAGE_TX_PENDING)?;
                }
                other => {
                    bail!("Sahara 上传时收到意外命令 0x{:x}", other);
                }
            }
        }
    }

    fn cmd_done(&self) -> Result<()> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&DONE_REQ.to_le_bytes());
        pkt.extend_from_slice(&0x8u32.to_le_bytes());
        self.write(&pkt)?;
        let rsp = self.read_pkt()?;
        if rsp.len() >= 4 {
            let cmd = rd_u32(&rsp, 0);
            if cmd == DONE_RSP || cmd == END_TRANSFER {
                return Ok(());
            }
        }
        // 有些设备不回 DONE_RSP 直接进 firehose,也算成功。
        Ok(())
    }

    // ---- 命令模式:读设备信息 ----

    fn enter_command_mode(&self) -> Result<()> {
        self.hello_rsp(MODE_COMMAND)?;
        let rsp = self.read_pkt()?;
        if rsp.len() >= 4 {
            let cmd = rd_u32(&rsp, 0);
            if cmd == CMD_READY {
                return Ok(());
            }
            if cmd == END_TRANSFER {
                bail!("进入命令模式失败(END_TRANSFER)");
            }
        }
        bail!("进入命令模式失败,未收到 CMD_READY")
    }

    fn cmd_exec(&self, mcmd: u32) -> Result<Vec<u8>> {
        let mut req = Vec::new();
        req.extend_from_slice(&EXECUTE_REQ.to_le_bytes());
        req.extend_from_slice(&0xCu32.to_le_bytes());
        req.extend_from_slice(&mcmd.to_le_bytes());
        self.write(&req)?;
        let rsp = self.read_pkt()?;
        if rsp.len() >= 16 && rd_u32(&rsp, 0) == EXECUTE_RSP {
            let data_len = rd_u32(&rsp, 12) as usize;
            let mut req2 = Vec::new();
            req2.extend_from_slice(&EXECUTE_DATA.to_le_bytes());
            req2.extend_from_slice(&0xCu32.to_le_bytes());
            req2.extend_from_slice(&mcmd.to_le_bytes());
            self.write(&req2)?;
            let payload = self.usb.read_exact_timeout(data_len, TIMEOUT)?;
            return Ok(payload);
        }
        Err(anyhow!("cmd_exec(0x{:x}) 未收到 EXECUTE_RSP", mcmd))
    }

    /// 命令模式读 serial / msm_hwid / pkhash,然后 reset。
    pub fn cmd_info(&mut self) -> Result<SaharaInfo> {
        self.enter_command_mode()?;
        let serial = self
            .cmd_exec(EXEC_SERIAL_NUM_READ)
            .ok()
            .filter(|d| d.len() >= 4)
            .map(|d| rd_u32(&d, 0));
        let msm_hwid = self
            .cmd_exec(EXEC_MSM_HW_ID_READ)
            .ok()
            .filter(|d| d.len() >= 8)
            .map(|d| rd_u64(&d, 0));
        let pkhash = self.cmd_exec(EXEC_OEM_PK_HASH_READ).ok().map(|d| {
            d.iter().map(|b| format!("{:02x}", b)).collect::<String>()
        });
        Ok(SaharaInfo {
            serial,
            msm_hwid,
            pkhash,
        })
    }

    pub fn cmd_reset(&self) -> Result<()> {
        let mut pkt = Vec::new();
        pkt.extend_from_slice(&RESET_REQ.to_le_bytes());
        pkt.extend_from_slice(&0x8u32.to_le_bytes());
        self.write(&pkt)?;
        // 读 RESET_RSP(可选)
        let rsp = self.read_pkt()?;
        if rsp.len() >= 4 && rd_u32(&rsp, 0) == RESET_RSP {
            return Ok(());
        }
        Ok(())
    }
}
