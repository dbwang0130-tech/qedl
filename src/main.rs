//! qedl —— Rust 版高通 9008 EDL 工具(Sahara + Firehose),Mac 原生二进制。
//!
//! 面向 agent:每条命令可用 `--json` 输出单个 JSON 对象到 stdout;
//! 人类可读日志统一走 stderr;退出码 0=成功,1=失败。

mod firehose;
mod gpt;
mod sahara;
mod usb;
mod xml;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use firehose::{Cfg, Firehose};
use sahara::{Mode, Sahara};
use serde_json::{json, Value};
use std::io::Write;
use usb::UsbDev;

/// 高通 9008 EDL 工具(Rust)。
#[derive(Parser)]
#[command(name = "qedl", version, about = "Qualcomm 9008 EDL (Sahara+Firehose) · 原生 Mac 二进制")]
struct Cli {
    /// firehose loader 路径(除 detect/info 外的命令都需要)
    #[arg(short = 'l', long, global = true)]
    loader: Option<String>,

    /// 存储类型:ufs 或 emmc
    #[arg(short = 'm', long, global = true, default_value = "ufs")]
    memory: String,

    /// 扇区大小覆盖(字节),默认 ufs=4096 emmc=512
    #[arg(long, global = true)]
    sector_size: Option<usize>,

    /// 单次写入 payload 上限(字节)
    #[arg(long, global = true)]
    max_payload: Option<usize>,

    /// VID 覆盖(十六进制,如 05c6)
    #[arg(long, global = true)]
    vid: Option<String>,

    /// PID 覆盖(十六进制,如 9008)
    #[arg(long, global = true)]
    pid: Option<String>,

    /// 等待设备出现的秒数(PBL 会超时重启,保持较短)
    #[arg(short = 'w', long, global = true, default_value = "0")]
    wait: f64,

    /// 结构化 JSON 输出到 stdout
    #[arg(long, global = true)]
    json: bool,

    #[command(subcommand)]
    cmd: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// 仅检测 9008 设备是否在线(不需要 loader)
    Detect,
    /// Sahara 命令模式读 serial/hwid/pkhash(不需要 loader)
    Info,
    /// 上传 loader 并打印存储信息
    Storageinfo,
    /// 列出所有分区(lun/起始扇区/扇区数/大小)
    Printgpt,
    /// 按分区名读取到文件
    Read {
        partition: String,
        out: String,
    },
    /// 按 lun/起始扇区/扇区数读取到文件
    ReadLun {
        lun: u32,
        start: u64,
        sectors: u64,
        out: String,
    },
    /// 按分区名把文件写入(program)
    Write {
        partition: String,
        input: String,
    },
    /// 按 lun/起始扇区把文件写入
    WriteLun {
        lun: u32,
        start: u64,
        input: String,
    },
    /// 按分区名擦除
    Erase {
        partition: String,
    },
    /// 按 lun/起始扇区/扇区数擦除
    EraseLun {
        lun: u32,
        start: u64,
        sectors: u64,
    },
    /// 读内存
    Peek {
        /// 地址(支持 0x 前缀)
        address: String,
        size: u64,
        /// 可选输出文件;不给则 hex 打印
        out: Option<String>,
    },
    /// 写内存(hex 字节串,如 0101)
    Poke {
        address: String,
        hex: String,
    },
    /// 复位设备:reset(重启)/ edl(回 9008)/ off(关机)
    Reset {
        #[arg(default_value = "reset")]
        mode: String,
    },
}

fn main() {
    let cli = Cli::parse();
    let json_mode = cli.json;
    match run(&cli) {
        Ok(v) => {
            if json_mode {
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            }
            std::process::exit(0);
        }
        Err(e) => {
            if json_mode {
                let v = json!({"ok": false, "error": format!("{e:#}")});
                println!("{}", serde_json::to_string_pretty(&v).unwrap());
            } else {
                eprintln!("错误: {e:#}");
            }
            std::process::exit(1);
        }
    }
}

fn logln(args: std::fmt::Arguments) {
    let _ = writeln!(std::io::stderr(), "{args}");
}
macro_rules! log {
    ($($a:tt)*) => { logln(format_args!($($a)*)) };
}

fn parse_hex_u16(s: &str) -> Result<u16> {
    let s = s.trim_start_matches("0x");
    u16::from_str_radix(s, 16).with_context(|| format!("非法十六进制: {s}"))
}
fn parse_addr(s: &str) -> Result<u64> {
    let t = s.trim();
    if let Some(h) = t.strip_prefix("0x") {
        u64::from_str_radix(h, 16).with_context(|| format!("非法地址: {s}"))
    } else {
        t.parse().with_context(|| format!("非法地址: {s}"))
    }
}

fn device_ids(cli: &Cli) -> Result<Vec<(u16, u16)>> {
    if cli.vid.is_some() || cli.pid.is_some() {
        let v = parse_hex_u16(cli.vid.as_deref().unwrap_or("05c6"))?;
        let p = parse_hex_u16(cli.pid.as_deref().unwrap_or("9008"))?;
        Ok(vec![(v, p)])
    } else {
        Ok(vec![
            (0x05c6, 0x9008),
            (0x05c6, 0x900e),
            (0x05c6, 0x9025),
        ])
    }
}

fn open_usb(cli: &Cli) -> Result<UsbDev> {
    let ids = device_ids(cli)?;
    if cli.wait > 0.0 {
        log!("等待设备(最多 {:.0}s)...", cli.wait);
        usb::wait_for(&ids, cli.wait);
    }
    let dev = UsbDev::open(&ids)?;
    log!("设备已连接: {:04x}:{:04x}", dev.vid, dev.pid);
    Ok(dev)
}

fn load_loader(cli: &Cli) -> Result<Vec<u8>> {
    let path = cli
        .loader
        .as_deref()
        .context("该命令需要 --loader <firehose loader 路径>")?;
    std::fs::read(path).with_context(|| format!("读取 loader {path} 失败"))
}

/// 完成 sahara 上传 + firehose 初始化,返回就绪的 Firehose。
fn start_firehose<'a>(usb: &'a UsbDev, cli: &Cli) -> Result<Firehose<'a>> {
    let loader = load_loader(cli)?;
    let mut sah = Sahara::new(usb);
    match sah.connect()? {
        Mode::Sahara => {
            log!("Sahara 握手成功 (version {})", sah.version);
            log!("上传 loader ({} 字节)...", loader.len());
            sah.upload_loader(&loader)?;
            log!("loader 上传完成,进入 firehose");
        }
        Mode::Firehose => {
            log!("设备已处于 firehose 模式");
        }
        Mode::Unknown => bail!("无法识别设备模式(既非 sahara 也非 firehose)"),
    }

    let cfg = Cfg::new(&cli.memory, cli.sector_size, cli.max_payload);
    let mut fh = Firehose::new(usb, cfg);
    fh.connect()?;
    if !fh.supported_functions.is_empty() {
        log!("支持的功能: {}", fh.supported_functions.join(","));
    }
    fh.configure()?;
    log!(
        "configure 完成: memory={} sector={} payload_to={} payload_from={} target={}",
        fh.cfg.memory_name,
        fh.cfg.sector_size,
        fh.cfg.max_payload_to_target,
        fh.cfg.max_payload_from_target,
        fh.cfg.target_name
    );
    let _ = fh.get_storage_info();
    if fh.cfg.num_physical > 0 {
        log!(
            "存储: {} 物理分区, block_size={}, sector={}",
            fh.cfg.num_physical,
            fh.cfg.block_size,
            fh.cfg.sector_size
        );
    }
    Ok(fh)
}

fn run(cli: &Cli) -> Result<Value> {
    match &cli.cmd {
        Cmd::Detect => {
            let ids = device_ids(cli)?;
            let found = if cli.wait > 0.0 {
                usb::wait_for(&ids, cli.wait)
            } else {
                usb::detect(&ids)
            };
            match found {
                Some((v, p)) => {
                    log!("找到设备 {:04x}:{:04x}", v, p);
                    Ok(json!({"ok": true, "present": true, "vid": format!("{:04x}", v), "pid": format!("{:04x}", p)}))
                }
                None => {
                    log!("未找到 EDL 设备");
                    Ok(json!({"ok": true, "present": false}))
                }
            }
        }

        Cmd::Info => {
            let usb = open_usb(cli)?;
            let mut sah = Sahara::new(&usb);
            match sah.connect()? {
                Mode::Sahara => {}
                _ => bail!("设备不在 sahara 模式,info 需要刚进 9008 的设备"),
            }
            let info = sah.cmd_info()?;
            let serial = info.serial.map(|s| format!("{:08x}", s));
            let hwid = info.msm_hwid.map(|h| format!("{:016x}", h));
            log!("serial={:?} hwid={:?} pkhash={:?}", serial, hwid, info.pkhash);
            let _ = sah.cmd_reset();
            Ok(json!({
                "ok": true,
                "serial": serial,
                "msm_hwid": hwid,
                "pkhash": info.pkhash,
            }))
        }

        Cmd::Storageinfo => {
            let usb = open_usb(cli)?;
            let mut fh = start_firehose(&usb, cli)?;
            let logs = fh.get_storage_info()?;
            Ok(json!({
                "ok": true,
                "memory": fh.cfg.memory_name,
                "sector_size": fh.cfg.sector_size,
                "block_size": fh.cfg.block_size,
                "num_physical": fh.cfg.num_physical,
                "prod_name": fh.cfg.prod_name,
                "target": fh.cfg.target_name,
                "supported_functions": fh.supported_functions,
                "raw_logs": logs,
            }))
        }

        Cmd::Printgpt => {
            let usb = open_usb(cli)?;
            let fh = start_firehose(&usb, cli)?;
            let all = fh.list_all();
            let ss = fh.cfg.sector_size as u64;
            let parts: Vec<Value> = all
                .iter()
                .map(|(lun, p)| {
                    json!({
                        "lun": lun,
                        "name": p.name,
                        "start_sector": p.start_sector,
                        "num_sectors": p.num_sectors,
                        "size_bytes": p.num_sectors * ss,
                        "unique_guid": p.unique_guid,
                        "flags": format!("0x{:x}", p.flags),
                    })
                })
                .collect();
            if !cli.json {
                log!("{:<4} {:<24} {:>12} {:>12} {:>14}", "LUN", "NAME", "START", "SECTORS", "SIZE");
                for (lun, p) in &all {
                    log!(
                        "{:<4} {:<24} {:>12} {:>12} {:>14}",
                        lun,
                        p.name,
                        p.start_sector,
                        p.num_sectors,
                        human(p.num_sectors * ss)
                    );
                }
            }
            Ok(json!({"ok": true, "sector_size": ss, "partitions": parts}))
        }

        Cmd::Read { partition, out } => {
            let usb = open_usb(cli)?;
            let fh = start_firehose(&usb, cli)?;
            let (lun, start, sectors) = fh
                .find_partition(partition)
                .with_context(|| format!("未找到分区 {partition}"))?;
            log!("读取 {partition} (lun={lun} start={start} sectors={sectors}) -> {out}");
            let n = fh.read_to_file(lun, start, sectors, out)?;
            log!("完成,写入 {} 字节", n);
            Ok(json!({"ok": true, "partition": partition, "lun": lun, "start_sector": start, "num_sectors": sectors, "bytes": n, "out": out}))
        }

        Cmd::ReadLun { lun, start, sectors, out } => {
            let usb = open_usb(cli)?;
            let fh = start_firehose(&usb, cli)?;
            log!("读取 lun={lun} start={start} sectors={sectors} -> {out}");
            let n = fh.read_to_file(*lun, *start, *sectors, out)?;
            log!("完成,写入 {} 字节", n);
            Ok(json!({"ok": true, "lun": lun, "start_sector": start, "num_sectors": sectors, "bytes": n, "out": out}))
        }

        Cmd::Write { partition, input } => {
            let usb = open_usb(cli)?;
            let fh = start_firehose(&usb, cli)?;
            let (lun, start, sectors) = fh
                .find_partition(partition)
                .with_context(|| format!("未找到分区 {partition}"))?;
            let fsize = std::fs::metadata(input)?.len();
            let cap = sectors * fh.cfg.sector_size as u64;
            if fsize > cap {
                bail!("输入文件 {} 字节 > 分区容量 {} 字节", fsize, cap);
            }
            log!("写入 {input} -> {partition} (lun={lun} start={start})");
            let n = fh.program_file(lun, start, input)?;
            log!("完成,写入 {} 字节", n);
            Ok(json!({"ok": true, "partition": partition, "lun": lun, "start_sector": start, "bytes": n, "input": input}))
        }

        Cmd::WriteLun { lun, start, input } => {
            let usb = open_usb(cli)?;
            let fh = start_firehose(&usb, cli)?;
            log!("写入 {input} -> lun={lun} start={start}");
            let n = fh.program_file(*lun, *start, input)?;
            log!("完成,写入 {} 字节", n);
            Ok(json!({"ok": true, "lun": lun, "start_sector": start, "bytes": n, "input": input}))
        }

        Cmd::Erase { partition } => {
            let usb = open_usb(cli)?;
            let fh = start_firehose(&usb, cli)?;
            let (lun, start, sectors) = fh
                .find_partition(partition)
                .with_context(|| format!("未找到分区 {partition}"))?;
            log!("擦除 {partition} (lun={lun} start={start} sectors={sectors})");
            fh.erase(lun, start, sectors)?;
            Ok(json!({"ok": true, "partition": partition, "lun": lun, "start_sector": start, "num_sectors": sectors}))
        }

        Cmd::EraseLun { lun, start, sectors } => {
            let usb = open_usb(cli)?;
            let fh = start_firehose(&usb, cli)?;
            log!("擦除 lun={lun} start={start} sectors={sectors}");
            fh.erase(*lun, *start, *sectors)?;
            Ok(json!({"ok": true, "lun": lun, "start_sector": start, "num_sectors": sectors}))
        }

        Cmd::Peek { address, size, out } => {
            let usb = open_usb(cli)?;
            let fh = start_firehose(&usb, cli)?;
            let addr = parse_addr(address)?;
            let data = fh.peek(addr, *size)?;
            if let Some(path) = out {
                std::fs::write(path, &data)?;
                log!("peek {} 字节 -> {}", data.len(), path);
                Ok(json!({"ok": true, "address": format!("0x{:x}", addr), "bytes": data.len(), "out": path}))
            } else {
                let hex: String = data.iter().map(|b| format!("{:02x}", b)).collect();
                if !cli.json {
                    log!("{}", hex);
                }
                Ok(json!({"ok": true, "address": format!("0x{:x}", addr), "bytes": data.len(), "hex": hex}))
            }
        }

        Cmd::Poke { address, hex } => {
            let usb = open_usb(cli)?;
            let fh = start_firehose(&usb, cli)?;
            let addr = parse_addr(address)?;
            let bytes = decode_hex_cli(hex)?;
            fh.poke(addr, &bytes)?;
            log!("poke {} 字节 @ 0x{:x}", bytes.len(), addr);
            Ok(json!({"ok": true, "address": format!("0x{:x}", addr), "bytes": bytes.len()}))
        }

        Cmd::Reset { mode } => {
            let usb = open_usb(cli)?;
            let fh = start_firehose(&usb, cli)?;
            log!("复位: {mode}");
            fh.reset(mode)?;
            Ok(json!({"ok": true, "mode": mode}))
        }
    }
}

fn human(bytes: u64) -> String {
    const U: [&str; 5] = ["B", "KB", "MB", "GB", "TB"];
    let mut v = bytes as f64;
    let mut i = 0;
    while v >= 1024.0 && i < U.len() - 1 {
        v /= 1024.0;
        i += 1;
    }
    if i == 0 {
        format!("{} {}", bytes, U[i])
    } else {
        format!("{:.2} {}", v, U[i])
    }
}

fn decode_hex_cli(s: &str) -> Result<Vec<u8>> {
    let s: String = s.chars().filter(|c| !c.is_whitespace()).collect();
    let s = s.trim_start_matches("0x");
    if s.len() % 2 != 0 {
        bail!("hex 长度必须为偶数");
    }
    let b = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for i in (0..b.len()).step_by(2) {
        let hi = (b[i] as char).to_digit(16).context("非法 hex 字符")?;
        let lo = (b[i + 1] as char).to_digit(16).context("非法 hex 字符")?;
        out.push(((hi << 4) | lo) as u8);
    }
    Ok(out)
}
