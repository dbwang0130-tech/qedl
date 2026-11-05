//! qedl —— Rust 版高通 9008 EDL 工具(Sahara + Firehose),Mac 原生二进制。
//!
//! 面向 agent:每条命令可用 `--json` 输出单个 JSON 对象到 stdout;
//! 人类可读日志统一走 stderr;退出码 0=成功,1=失败。

mod bootimg;
mod compress;
mod cpio;
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
    /// 本地 boot 镜像处理(magiskboot 功能,不碰设备)
    Boot {
        #[command(subcommand)]
        sub: BootCmd,
    },
}

#[derive(Subcommand)]
enum BootCmd {
    /// 打印 boot 镜像头信息
    Info { img: String },
    /// 解包:分离 kernel/ramdisk(解压成 cpio)/dtb 等到目录
    Unpack {
        img: String,
        /// 输出目录,默认 <img>.unpacked
        outdir: Option<String>,
    },
    /// 重打包:从 unpack 目录重建镜像
    Repack {
        dir: String,
        out: String,
    },
    /// cpio 操作(修改 ramdisk.cpio,原地写回)
    Cpio {
        #[command(subcommand)]
        sub: CpioCmd,
    },
}

#[derive(Subcommand)]
enum CpioCmd {
    /// 列出条目
    Ls { file: String },
    /// 提取:给 entry+out 提取单个,否则全部解到目录
    Extract {
        file: String,
        entry: Option<String>,
        out: Option<String>,
    },
    /// 添加文件(mode 为八进制,如 0644)
    Add {
        file: String,
        mode: String,
        entry: String,
        infile: String,
    },
    /// 删除条目
    Rm {
        file: String,
        entry: String,
        #[arg(short, long)]
        recursive: bool,
    },
    /// 新建目录(mode 八进制)
    Mkdir {
        file: String,
        mode: String,
        entry: String,
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

        Cmd::Boot { sub } => run_boot(sub, cli.json),
    }
}

fn run_boot(sub: &BootCmd, json_mode: bool) -> Result<Value> {
    match sub {
        BootCmd::Info { img } => {
            let data = std::fs::read(img).with_context(|| format!("读取 {img} 失败"))?;
            let b = bootimg::BootImg::parse(&data)?;
            let cmdline = read_cmdline(&b);
            log!(
                "version={} page_size={} kernel={} ramdisk={}({}) second={} dtb={}",
                b.version,
                b.page_size,
                b.kernel.len(),
                b.ramdisk_raw.len(),
                b.ramdisk_fmt.name(),
                b.second.len(),
                b.dtb.len()
            );
            Ok(json!({
                "ok": true,
                "version": b.version,
                "page_size": b.page_size,
                "kernel_size": b.kernel.len(),
                "ramdisk_size": b.ramdisk_raw.len(),
                "ramdisk_format": b.ramdisk_fmt.name(),
                "ramdisk_uncompressed": b.ramdisk.len(),
                "second_size": b.second.len(),
                "recovery_dtbo_size": b.recovery_dtbo.len(),
                "dtb_size": b.dtb.len(),
                "cmdline": cmdline,
            }))
        }

        BootCmd::Unpack { img, outdir } => {
            let data = std::fs::read(img).with_context(|| format!("读取 {img} 失败"))?;
            let b = bootimg::BootImg::parse(&data)?;
            let dir = outdir.clone().unwrap_or_else(|| format!("{img}.unpacked"));
            b.unpack_to(std::path::Path::new(&dir))?;
            log!(
                "解包到 {dir}/(kernel {} 字节, ramdisk {} 字节/{}, 解压后 cpio {} 字节)",
                b.kernel.len(),
                b.ramdisk_raw.len(),
                b.ramdisk_fmt.name(),
                b.ramdisk.len()
            );
            Ok(json!({
                "ok": true, "outdir": dir, "version": b.version,
                "ramdisk_format": b.ramdisk_fmt.name(),
                "files": ["header.bin","ramdisk_fmt","kernel","ramdisk.cpio"],
            }))
        }

        BootCmd::Repack { dir, out } => {
            let img = bootimg::repack_from_dir(std::path::Path::new(dir))?;
            std::fs::write(out, &img).with_context(|| format!("写入 {out} 失败"))?;
            log!("重打包完成: {out}({} 字节)", img.len());
            Ok(json!({"ok": true, "out": out, "bytes": img.len()}))
        }

        BootCmd::Cpio { sub } => run_cpio(sub, json_mode),
    }
}

fn run_cpio(sub: &CpioCmd, _json_mode: bool) -> Result<Value> {
    match sub {
        CpioCmd::Ls { file } => {
            let data = std::fs::read(file).with_context(|| format!("读取 {file} 失败"))?;
            let c = cpio::Cpio::parse(&data)?;
            let mut list = Vec::new();
            for (name, e) in &c.entries {
                let tc = cpio::type_char(e.mode);
                let perm = e.mode & 0o7777;
                let target = if e.mode & cpio::S_IFMT == cpio::S_IFLNK {
                    String::from_utf8_lossy(&e.data).into_owned()
                } else {
                    String::new()
                };
                log!(
                    "{}{:04o} {:>8} {}{}",
                    tc,
                    perm,
                    e.data.len(),
                    name,
                    if target.is_empty() { String::new() } else { format!(" -> {target}") }
                );
                list.push(json!({
                    "name": name, "type": tc.to_string(), "mode": format!("{:04o}", perm),
                    "size": e.data.len(), "symlink": target,
                }));
            }
            Ok(json!({"ok": true, "count": list.len(), "entries": list}))
        }

        CpioCmd::Extract { file, entry, out } => {
            let data = std::fs::read(file).with_context(|| format!("读取 {file} 失败"))?;
            let c = cpio::Cpio::parse(&data)?;
            match (entry, out) {
                (Some(e), Some(o)) => {
                    let name = e.trim_start_matches('/');
                    let ent = c
                        .entries
                        .get(name)
                        .with_context(|| format!("cpio 内无条目 {name}"))?;
                    std::fs::write(o, &ent.data)?;
                    log!("提取 {name} -> {o}({} 字节)", ent.data.len());
                    Ok(json!({"ok": true, "entry": name, "out": o, "bytes": ent.data.len()}))
                }
                _ => {
                    let dir = out.clone().unwrap_or_else(|| format!("{file}.extracted"));
                    let base = std::path::Path::new(&dir);
                    let mut n = 0;
                    for (name, e) in &c.entries {
                        if e.mode & cpio::S_IFMT == cpio::S_IFREG {
                            let p = base.join(name);
                            if let Some(parent) = p.parent() {
                                std::fs::create_dir_all(parent)?;
                            }
                            std::fs::write(&p, &e.data)?;
                            n += 1;
                        }
                    }
                    log!("提取 {n} 个文件到 {dir}/");
                    Ok(json!({"ok": true, "outdir": dir, "files": n}))
                }
            }
        }

        CpioCmd::Add { file, mode, entry, infile } => {
            let data = std::fs::read(file).with_context(|| format!("读取 {file} 失败"))?;
            let mut c = cpio::Cpio::parse(&data)?;
            let m = parse_octal(mode)?;
            let content = std::fs::read(infile).with_context(|| format!("读取 {infile} 失败"))?;
            let sz = content.len();
            c.add_file(m, entry, content);
            std::fs::write(file, c.serialize())?;
            log!("添加 {entry}(mode {mode}, {sz} 字节)写回 {file}");
            Ok(json!({"ok": true, "entry": entry, "bytes": sz}))
        }

        CpioCmd::Rm { file, entry, recursive } => {
            let data = std::fs::read(file).with_context(|| format!("读取 {file} 失败"))?;
            let mut c = cpio::Cpio::parse(&data)?;
            c.rm(entry, *recursive);
            std::fs::write(file, c.serialize())?;
            log!("删除 {entry}{}写回 {file}", if *recursive { "(递归)" } else { "" });
            Ok(json!({"ok": true, "entry": entry}))
        }

        CpioCmd::Mkdir { file, mode, entry } => {
            let data = std::fs::read(file).with_context(|| format!("读取 {file} 失败"))?;
            let mut c = cpio::Cpio::parse(&data)?;
            let m = parse_octal(mode)?;
            c.mkdir(m, entry);
            std::fs::write(file, c.serialize())?;
            log!("新建目录 {entry}(mode {mode})写回 {file}");
            Ok(json!({"ok": true, "entry": entry}))
        }
    }
}

/// 解析八进制 mode,接受 "0644"/"644"/"0o644"。
fn parse_octal(s: &str) -> Result<u32> {
    let t = s.trim().trim_start_matches("0o");
    u32::from_str_radix(t, 8).with_context(|| format!("mode 需为八进制,如 0644,收到 {s}"))
}

/// 从 header 页读 cmdline(v0-2 @64/512, v3+ @44/1536)。
fn read_cmdline(b: &bootimg::BootImg) -> String {
    let (off, len) = if b.version >= 3 { (44usize, 1536usize) } else { (64usize, 512usize) };
    if b.header_page.len() < off + len {
        return String::new();
    }
    let raw = &b.header_page[off..off + len];
    let end = raw.iter().position(|&c| c == 0).unwrap_or(raw.len());
    String::from_utf8_lossy(&raw[..end]).into_owned()
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
