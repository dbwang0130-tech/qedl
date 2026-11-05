//! Magisk 修补:解 Magisk apk 取 native 资源,按现代 Magisk 流程注入 boot ramdisk。
//!
//! patch 的 cpio 序列对齐高通工具箱 imgkit.bat 验证过的现代分支(26000-28000):
//!   add 0750 init magiskinit
//!   mkdir overlay.d ; mkdir overlay.d/sbin
//!   add overlay.d/sbin/{magisk.xz,stub.xz,init-ld.xz}
//!   mkdir .backup ; add .backup/.magisk config
//! config = KEEPVERITY / KEEPFORCEENCRYPT / RECOVERYMODE / SHA1(原 boot)
//!
//! 未复刻:magiskboot cpio "patch"(verity/forceencrypt 默认 true 时基本 no-op)、
//! "backup"(仅供 magisk 卸载还原,不影响开机)、各老版本分支差异、kernel hexpatch。
//! 默认选项(keepverity/keepforceencrypt=true)下与工具箱注入等价。未真机刷机验证。

use crate::bootimg::BootImg;
use crate::compress::{self, Format};
use crate::cpio::Cpio;
use anyhow::{anyhow, bail, Context, Result};
use sha1::{Digest, Sha1};
use std::io::Read;

pub struct Resources {
    pub magiskinit: Vec<u8>,
    pub magisk_xz: Vec<u8>,
    pub stub_xz: Option<Vec<u8>>,
    pub initld_xz: Option<Vec<u8>>,
    pub arch: String,
}

pub struct PatchOpts {
    pub keep_verity: bool,
    pub keep_forceencrypt: bool,
    pub recovery: bool,
}

/// arch 名 → apk 内 abi 目录。
pub fn abi_dir(arch: &str) -> Result<&'static str> {
    Ok(match arch {
        "arm64" | "arm_64" | "arm64-v8a" => "arm64-v8a",
        "arm" | "arm_32" | "armeabi-v7a" => "armeabi-v7a",
        "x64" | "x86_64" => "x86_64",
        "x86" | "x86_32" => "x86",
        "riscv64" | "riscv_64" => "riscv64",
        other => bail!("未知 arch: {other}(用 arm64/arm/x64/x86/riscv64)"),
    })
}

type Apk = zip::ZipArchive<std::fs::File>;

pub fn open_apk(path: &str) -> Result<Apk> {
    let f = std::fs::File::open(path).with_context(|| format!("打开 apk {path} 失败"))?;
    zip::ZipArchive::new(f).with_context(|| format!("{path} 不是有效 zip/apk"))
}

fn read_entry(apk: &mut Apk, name: &str) -> Option<Vec<u8>> {
    let mut f = apk.by_name(name).ok()?;
    let mut buf = Vec::new();
    f.read_to_end(&mut buf).ok()?;
    Some(buf)
}

/// 读 Magisk 版本(assets/util_functions.sh 的 MAGISK_VER / MAGISK_VER_CODE)。
pub fn version(apk: &mut Apk) -> (Option<String>, Option<String>) {
    let data = read_entry(apk, "assets/util_functions.sh");
    let text = match data {
        Some(d) => String::from_utf8_lossy(&d).into_owned(),
        None => return (None, None),
    };
    let mut ver = None;
    let mut code = None;
    for line in text.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("MAGISK_VER=") {
            ver = Some(v.trim_matches('\'').trim_matches('"').to_string());
        } else if let Some(v) = l.strip_prefix("MAGISK_VER_CODE=") {
            code = Some(v.trim().to_string());
        }
    }
    (ver, code)
}

/// 列出 apk 里存在 libmagiskinit.so 的 abi。
pub fn list_archs(apk: &mut Apk) -> Vec<String> {
    let mut out = Vec::new();
    for abi in ["arm64-v8a", "armeabi-v7a", "x86_64", "x86", "riscv64"] {
        if apk.by_name(&format!("lib/{abi}/libmagiskinit.so")).is_ok() {
            out.push(abi.to_string());
        }
    }
    out
}

/// 解出指定 arch 的资源并 xz 压缩(magisk/stub/init-ld),magiskinit 保持原样。
pub fn extract(apk: &mut Apk, arch: &str) -> Result<Resources> {
    let abi = abi_dir(arch)?;
    let magiskinit = read_entry(apk, &format!("lib/{abi}/libmagiskinit.so"))
        .ok_or_else(|| anyhow!("apk 内缺 lib/{abi}/libmagiskinit.so(arch 不对或 apk 不含该架构)"))?;
    let magisk_so = read_entry(apk, &format!("lib/{abi}/libmagisk.so")).ok_or_else(|| {
        anyhow!("apk 内缺 lib/{abi}/libmagisk.so —— 可能是较老 Magisk(magisk32/64 分离),本工具聚焦现代版(25000+)")
    })?;
    let magisk_xz = compress::compress(Format::Xz, &magisk_so)?;
    let stub_xz = read_entry(apk, "assets/stub.apk")
        .map(|d| compress::compress(Format::Xz, &d))
        .transpose()?;
    let initld_xz = read_entry(apk, &format!("lib/{abi}/libinit-ld.so"))
        .map(|d| compress::compress(Format::Xz, &d))
        .transpose()?;
    Ok(Resources {
        magiskinit,
        magisk_xz,
        stub_xz,
        initld_xz,
        arch: abi.to_string(),
    })
}

fn sha1_hex(data: &[u8]) -> String {
    let mut h = Sha1::new();
    h.update(data);
    h.finalize().iter().map(|b| format!("{:02x}", b)).collect()
}

/// 用资源给 boot 打补丁,返回新 boot 镜像字节。
pub fn patch(boot: &[u8], res: &Resources, opts: &PatchOpts) -> Result<Vec<u8>> {
    let b = BootImg::parse(boot)?;
    if b.ramdisk.is_empty() {
        bail!("该 boot 无 ramdisk,无法注入(可能需要 init_boot 分区)");
    }
    let mut c = Cpio::parse(&b.ramdisk)?;
    if c.exists(".backup/.magisk") || c.exists("overlay.d/sbin/magisk.xz") {
        bail!("这个 boot 已经被 Magisk 修补过,请用原厂 boot 重新修补");
    }
    let sha1 = sha1_hex(boot);

    // 注入(对齐 imgkit 现代分支)
    c.add_file(0o750, "init", res.magiskinit.clone());
    c.mkdir(0o750, "overlay.d");
    c.mkdir(0o750, "overlay.d/sbin");
    c.add_file(0o644, "overlay.d/sbin/magisk.xz", res.magisk_xz.clone());
    if let Some(s) = &res.stub_xz {
        c.add_file(0o644, "overlay.d/sbin/stub.xz", s.clone());
    }
    if let Some(i) = &res.initld_xz {
        c.add_file(0o644, "overlay.d/sbin/init-ld.xz", i.clone());
    }
    c.mkdir(0, ".backup");
    let config = format!(
        "KEEPVERITY={}\nKEEPFORCEENCRYPT={}\nRECOVERYMODE={}\nSHA1={}\n",
        opts.keep_verity, opts.keep_forceencrypt, opts.recovery, sha1
    );
    c.add_file(0, ".backup/.magisk", config.into_bytes());

    let new_ramdisk = c.serialize();
    b.repack(&new_ramdisk)
}
