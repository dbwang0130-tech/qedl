//! Android boot image 解析 / unpack / repack。对齐 magiskboot unpack/repack。
//! 支持 header v0-v4。策略:保留原始 header 页逐字节,repack 时只改尺寸字段与 id,
//! 最大限度不破坏厂商自定义/quirk,降低变砖风险。

use crate::compress::{self, Format};
use anyhow::{bail, Context, Result};
use sha1::{Digest, Sha1};
use std::path::Path;

const MAGIC: &[u8] = b"ANDROID!";

pub struct BootImg {
    pub version: u32,
    pub page_size: usize,
    pub header_page: Vec<u8>, // 原始首页(含 header),repack 时原样改尺寸
    pub kernel: Vec<u8>,
    pub ramdisk_raw: Vec<u8>,  // 压缩态
    pub ramdisk: Vec<u8>,      // 解压后
    pub ramdisk_fmt: Format,
    pub second: Vec<u8>,
    pub recovery_dtbo: Vec<u8>,
    pub dtb: Vec<u8>,
}

fn rd_u32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn wr_u32(d: &mut [u8], o: usize, v: u32) {
    d[o..o + 4].copy_from_slice(&v.to_le_bytes());
}
fn round_up(n: usize, align: usize) -> usize {
    (n + align - 1) / align * align
}

impl BootImg {
    pub fn parse(data: &[u8]) -> Result<BootImg> {
        if data.len() < 64 || &data[0..8] != MAGIC {
            bail!("不是 Android boot 镜像(缺 ANDROID! 魔数)");
        }
        let version = rd_u32(data, 40);
        if version >= 3 {
            return Self::parse_v3(data, version);
        }
        // v0-v2
        let kernel_size = rd_u32(data, 8) as usize;
        let ramdisk_size = rd_u32(data, 16) as usize;
        let second_size = rd_u32(data, 24) as usize;
        let page_size = rd_u32(data, 36) as usize;
        if page_size == 0 {
            bail!("page_size 为 0");
        }
        let mut recovery_dtbo_size = 0usize;
        let mut dtb_size = 0usize;
        if version >= 1 {
            recovery_dtbo_size = rd_u32(data, 1632) as usize;
        }
        if version >= 2 {
            dtb_size = rd_u32(data, 1648) as usize;
        }

        let mut off = round_up(page_size, page_size); // 首页之后
        let kernel = read_section(data, &mut off, kernel_size, page_size, "kernel")?;
        let ramdisk_raw = read_section(data, &mut off, ramdisk_size, page_size, "ramdisk")?;
        let second = read_section(data, &mut off, second_size, page_size, "second")?;
        let recovery_dtbo =
            read_section(data, &mut off, recovery_dtbo_size, page_size, "recovery_dtbo")?;
        let dtb = read_section(data, &mut off, dtb_size, page_size, "dtb")?;

        let header_page = data[0..page_size.min(data.len())].to_vec();
        let (ramdisk, ramdisk_fmt) = decomp_ramdisk(&ramdisk_raw)?;

        Ok(BootImg {
            version,
            page_size,
            header_page,
            kernel,
            ramdisk_raw,
            ramdisk,
            ramdisk_fmt,
            second,
            recovery_dtbo,
            dtb,
        })
    }

    fn parse_v3(data: &[u8], version: u32) -> Result<BootImg> {
        let page_size = 4096;
        let kernel_size = rd_u32(data, 8) as usize;
        let ramdisk_size = rd_u32(data, 12) as usize;
        let mut off = page_size;
        let kernel = read_section(data, &mut off, kernel_size, page_size, "kernel")?;
        let ramdisk_raw = read_section(data, &mut off, ramdisk_size, page_size, "ramdisk")?;
        let header_page = data[0..page_size.min(data.len())].to_vec();
        let (ramdisk, ramdisk_fmt) = decomp_ramdisk(&ramdisk_raw)?;
        Ok(BootImg {
            version,
            page_size,
            header_page,
            kernel,
            ramdisk_raw,
            ramdisk,
            ramdisk_fmt,
            second: Vec::new(),
            recovery_dtbo: Vec::new(),
            dtb: Vec::new(),
        })
    }

    /// 用(可能已修改的)ramdisk 重新打包。kernel/dtb 等保持原样。
    pub fn repack(&self, new_ramdisk: &[u8]) -> Result<Vec<u8>> {
        // 压缩 ramdisk(沿用原格式)
        let fmt = if self.ramdisk_fmt == Format::Raw {
            Format::Gzip
        } else {
            self.ramdisk_fmt
        };
        let ramdisk_comp = compress::compress(fmt, new_ramdisk)?;

        let mut header = self.header_page.clone();
        if self.version >= 3 {
            wr_u32(&mut header, 8, self.kernel.len() as u32);
            wr_u32(&mut header, 12, ramdisk_comp.len() as u32);
        } else {
            wr_u32(&mut header, 8, self.kernel.len() as u32);
            wr_u32(&mut header, 16, ramdisk_comp.len() as u32);
            wr_u32(&mut header, 24, self.second.len() as u32);
            if self.version >= 1 {
                wr_u32(&mut header, 1632, self.recovery_dtbo.len() as u32);
            }
            if self.version >= 2 {
                wr_u32(&mut header, 1648, self.dtb.len() as u32);
            }
            // 重算 id(mkbootimg 方式)
            let id = self.compute_id(&ramdisk_comp);
            header[576..576 + 20].copy_from_slice(&id);
            for b in header.iter_mut().take(576 + 32).skip(576 + 20) {
                *b = 0;
            }
        }

        let ps = self.page_size;
        let mut out = Vec::new();
        out.extend_from_slice(&header);
        pad_to(&mut out, ps);
        push_section(&mut out, &self.kernel, ps);
        push_section(&mut out, &ramdisk_comp, ps);
        if self.version < 3 {
            push_section(&mut out, &self.second, ps);
            push_section(&mut out, &self.recovery_dtbo, ps);
            push_section(&mut out, &self.dtb, ps);
        }
        Ok(out)
    }

    fn compute_id(&self, ramdisk_comp: &[u8]) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(&self.kernel);
        h.update((self.kernel.len() as u32).to_le_bytes());
        h.update(ramdisk_comp);
        h.update((ramdisk_comp.len() as u32).to_le_bytes());
        h.update(&self.second);
        h.update((self.second.len() as u32).to_le_bytes());
        if self.version >= 1 {
            h.update(&self.recovery_dtbo);
            h.update((self.recovery_dtbo.len() as u32).to_le_bytes());
        }
        if self.version >= 2 {
            h.update(&self.dtb);
            h.update((self.dtb.len() as u32).to_le_bytes());
        }
        let d = h.finalize();
        let mut id = [0u8; 20];
        id.copy_from_slice(&d[..20]);
        id
    }

    /// 解包到目录:kernel / ramdisk.cpio / dtb / second / recovery_dtbo / header.bin / ramdisk_fmt。
    pub fn unpack_to(&self, dir: &Path) -> Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("header.bin"), &self.header_page)?;
        std::fs::write(dir.join("ramdisk_fmt"), self.ramdisk_fmt.name())?;
        std::fs::write(dir.join("kernel"), &self.kernel)?;
        std::fs::write(dir.join("ramdisk.cpio"), &self.ramdisk)?;
        if !self.second.is_empty() {
            std::fs::write(dir.join("second"), &self.second)?;
        }
        if !self.recovery_dtbo.is_empty() {
            std::fs::write(dir.join("recovery_dtbo"), &self.recovery_dtbo)?;
        }
        if !self.dtb.is_empty() {
            std::fs::write(dir.join("dtb"), &self.dtb)?;
        }
        Ok(())
    }
}

fn read_section(
    data: &[u8],
    off: &mut usize,
    size: usize,
    page_size: usize,
    what: &str,
) -> Result<Vec<u8>> {
    if size == 0 {
        return Ok(Vec::new());
    }
    if *off + size > data.len() {
        bail!("{what} 段越界(off={off} size={size} len={})", data.len());
    }
    let sec = data[*off..*off + size].to_vec();
    *off = round_up(*off + size, page_size);
    Ok(sec)
}

fn decomp_ramdisk(raw: &[u8]) -> Result<(Vec<u8>, Format)> {
    if raw.is_empty() {
        return Ok((Vec::new(), Format::Raw));
    }
    let fmt = compress::detect(raw);
    let data = compress::decompress(fmt, raw)
        .with_context(|| format!("ramdisk 解压失败(格式 {})", fmt.name()))?;
    Ok((data, fmt))
}

fn pad_to(out: &mut Vec<u8>, align: usize) {
    while out.len() % align != 0 {
        out.push(0);
    }
}
fn push_section(out: &mut Vec<u8>, sec: &[u8], page_size: usize) {
    if sec.is_empty() {
        return;
    }
    out.extend_from_slice(sec);
    pad_to(out, page_size);
}

/// repack 入口:从 unpack 目录重建镜像。
pub fn repack_from_dir(dir: &Path) -> Result<Vec<u8>> {
    let header_page = std::fs::read(dir.join("header.bin")).context("缺 header.bin")?;
    let fmt_name = std::fs::read_to_string(dir.join("ramdisk_fmt")).unwrap_or_else(|_| "gzip".into());
    let kernel = std::fs::read(dir.join("kernel")).unwrap_or_default();
    let ramdisk = std::fs::read(dir.join("ramdisk.cpio")).context("缺 ramdisk.cpio")?;
    let second = std::fs::read(dir.join("second")).unwrap_or_default();
    let recovery_dtbo = std::fs::read(dir.join("recovery_dtbo")).unwrap_or_default();
    let dtb = std::fs::read(dir.join("dtb")).unwrap_or_default();

    if header_page.len() < 44 || &header_page[0..8] != MAGIC {
        bail!("header.bin 非法");
    }
    let version = rd_u32(&header_page, 40);
    let page_size = if version >= 3 {
        4096
    } else {
        rd_u32(&header_page, 36) as usize
    };
    let fmt = fmt_name_to_format(fmt_name.trim());
    let img = BootImg {
        version,
        page_size,
        header_page,
        kernel,
        ramdisk_raw: Vec::new(),
        ramdisk: ramdisk.clone(),
        ramdisk_fmt: fmt,
        second,
        recovery_dtbo,
        dtb,
    };
    img.repack(&ramdisk)
}

fn fmt_name_to_format(name: &str) -> Format {
    match name {
        "gzip" => Format::Gzip,
        "xz" => Format::Xz,
        "lzma" => Format::Lzma,
        "lz4" => Format::Lz4,
        "lz4_legacy" => Format::Lz4Legacy,
        "bzip2" => Format::Bzip2,
        "lzop" => Format::Lzop,
        _ => Format::Raw,
    }
}
