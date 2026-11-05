//! ramdisk 压缩格式检测与编解码。对齐 magiskboot 支持的常见格式。
//! 纯 Rust 实现,保持 qedl 自包含。

use anyhow::{anyhow, bail, Result};
use std::io::{Read, Write};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Format {
    Gzip,
    Xz,
    Lzma,
    Lz4,       // lz4 frame
    Lz4Legacy, // lz4 legacy(高通 ramdisk 常见)
    Bzip2,
    Lzop,
    Raw, // 未压缩/未知
}

impl Format {
    pub fn name(&self) -> &'static str {
        match self {
            Format::Gzip => "gzip",
            Format::Xz => "xz",
            Format::Lzma => "lzma",
            Format::Lz4 => "lz4",
            Format::Lz4Legacy => "lz4_legacy",
            Format::Bzip2 => "bzip2",
            Format::Lzop => "lzop",
            Format::Raw => "raw",
        }
    }
}

const LZ4_LEGACY_MAGIC: u32 = 0x184C2102;
const LZ4_BLOCK_MAX: usize = 0x800000; // 8MB

/// 按魔数识别压缩格式。
pub fn detect(data: &[u8]) -> Format {
    if data.len() >= 2 && data[0] == 0x1f && data[1] == 0x8b {
        return Format::Gzip;
    }
    if data.len() >= 6 && &data[0..6] == b"\xfd7zXZ\x00" {
        return Format::Xz;
    }
    if data.len() >= 4 && data[0] == 0x02 && data[1] == 0x21 && data[2] == 0x4c && data[3] == 0x18 {
        return Format::Lz4Legacy;
    }
    if data.len() >= 4 && data[0] == 0x04 && data[1] == 0x22 && data[2] == 0x4d && data[3] == 0x18 {
        return Format::Lz4;
    }
    if data.len() >= 3 && data[0] == 0x42 && data[1] == 0x5a && data[2] == 0x68 {
        return Format::Bzip2;
    }
    if data.len() >= 4 && data[0] == 0x89 && &data[1..4] == b"LZO" {
        return Format::Lzop;
    }
    // lzma: 5d 00 00 (properties byte 0x5d 常见)
    if data.len() >= 3 && data[0] == 0x5d && data[1] == 0x00 && data[2] == 0x00 {
        return Format::Lzma;
    }
    Format::Raw
}

/// 解压。返回原始数据。
pub fn decompress(fmt: Format, data: &[u8]) -> Result<Vec<u8>> {
    match fmt {
        Format::Gzip => {
            let mut out = Vec::new();
            flate2::read::MultiGzDecoder::new(data).read_to_end(&mut out)?;
            Ok(out)
        }
        Format::Xz => {
            let mut out = Vec::new();
            let mut cur = std::io::Cursor::new(data);
            lzma_rs::xz_decompress(&mut cur, &mut out)
                .map_err(|e| anyhow!("xz 解压失败: {e:?}"))?;
            Ok(out)
        }
        Format::Lzma => {
            let mut out = Vec::new();
            let mut cur = std::io::Cursor::new(data);
            lzma_rs::lzma_decompress(&mut cur, &mut out)
                .map_err(|e| anyhow!("lzma 解压失败: {e:?}"))?;
            Ok(out)
        }
        Format::Lz4 => {
            let mut out = Vec::new();
            lz4_flex::frame::FrameDecoder::new(data).read_to_end(&mut out)?;
            Ok(out)
        }
        Format::Lz4Legacy => decompress_lz4_legacy(data),
        Format::Raw => Ok(data.to_vec()),
        other => bail!("暂不支持解压格式 {}", other.name()),
    }
}

/// 压缩成指定格式(用于 repack)。
pub fn compress(fmt: Format, data: &[u8]) -> Result<Vec<u8>> {
    match fmt {
        Format::Gzip => {
            let mut enc =
                flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(9));
            enc.write_all(data)?;
            Ok(enc.finish()?)
        }
        Format::Xz => {
            let mut out = Vec::new();
            let mut cur = std::io::Cursor::new(data);
            lzma_rs::xz_compress(&mut cur, &mut out)
                .map_err(|e| anyhow!("xz 压缩失败: {e:?}"))?;
            Ok(out)
        }
        Format::Lz4Legacy => compress_lz4_legacy(data),
        Format::Raw => Ok(data.to_vec()),
        other => bail!(
            "暂不支持压缩回 {} 格式(repack 时可改用 --compress gzip)",
            other.name()
        ),
    }
}

fn decompress_lz4_legacy(data: &[u8]) -> Result<Vec<u8>> {
    if data.len() < 4 {
        bail!("lz4_legacy 数据过短");
    }
    let magic = u32::from_le_bytes([data[0], data[1], data[2], data[3]]);
    if magic != LZ4_LEGACY_MAGIC {
        bail!("lz4_legacy 魔数不符");
    }
    let mut pos = 4;
    let mut out = Vec::new();
    let mut buf = vec![0u8; LZ4_BLOCK_MAX];
    while pos + 4 <= data.len() {
        let block_size =
            u32::from_le_bytes([data[pos], data[pos + 1], data[pos + 2], data[pos + 3]]) as usize;
        pos += 4;
        // 遇到下一个 magic 或 0 长度则结束
        if block_size == 0 || block_size as u32 == LZ4_LEGACY_MAGIC {
            break;
        }
        if pos + block_size > data.len() {
            break;
        }
        let n = lz4_flex::block::decompress_into(&data[pos..pos + block_size], &mut buf)
            .map_err(|e| anyhow!("lz4_legacy 块解压失败: {e:?}"))?;
        out.extend_from_slice(&buf[..n]);
        pos += block_size;
    }
    Ok(out)
}

fn compress_lz4_legacy(data: &[u8]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&LZ4_LEGACY_MAGIC.to_le_bytes());
    for chunk in data.chunks(LZ4_BLOCK_MAX) {
        let comp = lz4_flex::block::compress(chunk);
        out.extend_from_slice(&(comp.len() as u32).to_le_bytes());
        out.extend_from_slice(&comp);
    }
    Ok(out)
}
