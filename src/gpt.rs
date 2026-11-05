//! GPT 解析。对齐 bkerler/edl 的 gpt.py(只做读取/查名,不做写回)。

use serde::Serialize;

fn rd_u32(d: &[u8], o: usize) -> u32 {
    u32::from_le_bytes([d[o], d[o + 1], d[o + 2], d[o + 3]])
}
fn rd_u64(d: &[u8], o: usize) -> u64 {
    let mut b = [0u8; 8];
    b.copy_from_slice(&d[o..o + 8]);
    u64::from_le_bytes(b)
}

#[derive(Serialize, Clone)]
pub struct Partition {
    pub name: String,
    pub start_sector: u64,
    pub num_sectors: u64,
    pub flags: u64,
    pub unique_guid: String,
}

pub struct GptHeader {
    pub part_entry_start_lba: u64,
    pub num_part_entries: u32,
    pub part_entry_size: u32,
}

/// 从 LBA0 起的缓冲里解析 GPT 头(位于 LBA1,即偏移 sectorsize)。
pub fn parse_header(data: &[u8], sectorsize: usize) -> Option<GptHeader> {
    if data.len() < sectorsize + 0x5C {
        return None;
    }
    let h = &data[sectorsize..];
    if &h[0..8] != b"EFI PART" {
        return None;
    }
    let revision = rd_u32(h, 8);
    if revision != 0x10000 {
        return None;
    }
    Some(GptHeader {
        part_entry_start_lba: rd_u64(h, 72),
        num_part_entries: rd_u32(h, 80),
        part_entry_size: rd_u32(h, 84),
    })
}

/// 解析分区表。`data` 需包含从 LBA0 到分区项区域的全部扇区。
pub fn parse(data: &[u8], sectorsize: usize) -> Option<Vec<Partition>> {
    let hdr = parse_header(data, sectorsize)?;
    let entrysize = hdr.part_entry_size as usize;
    if entrysize < 128 {
        return None;
    }
    let start = hdr.part_entry_start_lba as usize * sectorsize;
    let mut parts = Vec::new();
    for idx in 0..hdr.num_part_entries as usize {
        let off = start + idx * entrysize;
        if off + entrysize > data.len() {
            break;
        }
        let e = &data[off..off + entrysize];
        // unique GUID 全 0 => 表结束
        if e[16..32].iter().all(|&b| b == 0) {
            break;
        }
        let type_first = rd_u32(e, 0);
        if type_first == 0 {
            continue; // EFI_UNUSED
        }
        let first_lba = rd_u64(e, 32);
        let last_lba = rd_u64(e, 40);
        let flags = rd_u64(e, 48);
        let name = decode_utf16le(&e[56..128]);
        let unique = format_guid(&e[16..32]);
        parts.push(Partition {
            name,
            start_sector: first_lba,
            num_sectors: last_lba.saturating_sub(first_lba) + 1,
            flags,
            unique_guid: unique,
        });
    }
    Some(parts)
}

fn decode_utf16le(b: &[u8]) -> String {
    let mut u16s = Vec::with_capacity(b.len() / 2);
    for c in b.chunks_exact(2) {
        let v = u16::from_le_bytes([c[0], c[1]]);
        if v == 0 {
            break;
        }
        u16s.push(v);
    }
    String::from_utf16_lossy(&u16s)
}

fn format_guid(b: &[u8]) -> String {
    let d1 = rd_u32(b, 0);
    let d2 = u16::from_le_bytes([b[4], b[5]]);
    let d3 = u16::from_le_bytes([b[6], b[7]]);
    let d4 = u16::from_be_bytes([b[8], b[9]]);
    let rest: String = b[10..16].iter().map(|x| format!("{:02x}", x)).collect();
    format!("{:08x}-{:04x}-{:04x}-{:04x}-{}", d1, d2, d3, d4, rest)
}
