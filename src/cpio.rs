//! newc cpio(ramdisk 用的格式)解析与编辑。对齐 magiskboot cpio 子命令。

use anyhow::{bail, Result};
use std::collections::BTreeMap;

const MAGIC: &[u8] = b"070701";
const TRAILER: &str = "TRAILER!!!";

pub const S_IFMT: u32 = 0o170000;
pub const S_IFDIR: u32 = 0o040000;
pub const S_IFREG: u32 = 0o100000;
pub const S_IFLNK: u32 = 0o120000;

#[derive(Clone)]
pub struct Entry {
    pub ino: u32,
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub nlink: u32,
    pub mtime: u32,
    pub dev_major: u32,
    pub dev_minor: u32,
    pub rdev_major: u32,
    pub rdev_minor: u32,
    pub data: Vec<u8>,
}

/// 保持插入顺序的 cpio 归档。
pub struct Cpio {
    /// 文件名 -> 条目。用 BTreeMap 保证稳定(名字序),repack 不要求原始顺序。
    pub entries: BTreeMap<String, Entry>,
}

fn align4(n: usize) -> usize {
    (n + 3) & !3
}

fn rd_hex(d: &[u8], off: usize) -> Result<u32> {
    let s = std::str::from_utf8(&d[off..off + 8])?;
    Ok(u32::from_str_radix(s, 16)?)
}

impl Cpio {
    pub fn parse(data: &[u8]) -> Result<Cpio> {
        let mut entries = BTreeMap::new();
        let mut pos = 0;
        while pos + 110 <= data.len() {
            if &data[pos..pos + 6] != MAGIC {
                // 可能是末尾填充
                break;
            }
            let mode = rd_hex(data, pos + 14)?;
            let ino = rd_hex(data, pos + 6)?;
            let uid = rd_hex(data, pos + 22)?;
            let gid = rd_hex(data, pos + 30)?;
            let nlink = rd_hex(data, pos + 38)?;
            let mtime = rd_hex(data, pos + 46)?;
            let filesize = rd_hex(data, pos + 54)? as usize;
            let dev_major = rd_hex(data, pos + 62)?;
            let dev_minor = rd_hex(data, pos + 70)?;
            let rdev_major = rd_hex(data, pos + 78)?;
            let rdev_minor = rd_hex(data, pos + 86)?;
            let namesize = rd_hex(data, pos + 94)? as usize;
            // name 从 pos+110 起,含结尾 \0
            let name_start = pos + 110;
            if name_start + namesize > data.len() {
                bail!("cpio 头越界");
            }
            let name_raw = &data[name_start..name_start + namesize];
            let name = String::from_utf8_lossy(&name_raw[..namesize.saturating_sub(1)]).into_owned();
            // header+name 对齐 4
            let data_start = pos + align4(110 + namesize);
            if name == TRAILER {
                break;
            }
            if data_start + filesize > data.len() {
                bail!("cpio 数据越界");
            }
            let body = data[data_start..data_start + filesize].to_vec();
            entries.insert(
                name,
                Entry {
                    ino,
                    mode,
                    uid,
                    gid,
                    nlink,
                    mtime,
                    dev_major,
                    dev_minor,
                    rdev_major,
                    rdev_minor,
                    data: body,
                },
            );
            pos = align4(data_start + filesize);
        }
        Ok(Cpio { entries })
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut out = Vec::new();
        let mut ino = 300000u32;
        for (name, e) in &self.entries {
            Self::write_entry(&mut out, name, e, ino);
            ino += 1;
        }
        // TRAILER
        let trailer = Entry {
            ino: 0,
            mode: 0,
            uid: 0,
            gid: 0,
            nlink: 1,
            mtime: 0,
            dev_major: 0,
            dev_minor: 0,
            rdev_major: 0,
            rdev_minor: 0,
            data: Vec::new(),
        };
        Self::write_entry(&mut out, TRAILER, &trailer, 0);
        // 整体对齐(magiskboot 填充到 4 字节,已在每条处理)
        out
    }

    fn write_entry(out: &mut Vec<u8>, name: &str, e: &Entry, ino: u32) {
        let namesize = name.len() + 1;
        let hdr = format!(
            "070701{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}{:08x}00000000",
            ino,
            e.mode,
            e.uid,
            e.gid,
            e.nlink,
            e.mtime,
            e.data.len(),
            e.dev_major,
            e.dev_minor,
            e.rdev_major,
            e.rdev_minor,
            namesize,
        );
        out.extend_from_slice(hdr.as_bytes());
        out.extend_from_slice(name.as_bytes());
        out.push(0);
        // header+name 对齐 4
        while out.len() % 4 != 0 {
            out.push(0);
        }
        out.extend_from_slice(&e.data);
        while out.len() % 4 != 0 {
            out.push(0);
        }
    }

    pub fn exists(&self, name: &str) -> bool {
        self.entries.contains_key(name.trim_start_matches('/'))
    }

    pub fn rm(&mut self, name: &str, recursive: bool) {
        let name = name.trim_start_matches('/').to_string();
        self.entries.remove(&name);
        if recursive {
            let prefix = format!("{}/", name);
            let keys: Vec<String> = self
                .entries
                .keys()
                .filter(|k| k.starts_with(&prefix))
                .cloned()
                .collect();
            for k in keys {
                self.entries.remove(&k);
            }
        }
    }

    pub fn mkdir(&mut self, mode: u32, name: &str) {
        let name = name.trim_start_matches('/').to_string();
        self.entries.insert(
            name,
            Entry {
                ino: 0,
                mode: S_IFDIR | (mode & 0o7777),
                uid: 0,
                gid: 0,
                nlink: 2,
                mtime: 0,
                dev_major: 0,
                dev_minor: 0,
                rdev_major: 0,
                rdev_minor: 0,
                data: Vec::new(),
            },
        );
    }

    pub fn add_file(&mut self, mode: u32, name: &str, data: Vec<u8>) {
        let name = name.trim_start_matches('/').to_string();
        self.entries.insert(
            name,
            Entry {
                ino: 0,
                mode: S_IFREG | (mode & 0o7777),
                uid: 0,
                gid: 0,
                nlink: 1,
                mtime: 0,
                dev_major: 0,
                dev_minor: 0,
                rdev_major: 0,
                rdev_minor: 0,
                data,
            },
        );
    }

    pub fn symlink(&mut self, target: &str, name: &str) {
        let name = name.trim_start_matches('/').to_string();
        self.entries.insert(
            name,
            Entry {
                ino: 0,
                mode: S_IFLNK | 0o777,
                uid: 0,
                gid: 0,
                nlink: 1,
                mtime: 0,
                dev_major: 0,
                dev_minor: 0,
                rdev_major: 0,
                rdev_minor: 0,
                data: target.as_bytes().to_vec(),
            },
        );
    }
}

/// 把 mode 高位转成类型字符,便于 ls 展示。
pub fn type_char(mode: u32) -> char {
    match mode & S_IFMT {
        S_IFDIR => 'd',
        S_IFLNK => 'l',
        S_IFREG => '-',
        _ => '?',
    }
}
