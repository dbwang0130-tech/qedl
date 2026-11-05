//! USB 传输层:封装 rusb,负责找 9008 设备、claim 接口、bulk 读写。
//!
//! 对齐 bkerler/edl 的 usblib.py 关键语义:
//! - 写:按 16384 分块;空 slice 发 ZLP。
//! - 读:一次 read_bulk = 一次 libusb bulk transfer(libusb 内部把多个 maxpacket 拼到 buffer)。

use anyhow::{anyhow, bail, Context, Result};
use rusb::{Device, DeviceHandle, Direction, GlobalContext, TransferType};
use std::time::{Duration, Instant};

const WRITE_CHUNK: usize = 16384; // MAX_USB_BULK_BUFFER_SIZE

pub struct UsbDev {
    handle: DeviceHandle<GlobalContext>,
    iface: u8,
    ep_in: u8,
    ep_out: u8,
    pub max_packet_in: u16,
    pub vid: u16,
    pub pid: u16,
    /// 读取单次 bulk transfer 的缓冲大小上限(字节)。
    pub read_buf: usize,
}

/// 轮询检测 9008 是否出现(不打开)。返回找到的 (vid,pid)。
pub fn detect(ids: &[(u16, u16)]) -> Option<(u16, u16)> {
    let devices = rusb::devices().ok()?;
    for dev in devices.iter() {
        if let Ok(d) = dev.device_descriptor() {
            let v = d.vendor_id();
            let p = d.product_id();
            if ids.iter().any(|&(iv, ip)| iv == v && ip == p) {
                return Some((v, p));
            }
        }
    }
    None
}

/// 轮询等待设备出现,超时(秒)后放弃。PBL 会超时自动重启,所以 interval 要小。
pub fn wait_for(ids: &[(u16, u16)], timeout_secs: f64) -> Option<(u16, u16)> {
    let start = Instant::now();
    loop {
        if let Some(found) = detect(ids) {
            return Some(found);
        }
        if start.elapsed().as_secs_f64() >= timeout_secs {
            return None;
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

impl UsbDev {
    /// 打开匹配 ids 中任一 (vid,pid) 的第一个设备,找到 vendor 接口的 bulk in/out。
    pub fn open(ids: &[(u16, u16)]) -> Result<UsbDev> {
        let devices = rusb::devices().context("枚举 USB 设备失败")?;
        for dev in devices.iter() {
            let desc = match dev.device_descriptor() {
                Ok(d) => d,
                Err(_) => continue,
            };
            let v = desc.vendor_id();
            let p = desc.product_id();
            if !ids.iter().any(|&(iv, ip)| iv == v && ip == p) {
                continue;
            }
            match Self::open_dev(&dev, v, p) {
                Ok(u) => return Ok(u),
                Err(e) => return Err(e),
            }
        }
        bail!(
            "未找到 EDL 设备({})。进 9008:关机→按住音量上+下→插线。",
            ids.iter()
                .map(|(v, p)| format!("{:04x}:{:04x}", v, p))
                .collect::<Vec<_>>()
                .join(", ")
        )
    }

    fn open_dev(dev: &Device<GlobalContext>, vid: u16, pid: u16) -> Result<UsbDev> {
        let handle = dev
            .open()
            .with_context(|| format!("打开 {:04x}:{:04x} 失败(权限?)", vid, pid))?;

        // Linux 下自动 detach;Mac 为 noop,忽略错误。
        let _ = handle.set_auto_detach_kernel_driver(true);

        let config = dev
            .active_config_descriptor()
            .or_else(|_| dev.config_descriptor(0))
            .context("读取配置描述符失败")?;

        // 找一个同时有 bulk IN+OUT 的接口(EDL vendor 接口 class 0xFF)。
        let mut found: Option<(u8, u8, u8, u16)> = None;
        for iface in config.interfaces() {
            for desc in iface.descriptors() {
                let mut ep_in = None;
                let mut ep_out = None;
                let mut mp_in = 512u16;
                for ep in desc.endpoint_descriptors() {
                    if ep.transfer_type() != TransferType::Bulk {
                        continue;
                    }
                    match ep.direction() {
                        Direction::In => {
                            ep_in = Some(ep.address());
                            mp_in = ep.max_packet_size();
                        }
                        Direction::Out => ep_out = Some(ep.address()),
                    }
                }
                if let (Some(i), Some(o)) = (ep_in, ep_out) {
                    found = Some((desc.interface_number(), i, o, mp_in));
                    break;
                }
            }
            if found.is_some() {
                break;
            }
        }

        let (iface, ep_in, ep_out, mp_in) =
            found.ok_or_else(|| anyhow!("设备没有可用的 bulk in/out 接口"))?;

        // 某些 mac 环境需要显式设置配置;失败不致命。
        let _ = handle.set_active_configuration(config.number());

        handle
            .claim_interface(iface)
            .with_context(|| format!("claim interface {} 失败", iface))?;

        Ok(UsbDev {
            handle,
            iface,
            ep_in,
            ep_out,
            max_packet_in: mp_in,
            vid,
            pid,
            read_buf: 1 << 20, // 1MB
        })
    }

    /// 写入数据,按 16384 分块。对齐 usblib.write。
    pub fn write(&self, data: &[u8], timeout: Duration) -> Result<()> {
        if data.is_empty() {
            return self.write_zlp(timeout);
        }
        let mut pos = 0;
        while pos < data.len() {
            let end = (pos + WRITE_CHUNK).min(data.len());
            self.handle
                .write_bulk(self.ep_out, &data[pos..end], timeout)
                .context("USB 写入失败")?;
            pos = end;
        }
        Ok(())
    }

    /// 发送零长包(ZLP)。Firehose program/erase 每块后需要。
    pub fn write_zlp(&self, timeout: Duration) -> Result<()> {
        self.handle
            .write_bulk(self.ep_out, &[], timeout)
            .context("USB 发送 ZLP 失败")?;
        Ok(())
    }

    /// 一次 bulk 读,最多 `max` 字节。超时返回空 Vec(非错误)。
    pub fn read(&self, max: usize, timeout: Duration) -> Result<Vec<u8>> {
        let cap = max.min(self.read_buf).max(self.max_packet_in as usize);
        let mut buf = vec![0u8; cap];
        match self.handle.read_bulk(self.ep_in, &mut buf, timeout) {
            Ok(n) => {
                buf.truncate(n);
                Ok(buf)
            }
            Err(rusb::Error::Timeout) => Ok(Vec::new()),
            Err(rusb::Error::Overflow) => Err(anyhow!("USB overflow")),
            Err(e) => Err(anyhow!("USB 读取失败: {e}")),
        }
    }

    /// 读满 exactly `len` 字节(用于 sahara 定长包 / 分区数据)。超时即停。
    pub fn read_exact_timeout(&self, len: usize, timeout: Duration) -> Result<Vec<u8>> {
        let mut out = Vec::with_capacity(len);
        while out.len() < len {
            let chunk = self.read(len - out.len(), timeout)?;
            if chunk.is_empty() {
                break;
            }
            out.extend_from_slice(&chunk);
        }
        Ok(out)
    }
}

impl Drop for UsbDev {
    fn drop(&mut self) {
        let _ = self.handle.release_interface(self.iface);
    }
}
