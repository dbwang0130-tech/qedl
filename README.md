# qedl

Rust 版高通 9008 EDL 工具(Sahara + Firehose),编译成 **Mac 原生二进制,免安装**——替代 bkerler/edl 的 Python + uv venv 流程。

实现的是「够用子集 + 常用增强」:Sahara 上传 loader、Firehose configure / getstorageinfo / GPT 解析 / 按分区名读写擦除 / peek/poke / reset。面向 agent:所有命令支持 `--json` 结构化输出(stdout),人类日志走 stderr,退出码 0=成功 1=失败。

## 构建

```sh
cd ~/Projects/qedl
cargo build --release
# 产物:target/release/qedl(自包含 vendored libusb,拷走即用)
```

## 用法

全局选项:`--loader <path>`(除 detect/info 外必需)、`--memory ufs|emmc`、`--sector-size N`、`--max-payload N`、`--vid/--pid`(hex)、`--wait <秒>`(轮询等待设备,PBL 会超时重启所以别设太大)、`--json`。

loader 已随仓库备份在 `loaders/`(见 `loaders/README.md`),S2 用 `devprg_665_mi_noauth`。

```sh
L=loaders/devprg_665_mi_noauth   # firehose loader(已验证,随仓库自带)

qedl detect                       # 只看 9008 是否在线
qedl info                         # sahara 命令模式读 serial/hwid/pkhash(刚进 9008 时)
qedl -l $L storageinfo            # 存储信息
qedl -l $L printgpt               # 列全部分区
qedl -l $L printgpt --json        # 同上,JSON

qedl -l $L read  devinfo out.img          # 按分区名读
qedl -l $L read-lun 4 178566 1 out.img    # 按 lun/起始扇区/扇区数读
qedl -l $L write devinfo in.img           # 按分区名写(program)
qedl -l $L write-lun 4 178566 in.img      # 按 lun/起始扇区写
qedl -l $L erase misc                     # 擦除分区
qedl -l $L peek 0x200000 256              # 读内存(hex 打印或 -> 文件)
qedl -l $L poke 0x200000 0101             # 写内存
qedl -l $L reset reset                    # 重启(reset / edl / off)
```

## 本地 boot 镜像处理(集成 magiskboot 功能,不碰设备)

把 magiskboot 的核心能力并进来了,配合 EDL 读写形成「读 boot → 改 → 写回」闭环,全程 Mac 原生:

```sh
qedl boot info  boot.img                       # 看头信息(版本/各段/ramdisk 压缩格式)
qedl boot unpack boot.img ud                   # 解包:ud/{header.bin,kernel,ramdisk.cpio,dtb,...}
qedl boot cpio ls      ud/ramdisk.cpio         # 列 ramdisk 内容
qedl boot cpio extract ud/ramdisk.cpio fstab.default out   # 提取单个
qedl boot cpio add     ud/ramdisk.cpio 0644 my.sh file.sh  # 加/替换文件
qedl boot cpio rm      ud/ramdisk.cpio some.file           # 删
qedl boot cpio mkdir   ud/ramdisk.cpio 0755 overlay        # 建目录
qedl boot repack ud boot.new.img               # 重打包(ramdisk 按原格式重压)
```

- 支持 header **v0-v4**;ramdisk 压缩:**gzip**(读写)、xz/lzma/lz4/lz4_legacy(解压,压缩回 gzip/xz/lz4_legacy)。
- repack 保留原始 header 页逐字节,只改尺寸字段并重算 id,最大限度不破坏厂商 quirk。
- 典型闭环(S2 开 adb 思路,方案 B):
  ```sh
  qedl -l $L read boot_b boot_b.img       # EDL 读出
  qedl boot unpack boot_b.img ud          # 解包
  # …编辑 ud/ramdisk.cpio(改 fstab / 加 init 脚本 / resetprop 等)…
  qedl boot repack ud boot_b.new.img      # 重打包
  qedl -l $L write boot_b boot_b.new.img  # EDL 写回
  ```

## 进 9008

关机 → 按住音量上+下 → 插线(黑屏正常)。PBL 若迟迟收不到 firehose 会超时自动重启,所以检测到后要立刻上传。

## 已验证(真机小猿学练机 S2 / 骁龙 665 Nicobar / UFS)

- Sahara 握手 + firehose 模式识别
- configure(UFS,sector 4096,payload 1MB)
- getstorageinfo / 支持功能枚举
- GPT 解析(LUN0-4,分区布局与固件一致)
- 读分区(devinfo 魔数 `ANDROID-BOOT!` 读出无误)
- boot 处理:真实 boot_b.img(v2/gzip/含 dtb)info→unpack→cpio→repack 全通,**往返一致性验证通过**(repack 后重解包 kernel/ramdisk/dtb 的 SHA1 与原始完全一致)

> 写/擦除路径与读共用同一套 xmlsend/configure 管线,但**未在真机做破坏性实测**。刷写有风险,务必先备份。

## 与 bkerler/edl 的差异

- 只做常用子集:**不含** NAND/streaming/diag、各家 OEM 认证模块(小米 EDL auth、OnePlus 等)、Windows 驱动、xml 多镜像 Sahara config。需要这些时仍用原版。
- 协议实现对齐 bkerler/edl(GPLv3)。本项目同为 GPLv3。

## boot 模块与 magiskboot 的差异

- 对齐 magiskboot 的 unpack/repack/cpio 核心(功能参考其 Rust 实现,GPLv3)。
- **不含**:Magisk 注入本体(magiskinit/magisk so/stub)、dm-verity/forceencrypt 的 `cpio patch`、dtb 编辑、hexpatch、从 OTA `payload.bin` 提取、AVB 签名。
- 适合「解包改 ramdisk 再打包」这类操作;真要注入 Magisk 本体仍需 Magisk app 的 `boot_patch.sh` 资源。
