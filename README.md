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

## 进 9008

关机 → 按住音量上+下 → 插线(黑屏正常)。PBL 若迟迟收不到 firehose 会超时自动重启,所以检测到后要立刻上传。

## 已验证(真机小猿学练机 S2 / 骁龙 665 Nicobar / UFS)

- Sahara 握手 + firehose 模式识别
- configure(UFS,sector 4096,payload 1MB)
- getstorageinfo / 支持功能枚举
- GPT 解析(LUN0-4,分区布局与固件一致)
- 读分区(devinfo 魔数 `ANDROID-BOOT!` 读出无误)

> 写/擦除路径与读共用同一套 xmlsend/configure 管线,但**未在真机做破坏性实测**。刷写有风险,务必先备份。

## 与 bkerler/edl 的差异

- 只做常用子集:**不含** NAND/streaming/diag、各家 OEM 认证模块(小米 EDL auth、OnePlus 等)、Windows 驱动、xml 多镜像 Sahara config。需要这些时仍用原版。
- 协议实现对齐 bkerler/edl(GPLv3)。本项目同为 GPLv3。
