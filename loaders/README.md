# loaders

qedl 运行必须的 firehose loader(devprg）。这些是第三方签名固件,随仓库备份,免得 Downloads 被清后找不到。

骁龙 665 = SM6125(Nicobar),UFS。小猿学练机 S2 真机验证用的是 `devprg_665_mi_noauth`。

| 文件 | 来源 | sha256 | 真机 S2 |
|---|---|---|---|
| `devprg_665_mi_noauth` | 高通工具箱 `.../qctool/mi_noauth/devprg_665`(小米免授权版) | `da57956e3f67c46a2600eae2b152f84b0458db35f42db75432dc81eabe47dc3d` | ✅ 签名通过,功能全 |
| `devprg_665_oppo` | 高通工具箱 `.../qctool/oppo/devprg_665` | `31bbdfbd6566dc828e66daacf3fa49949229cfda8fbcb08d7be58fc79781fe43` | 备选,未实测 |

用法:

```sh
qedl -l loaders/devprg_665_mi_noauth --memory ufs printgpt
```

换别的芯片要换对应 devprg(原高通工具箱里还有 439/625/632/636/660/675/680/710/712/730/778g/845/855/865/888 等)。

## 版权声明

这些 firehose loader(`devprg_*`)是高通/厂商(小米、OPPO 等)的签名固件,**版权归原厂所有**,并非本项目作者创作。它们在刷机社区已广泛流传(来自公开的"高通工具箱"),此处仅为方便使用而收录,不含任何修改。若相关权利人认为不妥,请提 issue,将立即移除。

