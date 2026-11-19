# Photon 的 BIRD 补丁包

同一份 [Babel 补丁](../../patches/bird2-babel-hysteresis.patch) 支持以下 BIRD 2 版本。

| 环境 | BIRD 版本 | 软件包 |
| --- | --- | --- |
| NixOS 26.05 当前锁定依赖 | 2.19.3 | `bird2-photon` |
| Photon flake 当前锁定依赖 | 2.20.0 | `bird2-photon` |
| Ubuntu 24.04 LTS（Noble） | 2.14 | `bird2-photon-ubuntu-24.04-<arch>.deb` |
| Ubuntu 26.04 LTS（Resolute） | 2.18 | `bird2-photon-ubuntu-26.04-<arch>.deb` |

## NixOS

当 `inputs.photon.inputs.nixpkgs.follows = "nixpkgs"` 时，下面的设置使用系统配置
锁定的 `pkgs.bird2` 及其原有构建选项，仅为 Photon 服务选择补丁包。

```nix
services.photon.birdPackage =
  inputs.photon.packages.${pkgs.stdenv.hostPlatform.system}.bird2-photon;
```

如果主机显式设置了 `services.photon.runtimePackages`，在列表中用同一个包替换
`pkgs.bird2`。独立运行的 `services.bird` 仍由 `services.bird.package` 管理。

## Ubuntu

[软件包流水线](../../.github/workflows/bird-ubuntu.yml) 为两版 Ubuntu 分别构建
`amd64` 和 `arm64` `.deb`。发布流水线将安装包、对应源码及 SHA256 校验文件附在
Photon Release 中。选择匹配系统版本和架构的文件，再用 APT 安装。

```sh
sha256sum -c ./bird2-photon-ubuntu-24.04-amd64.sha256
sudo apt install ./bird2-photon-ubuntu-24.04-amd64.deb
bird --version
```

补丁包沿用 Ubuntu 的 `bird2` 包名、配置路径和维护脚本。升级时，包管理器
可能重启独立的 `bird.service`。Ubuntu 发布更新的 `bird2` 后，APT 可能选用
更新的原版包。同一系统上保留新版补丁时，应基于更新后的 Ubuntu 源码重建。

在对应的 Ubuntu 版本上启用 `bird2` 所在的 `deb-src` 源，然后可本地构建。

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends build-essential fakeroot
sudo apt-get build-dep -y --arch-only --no-install-recommends bird2
bash contrib/packaging/build-bird2-ubuntu.sh ./dist
```

## 启用配置

补丁版默认使用 `etx loss scale 128` 和 `hysteresis margin 24`。需要覆盖时，
在对应的 `routing.instances[]` 设置 `etx_loss_scale` 或 `hysteresis_margin`。
原版 BIRD 继续使用省略这两个字段的配置。参数含义见 [配置说明](config.md)。

`managed` 模式默认会在 Photon 重启后接管原来的 BIRD 进程。换包时，在维护窗口
先停 Photon 服务，再用 `birdc -s <control_socket> down` 停掉各实例的原托管 BIRD，
最后启动 Photon。这样新进程才会加载补丁包。`external` 模式由外部服务管理器重启
对应的 BIRD 实例。
