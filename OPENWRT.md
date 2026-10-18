# Photon on OpenWrt / ImmortalWrt

目标：直接在 OpenWrt / ImmortalWrt 路由器上运行 Photon，复用 Linux 的 strongSwan、XFRM 和 BIRD 路径，省去额外虚拟机。两种固件共用打包和 procd 适配，覆盖 AMD/Intel x86-64、32 位 x86、ARM32 和 ARM64。

## 开发基线

- 建立日期：2026-10-18。
- 独立仓库：`/home/herbertqiao/Work/photon-openwrt`。
- 开发分支：`openwrt/initial-port`。
- 基线：`v0.6.0-rc.13`，提交 `3faf3a96dcfb86bd90acd7321fb667e9df1781a1`。
- 保留上游 Git 历史；本副本有独立的 `.git`，没有共享对象库依赖。
- 来自已提交源码的克隆，没有复制原目录中的运行数据库、私钥、抓包或构建产物。

已开始实现：`contrib/openwrt/` 提供静态交叉编译脚本、SDK 本地源码包定义、procd 服务、UCI 启动设置、YAML 示例和只读设备检查。尚未完成真实 SDK 打包、固件运行或实机接入，不构成所有型号/版本的兼容承诺。

## 产品组织：安装包、LuCI 与系统服务

适配的交付目标是能安装、配置、启动、诊断和接入 LAN 的路由器软件。当前编译成功只完成其中一个环节。包结构收敛为两个包：

| 包 | 负责内容 | 架构 |
| --- | --- | --- |
| `photon` | 主程序、依赖声明、YAML 示例、UCI 服务设置、procd 启动、设备检查 | 使用目标 SDK 的 CPU/ABI 包架构 |
| `luci-app-photon`（待实现） | LuCI 页面、菜单、rpcd 接口及 ACL；依赖 `photon` 与所需 LuCI/rpcd 组件 | 页面和脚本部分为 `all` |

无 Web 管理需求时直接安装 `photon`；需要面板时安装 `luci-app-photon`，由包管理器解析主程序与运行依赖。依赖来自匹配固件的软件源，不把其他系统的 BIRD/charon/ip 二进制塞入程序，也不在首次启动时临时下载安装依赖。

### 依赖各自解决的问题

| 组件 | 用途与归属 |
| --- | --- |
| Go、编译器、SDK | 构建机工具，路由器运行时不需要 |
| `ip-full` | 提供完整 iproute2 的 link/route/rule/netns/XFRM 与 JSON 查询；不能仅检查命令名 `ip` 是否存在 |
| `bird2` | 提供 BIRD 可执行文件；Photon 生成配置并管理自己的 Babel 实例 |
| charon、VICI、所选 strongSwan 插件 | 系统 swanctl 服务提供 IKE 与内核 IPsec 管理，Photon 通过 VICI 提交连接 |
| XFRM/veth/crypto 内核模块 | 内核的数据面能力，必须与设备当前内核 ABI 匹配 |
| `nftables-json` 与 firewall4 | nft 提供命令接口；firewall4 继续管理主机/LAN/WAN 规则，Photon 管自己的表与 namespace 策略 |
| `iputils-ping` | 当前健康探测 raw socket 不可用时的后备实现，使用分数秒 `-i`/`-W`、IPv6 和源地址参数，不默认依赖 BusyBox 兼容这些行为 |

主包已声明上述运行依赖；加密插件仍须用实际密钥装载、握手与重协商验证。`iputils-ping` 已补入依赖，procd 显式设置 PATH，优先从 `/usr/bin` 选择 iputils，保留 `/sbin` 中的 ip-full alternatives。选了包并不代表被固件裁掉的 `CONFIG_NET_NS` 自动恢复。

### 进程管理只有明确的负责人

```text
LuCI 页面 --ubus/rpcd--> Photon 专用管理接口
                              |
                   /etc/init.d/photon（procd）
                              |
                         photon daemon
                           |       |
                         VICI    BIRD 子进程
                           |
                         charon
                           ^
                   系统 swanctl 服务（procd）
```

LuCI 只请求服务操作；procd 管一个前台 `photon daemon` 的启动、停止、重启与日志。charon 继续由固件原有 swanctl 服务管理，Photon 不另起 charon。Photon 管理自己生成配置的 BIRD 实例，安装 `bird2` 是获得程序，不表示要启动系统 `/etc/init.d/bird`。无需引入 systemd、额外常驻管理守护进程或第二套循环保活脚本。

`START=95` 仅决定开机调用顺序，不代表 charon/VICI 或 WAN 已就绪。源码中的 `NewReconnectingGoviciClient` 首次构造会立即连接 VICI，失败会使数据面初始化退出；后续断线重连与首次依赖缺失是两件事。当前脚本只有 procd 有限次重启，不能宣称已覆盖长时间延迟就绪。下一步必须验证并实现首次就绪等待/重试、charon 重启和网络变化后的恢复，同时避免重启共享 swanctl 影响其他 VPN。

### LuCI 首版的交互与配置归属

采用现代 LuCI JavaScript 页面配合 rpcd/ubus，参照官方示例的菜单和 ACL 结构；没有为了面板专门引入 Lua 的必要。首版页面计划如下，当前尚未实现：

1. **概览**：分别显示进程运行、VICI、IKE/CHILD、Babel 邻居和路由状态。进程运行不显示为网络已连通。
2. **服务与配置**：开关、开机启动、启停/重启、配置导入与校验。先提供完整 YAML 的受控编辑；后续表单写入同一 YAML，不同时维护另一份完整 UCI 协议配置。
3. **节点与链路**：复用现有 control socket 的 canonical inspect DTO，展示 peer、链路、最后失败及同步情况；补窄的结构化查询入口，不抓取人读文本，也不直读 bbolt。
4. **诊断**：包/工具/内核能力、配置错误、VICI 可用性、近期服务日志与只读检查结果。只读检查不被标注为真实流量验收。
5. **LAN 接入**：选择已有 LAN 区域、需要接入的前缀，展示将创建的命名接口/forwarding 规则和撤回方式；独立验收后再实现自动应用。

配置归属保持一处负责：`/etc/config/photon` 管服务开关和 YAML 路径；YAML 管本机协议意图；bbolt 管身份及已验证网络事实；`/etc/config/network`、`/etc/config/firewall` 管 netifd/firewall4 的主机网络意图；`/run/photon` 放生成文件和 socket。签名记录、委派和路由授权仍走 Photon 原有命令与验证流程，LuCI 配置项不能替代它们。

面板需要的 RPC 限于 Photon 状态、配置校验/应用和本服务启停。使用 LuCI 登录与方法级 ACL，避免授予任意 shell、任意路径文件访问或整个系统服务的写权限。状态复用本地 control socket 和 inspect 模型；面板本身不要求额外开放 Photon Observer 的 HTTP 监听端口。配置应用须先用实际解析器校验，再原子替换配置；失败不覆盖运行配置。相关 RPC、校验命令与 LuCI 包目前均是待实现项。

### 接下来的实现顺序

先用一个匹配版本的 x86/64 SDK 证明主包依赖能安装且 procd 生命周期正常，补齐 VICI 首次就绪与恢复；然后实现 LuCI 的服务/概览/诊断与配置校验闭环；再接入 netifd/firewall4 的 LAN 流量并验证 reload、重启和撤回；最后在 x86、ARM32、ARM64 分别跑对应 SDK 构建与设备验收。所有架构共用服务与 LuCI 代码，每种内核/固件包仍须分别构建和验证。

## 当前使用方法

### 1. 构建各架构主程序

开发主机需要 Go 1.25 以上。Photon 以及当前 `x/crypto`、`x/sys` 都要求这个最低版本；旧版 SDK 的 Go host 工具也需要达到该要求，不降级协议依赖来迁就旧工具链。

```sh
contrib/openwrt/build.sh
# 也可以只构建一部分；可选 mips/mipsle 使用 softfloat。
contrib/openwrt/build.sh amd64 386 armv7 arm64
```

默认输出至 `build/openwrt/`，每个二进制附带独立 `.sha256` 文件，`SHA256SUMS` 汇总本次构建目标；通过 `PHOTON_BUILD_DIR` 可更改位置。`GO`、`GOCACHE`、`GOMODCACHE` 可以显式指定。当前开发机可用独立缓存：

```sh
GOCACHE=/tmp/photon-openwrt-gocache \
GOMODCACHE=/tmp/photon-openwrt-gomodcache contrib/openwrt/build.sh
```

| 构建目标 | 设备类型 | CPU/浮点基线 |
| --- | --- | --- |
| `amd64` | AMD/Intel 64 位软路由，OpenWrt x86/64 | GOAMD64=v1，不要求 AVX |
| `386` | 32 位 x86 路由器 | GO386=softfloat，不要求 SSE2 浮点 |
| `armv5` | ARMv5 及以上 32 位设备 | GOARM=5,softfloat |
| `armv6` | ARMv6 及以上 32 位设备 | GOARM=6,softfloat |
| `armv7` | ARMv7 32 位路由器 | GOARM=7,softfloat |
| `arm64` | ARMv8 AArch64 路由器 | GOARM64=v8.0 |

构建目标不是 opkg/apk 包的架构名。ARM 的 `arm_cortex-a7`、`arm_cortex-a9`、`aarch64_cortex-a53` 等包架构以及 x86 包架构必须由相应版本/目标的 SDK 决定；不能把一个 SDK 生成的安装包重命名后用于其他架构。纯 Go 静态二进制不依赖固件 libc 的浮点 ABI，但仍受 CPU 指令、Go 支持的内核和固件能力限制。

### 2. 只读检查设备

将 `contrib/openwrt/preflight.sh` 复制到测试设备后运行 `sh preflight.sh`。脚本打印固件、架构、内存/存储、ip JSON、netns API、BIRD 版本、VICI 和 nft 可见性；不会加载模块、创建接口/namespace、启动服务或修改路由/防火墙。自定义 VICI 路径用 `PHOTON_VICI_SOCKET` 指定。

脚本检查失败返回非零。全部只读检查通过仍不能证明 namespace 创建/移动、XFRM if_id、实际算法、firewall4 放行和端到端业务成功。开发机的结果也不计入设备验收。

### 3. 在匹配的 SDK 中打包

以下是待真实 SDK 验证的开发入口。使用目标 OpenWrt / ImmortalWrt 版本及架构对应的 SDK，启用 packages feed，确保其 Go host 版本至少 1.25。`PHOTON_SOURCE_DIR` 指向本分支的绝对路径。

```sh
# 在 SDK 目录执行；PHOTON_SOURCE_DIR 由你填入实际源码目录。
cp -R /path/to/photon/contrib/openwrt package/photon
./scripts/feeds update packages
./scripts/feeds install -a -p packages
make menuconfig  # Network -> VPN -> photon，选为模块 M
make package/photon/compile V=s PHOTON_SOURCE_DIR=/path/to/photon
```

修改本地源码后先执行 `make package/photon/clean PHOTON_SOURCE_DIR=/path/to/photon` 再编译，以刷新 SDK 的 prepare 缓存。包只复制源码目录与 Go 清单，不复制工作区的 `.git`、设备身份、运行数据库和构建目录。包格式由目标 SDK 决定（ipk 或 apk），不得混用不同固件版本的 kmod。

依赖选择 `ip-full`、`iputils-ping`、`nftables-json`、BIRD、XFRM/veth、AES-GCM/HMAC/SHA256 内核模块和 charon/VICI。strongSwan 选 OpenSSL crypto、raw public key、PEM/PKCS8/X509 解码和 RNG，作为当前 Ed25519/P-256、AES-CBC/HMAC-SHA256 与 ESP AES-GCM 的候选组合；实际加载、VICI 装载密钥、协商与重协商仍待实测。不是安装 `strongswan-full`。固件内核还必须开启 `CONFIG_NAMESPACES`、`CONFIG_NET_NS`，包依赖不能补回裁掉的内核功能。

### 4. procd 与配置

包默认 `enabled=0`，只提供 `/etc/photon/config.yaml.example`。先复制为 `/etc/photon/config.yaml`，填入已有身份、可信根与 bootstrap，再依照原有 Photon 流程接入；没有自动新建根或授予网络权限。UCI 只管理启动开关和配置文件路径，协议配置继续由 YAML 单独负责。

持久数据库默认 `/etc/photon/photon.db`，支持通过 YAML 的 `data_dir`、`state_path` 迁移到 extroot。BIRD 示例明确使用 `/run/photon/bird/` 的临时配置/socket/PID，日志交给 procd/logd，不持续写 flash 日志。控制 socket 使用原 CLI 默认的 `/run/photon/photon.sock`。须在设备确认 `/run` 指向临时存储。BIRD 示例使用 `shutdown_policy: stop`，服务停止时一并停止该实例。

确认配置、依赖及测试网络边界后，在测试设备执行：

```sh
# charon 由固件原有 swanctl 服务管理；先检查 /etc/config/ipsec 的本机设置。
/etc/init.d/swanctl enable
/etc/init.d/swanctl start
uci set photon.main.enabled='1'
uci commit photon
/etc/init.d/photon enable
/etc/init.d/photon start
logread -e photon
photon status
```

procd 前台运行单个 Photon 实例，退出后按 5 秒间隔有限次重启，停止宽限 30 秒。服务启动顺序在 swanctl 之后，但首次 VICI 连接仍要求 charon 已就绪，长期延迟启动尚未适配；不另外启动 charon 或系统 BIRD。YAML 修改后执行 `/etc/init.d/photon reload`，UCI 修改可用 `reload_config` 通知 procd。首次依赖等待、WAN 切换、charon 重启后的实际恢复仍须实现并完成设备验收。

### 5. firewall4 与 LAN 接入

本轮不自动改写 firewall4。Photon namespace 内的转发、防火墙与主路由器的 `inet fw4` 是不同处理环节。先在目标设备规划：

- 主机 input 对 Gossip UDP 33434 和当前宣告的 IKE/NAT-T 端口放行，限制来源/入口范围。
- 若需要 LAN 进入 mesh，启用 routing upstream veth，并在 firewall4 中声明相应接口及明确的 LAN/mesh 双向 forwarding 和允许前缀。
- 初次验证固定端口。轮换端口需另验 host DNAT/SNAT 与 fw4 的优先级/规则，不直接开放整个端口区间。
- 实际执行 firewall reload、WAN 变化和重启后检查 IPv4/IPv6 流量；独立 nft 表中的 accept 不能证明 fw4 放行。

仅有隧道握手不表示路由器上的应用或 LAN 已接入 mesh。路由发布、IPAM 与授权仍遵循原有流程。

## 初步判断

从代码依赖和 OpenWrt 官方软件包定义判断，直接运行有可行性。Photon 已采用 `CGO_ENABLED=0` 构建，主程序可以避免依赖目标机的 glibc；这不等于目标固件具有完整的网络功能，也不代表低内存设备的资源占用已经合格。

Linux 平台组装入口在 `internal/photonlinux/`，无需另写一套 IKE 或 Gossip 协议。优先复用这些实现，通过打包、启动脚本和配置解决平台差异。

## 需要核实和适配的部分

| 部分 | 现有实现和 OpenWrt 条件 | 后续工作 |
| --- | --- | --- |
| 服务管理 | 当前通用安装脚本提供 systemd 单元；OpenWrt 使用 procd | 增加原生启动脚本，处理依赖就绪、重启、退出和日志 |
| strongSwan | Photon 直接连接现有 charon 的 VICI socket；官方包拆分了 charon、VICI 和加密插件 | 按目标固件确认插件、socket 路径、公钥装载和握手算法；charon 继续由系统服务管理 |
| 内核 IPsec | 使用 route-based XFRM interface 和 `if_id` | 核实 `kmod-xfrm-interface`、IPv4/IPv6 IPsec 和协商算法对应的内核支持 |
| 网络命名空间 | 现有 Linux 驱动会创建 namespace，并移动 XFRM/veth 接口 | 检查固件的 `CONFIG_NAMESPACES`、`CONFIG_NET_NS`、veth 和 mount/setns 能力；不能仅看包名 |
| 命令工具 | 使用 `ip -j`、`ip netns exec`、sysctl、nft，健康探测另有 ping 后备路径 | 以 `ip-full` 为候选，逐条验证实际命令；检查 BusyBox 的参数兼容性 |
| BIRD | Photon 管理自己的 BIRD 进程、配置及控制 socket；OpenWrt 有 `bird2` 包并支持 Babel | 验证生成配置可解析，区分系统已有的 BIRD 实例及 Photon 实例 |
| 防火墙 | Photon 使用自有 nft 表；路由器还可能由 firewall4 管理转发和 NAT | 检查各链实际处理结果、reload、端口轮换与 NAT；独立表里的 accept 不能保证别的链放行 |
| 存储 | Photon 使用持久化 bbolt 状态，另有运行时 socket、密钥材料和 BIRD 文件 | 根据 overlay/extroot 布局选择路径；先确认 `/var`、`/run` 是否临时存储，不能直接套用服务器路径 |
| 资源 | 服务器上的 CPU 数据不能代表路由器 | 记录固件空闲内存、程序大小、RSS、写入量、吞吐、重协商和长时间稳定性 |

不要直接安装所有 strongSwan 插件来掩盖依赖缺口。应从实际身份密钥、IKE/ESP 协商结果和 VICI 操作推导包集合，并在目标发行版上验证。

## 首轮验证顺序

1. 确认路由器型号、CPU 架构、OpenWrt 版本、内核版本及可用 RAM/存储。
2. 在宿主机交叉编译主程序，检查 ELF 架构及动态链接依赖。
3. 在测试设备检查命名空间、XFRM、veth、工具和 VICI，先不接入生产路由。
4. 增加 procd 与打包适配，用独立配置、身份和测试数据目录启动。
5. 验证握手、CHILD_SA、Babel 邻居以及 IPv4/IPv6 真实流量。
6. 验证路由器重启、WAN 地址变化、firewall reload、charon 重启和端口轮换。
7. 长时间测量 CPU、内存、存储写入和数据平面表现，再决定适用的设备范围。

已有 `docs/scripts/ipsec-xfrm-preflight.sh` 可作为功能清单参考，但它依赖 bash，并会临时创建接口和 namespace，不能当作只读设备检查脚本直接使用。

## 交叉编译复现

2026-10-18 首轮使用 Go 1.26.5 对 RC.13 源码完成以下构建（初次研究记录）：

| 目标 | 结果 | 主程序大小（约） |
| --- | --- | --- |
| Linux amd64 | 通过，静态链接 ELF | 15 MiB |
| Linux arm64 | 通过，静态链接 ELF | 14 MiB |
| Linux mipsle，softfloat | 通过，静态链接 ELF | 16 MiB |

产物和 SHA256 存放在本副本忽略的 `build/openwrt/` 下。尚未执行 ARM/MIPS 二进制，也没有在 OpenWrt 设备启动服务。

首次使用旧 `/tmp/photon-gomodcache` 的 ARM64/MIPS 构建因缓存仅有 amd64 平台文件而失败。改用独立完整缓存 `/tmp/photon-openwrt-gomodcache` 后三种目标全部通过，没有修改源码或依赖版本。

在开发机运行，`ARCH` 可取 `amd64`、`arm64` 或 `mipsle`；MIPS 的浮点 ABI 需要匹配设备，本轮以 `softfloat` 作编译探测。

```sh
ARCH=arm64
CGO_ENABLED=0 GOOS=linux GOARCH="$ARCH" GOMIPS=softfloat \
  go build -trimpath -ldflags='-s -w' \
  -o "build/openwrt/photon-linux-$ARCH" ./app/photon
```

编译成功仅代表该目标的主程序可构建。ARM、MIPS 的其他大小端/浮点组合和目标固件运行情况需要分别验证。

本轮已使用 `contrib/openwrt/build.sh` 完成默认六种架构构建，逐个检查 ELF：均没有动态解释器或共享库 `NEEDED` 项。产物约 13–15 MiB（未压缩）。x86-64 和 x86 的 `version` 已在当前 Linux 开发机运行；x86 softfloat 的 `pkg/core/state`、`pkg/core/host`、`pkg/health` 测试通过。首次沙箱运行 32 位程序被系统调用过滤拦截，放行后运行通过，不能将这个沙箱现象当作固件故障。

`contrib/openwrt/check.sh` 已验证脚本语法、默认禁用、缺少/相对配置路径拒绝、带空格配置路径传递、单实例注册、重启参数和 reload trigger；这里使用 stub procd，不是设备服务验收。真实 Linux 配置解析测试 `TestOpenWrtConfigExample` 覆盖初始示例及取消注释后的数据面配置，确认数据库保持持久化、BIRD 使用临时路径。

仍未验证：真实 SDK 生成 ipk/apk、ARM 执行、固件开机启动、实际公钥装载及 IKE/ESP/Babel/业务流量、firewall4 reload、内存和 flash 占用。尚未推送、发布或部署到设备。

## 参考来源

2026-10-18 查询的官方源码；以下 master 链接会变化，最终包清单须按目标 OpenWrt 版本重新核实。

- [OpenWrt strongSwan 包与插件定义](https://github.com/openwrt/packages/blob/master/net/strongswan/Makefile)
- [OpenWrt strongSwan swanctl/procd 启动实现](https://github.com/openwrt/packages/blob/master/net/strongswan/files/swanctl.init)
- [OpenWrt iproute2 的 ip-full/ip-tiny 定义](https://github.com/openwrt/openwrt/blob/master/package/network/utils/iproute2/Makefile)
- [OpenWrt 内核 XFRM/veth 包定义](https://github.com/openwrt/openwrt/blob/master/package/kernel/linux/modules/netsupport.mk)
- [OpenWrt BIRD 2 包定义](https://github.com/openwrt/packages/blob/master/net/bird2/Makefile)
- [ImmortalWrt strongSwan 包与插件定义](https://github.com/immortalwrt/packages/blob/master/net/strongswan/Makefile)
- [ImmortalWrt 内核模块定义](https://github.com/immortalwrt/immortalwrt/blob/master/package/kernel/linux/modules/netsupport.mk)
- [OpenWrt Go 包构建接口](https://github.com/openwrt/packages/blob/master/lang/golang/golang-package.mk)
- [OpenWrt Go 架构映射](https://github.com/openwrt/packages/blob/master/lang/golang/golang-values.mk)
- [OpenWrt procd 脚本接口](https://github.com/openwrt/openwrt/blob/master/package/system/procd/files/procd.sh)
- [LuCI 官方 JavaScript 应用示例](https://github.com/openwrt/luci/blob/master/applications/luci-app-example/README.md)
- [LuCI 应用目录结构](https://github.com/openwrt/luci/blob/master/applications/luci-app-example/structure.md)
- [OpenWrt iputils-ping 包定义](https://github.com/openwrt/packages/blob/master/net/iputils/Makefile)
