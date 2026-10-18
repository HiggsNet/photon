# Photon on OpenWrt / ImmortalWrt

在 OpenWrt / ImmortalWrt 上运行 Photon，复用 Linux 的 strongSwan/VICI、XFRM 与 BIRD，并通过原生 procd 和 LuCI 管理。当前已验证 x86/64 测试虚拟机上的管理闭环、真实 charon 依赖恢复，以及隔离 Babel/IPsec 联合双栈流量；ARM 仍处于交叉编译阶段，真实 WAN/LAN 接入尚未验收。

## 当前状态（2026-10-18）

开发分支为 `openwrt/initial-port`，上游基线为 `v0.6.0-rc.13`（`3faf3a96dcfb86bd90acd7321fb667e9df1781a1`）。初步移植已本地提交为 `ea917baf`；本轮继续完成 LuCI、RPC、依赖、恢复与双栈适配，整理为本地提交；未推送，也未发布版本。

| 层次 | 已验证事实 | 边界 |
| --- | --- | --- |
| 主程序 | 最新源码完成 amd64、386、ARMv5/v6/v7、ARM64 六种静态构建，无动态解释器或共享库依赖 | ARM 未在目标设备执行；不能推广到全部 CPU、固件和内核 |
| SDK 包 | 匹配 ImmortalWrt 25.12.1 x86/64 SDK 构建并安装 Photon、LuCI 与 13 个 strongSwan APK；应用 r1→r2 活动升级及二进制内容触发重启通过 | 只验证该固件/架构；未生成其他目标 SDK 的安装包 |
| procd | 启停、重生、数据库恢复，以及原生 daemon 在真实 charon 缺失、启动、停止、重启后的 reconcile/watcher 自动恢复通过，daemon PID 保持不变 | 依赖恢复使用空 SA；有活动 SA 时的业务重建、整机重启及 WAN 恢复未验收 |
| LuCI/rpcd | 六方法注册、HTTP ACL、真实表单登录、状态/节点/链路、诊断、配置校验保存与冲突处理通过 | 首轮编辑测试使用临时注入会话；随后另用真实临时账号验证登录及已安装 ACL 的角色映射 |
| XFRM/BIRD | 原六项测试，以及生产 BIRD 配置经真实 IPsec 学习双方 IPv4/IPv6 前缀、双向业务地址 ping、SA/接口计数、BIRD 撤路和恢复通过 | IPv4 underlay 上的隔离对等端；不是生产 WAN/LAN 或持续负载验收 |
| charon/IKE | strongSwan 6.0.3：VICI wrapper 恢复、P256 IPv6 双向 tunnel ping、Ed25519 canonical 双栈双向 ping 及双方 CHILD/IKE rekey 均通过；共享 TS 修复后重新回归通过 | IKE/ESP 底层为 IPv4；未验证 IPv6 underlay、实际 WAN/NAT 变化或有活动 SA 的 daemon 恢复 |
| LAN/业务 | 尚未验收 | netifd/firewall4 自动接入尚未实现 |

测试设备为 `root@10.16.255.80`：QEMU、ImmortalWrt 25.12.1、`x86_64`、Linux 6.12.94。先手工暂存源码构建产物完成管理验收，再使用 `apk add` 安装实际 SDK 产物，复核原有配置保留、rpcd 自动注册和原生二进制启动。首轮 r1 ELF SHA256 为 `3da383a91e4e3dce22bd90f7bc9470e94b3f02df4321c7e2628f610a4c376b72`；完成双栈修复与实际升级后，当前 r2 为 `fda077279dfec8a863822973dd111f63364b477e139bd3cb9ed2d17c0611061f`，与 r2 SDK 包内成品一致。首轮管理验收身份为 `router.acceptance.invalid.`，监听 `127.0.0.1:43434`，bootstrap 仅为 `127.0.0.1:43435`，数据库位于独立临时目录；节点真实处于 `auto-join / syncing_parent`，没有签发生产委派或接入生产路由。

本地证据保存在被 Git 忽略的 `build/openwrt/device-acceptance/`，总览为 `final-summary.json`；远端临时目录为 `/tmp/photon-acceptance.eEmOlk`。它们是本次验收产物，不随源码提交发布。

后续应用依赖恢复证据位于 `build/openwrt/device-acceptance-next/native-recovery/`；联合协议验收与修复前后日志位于 `build/openwrt/device-acceptance-next/`，汇总为 `joint-summary.json`，远端为 `/tmp/photon-joint.CNcbFc`。r1→r2 升级及单独更换二进制的验证位于 `build/openwrt/device-acceptance-next/upgrade-r2/`，远端为 `/tmp/photon-upgrade.GGkPbJ`。

验收后保留原生软件安装，Photon、这次新增的系统 BIRD/swanctl 均停止并禁用。已删除本次临时身份、数据库和 `/etc/photon/config.yaml`，面板重新显示安装包示例；未配置生产身份。构建容器已停止，SDK 和日志保留供复查。

## 包、依赖与进程归属

| 包 | 内容 | 架构 |
| --- | --- | --- |
| `photon` | 主程序、运行依赖、procd、UCI 服务设置、YAML 示例、只读 preflight 和 rpcd 启动入口 | 目标 SDK 的 CPU/ABI 包架构 |
| `luci-app-photon` | JavaScript 页面、菜单和方法级 ACL；依赖 `luci-base` 与 `photon` | `all` |

不需要 Web 管理时只安装 `photon`。需要面板时安装 `luci-app-photon`，由匹配固件的软件源解析依赖。Go、编译器和 SDK 只用于构建机；运行时不另装工具链，也不捆绑其他发行版的网络工具。

| 运行依赖 | 用途 |
| --- | --- |
| `ip-full` | 完整 iproute2、JSON 查询、link/route/rule/netns/XFRM |
| `iputils-ping` | raw socket 健康探测的后备实现，所用参数不默认依赖 BusyBox 兼容 |
| `bird2`、`bird2c` | BIRD/Babel 实例及 `birdc` 控制工具；Photon 停止实例会使用 `birdc ... down` |
| `strongswan`、charon、swanctl 和所选插件 | 系统 IKE/VICI 服务及密钥、算法支持 |
| XFRM、veth、GCM/HMAC/SHA256 内核模块 | 内核接口及加密能力，必须匹配当前内核 ABI |
| `nftables-json` | Photon 自有表与 namespace 内策略；主机 LAN/WAN 规则仍归 firewall4 |

真实 SDK 检查发现并修正：APK 包版本使用 `0.6.0_rc13`，程序仍标识上游 RC.13；主包直接依赖 `strongswan` 基包与 `bird2c`。该 strongSwan 包的 nonce 模块由基包提供。最终协议验收使用 13 个匹配 SDK 的 strongSwan 包：`strongswan`、`strongswan-charon`、`strongswan-swanctl`，以及 `strongswan-mod-{kernel-netlink,socket-default,openssl,pubkey,pem,pkcs1,pkcs8,x509,random,vici}`；VICI 由 swanctl 的传递依赖带入。这个 OpenSSL 组合已通过下文的实际密钥装载、IKE/ESP 和重协商测试。

首次 12 包组合的 `load-key` 成功，但 `load-conn` 返回 `parsing request failed`，这次失败不计为通过。原因是 raw 公钥证书构造请求 `KEY_ANY`，需要 PKCS1 插件解析 SubjectPublicKeyInfo（SPKI）的算法 OID，再转交 OpenSSL 的 ECDSA/Ed25519 provider。该插件并不表示改用 RSA 身份。补入 `strongswan-mod-pkcs1` 及主包依赖后，按原生产消息和算法提案重新通过首轮 IKE 验收；该次插件修复无需更改 Go 消息。后续联合流量测试另发现并修复了双栈 BIRD static 配置与 CHILD payload 选择器问题，见下文。

进程负责人保持唯一：LuCI 经 `ubus/rpcd` 调用 Photon 专用接口；procd 管前台 `photon daemon`；固件原有 swanctl 服务管 charon；Photon 经 VICI 使用 charon，并管理自己的 BIRD 子进程。不新增 systemd、第二个常驻管理服务或独立保活循环。

`bird2` 的包安装脚本可能自动启用系统 `/etc/init.d/bird`。本次设备原先没有 BIRD，安装后只停止并禁用了本次新增的空配置系统实例，主机路由未变。已有设备必须先识别系统 BIRD 的使用者和配置，不能照抄无条件停用既有 BIRD 的命令。

`START=95` 只决定开机调用顺序。首次 VICI socket 缺失或拒绝连接时，客户端保留重试能力，允许 Photon 控制接口先启动；既有 watcher 从 1 秒起退避订阅、上限 1 分钟，IPsec reconcile 默认每分钟重试。权限拒绝或非法路径等永久错误仍使初始化失败，Photon 不重启共享 swanctl。独立 wrapper 与原生 procd 应用均已用真实 charon 验证延迟启动及重启恢复，后者还核对了事件重新订阅、canonical 错误清除及同一 daemon PID；该恢复测试为空 SA，不能推广为活动链路业务已自动重建。

## 面板与配置约定

LuCI 使用现代 JavaScript 页面，不为面板另引入 Lua。服务菜单下提供四部分：

1. **概览与服务**：进程/PID、开关、控制接口、canonical 接入模式/阶段/原因、节点与链路计数及最近错误；启用、禁用、启动、停止、重启和刷新。
2. **节点与链路**：节点选用地址、同步时间、拉取状态和错误；链路接口、地址、状态、CHILD 名称、BIRD 状态及错误。离线或读取失败时清空旧详情。
3. **配置**：YAML 读取、校验、保存和重新读取。保存不自动重启，保存/校验与服务写操作互斥，状态轮询不覆盖编辑内容。
4. **诊断**：工具、可见内核能力、VICI 查询、只读 preflight 和近期日志，执行时间与输出大小受限。

进程运行、控制接口响应、链路运行与接入授权分别展示，均不能代替端到端业务验证。面板读取本地 control socket 的 `daemon_status_view`、`status_view`、`peers_view`、`links_view`，复用 canonical inspect DTO。`peers_view` 与 Observer 共享投影，原有 `gossip_peers_view` 调试 schema 保持不变；离线查询不会打开或初始化数据库。链路详情来自已有观测，不额外发起实时 VICI SA 查询；也不要求开放 Observer HTTP 端口。

`/usr/libexec/rpcd/luci.photon` 短时执行同一主程序的 `photon advanced openwrt-rpc`。接口只有六个方法：

| ACL | 方法 |
| --- | --- |
| read | `snapshot`、`get_config`、`diagnostics` |
| write | `validate_config`、`save_config`、`service` |

应用 ACL 不授任意 shell、客户端指定文件路径、通用 UCI 写入或其他服务管理权限。配置读取 UCI 指定的绝对 `.yaml`/`.yml` 路径，限制 128 KiB 和单个 YAML mapping 文档，使用实际 Linux 配置解析器校验。保存使用读取版本的 SHA256、文件锁、`0600` 同目录临时文件和原子替换；校验或版本冲突失败时不覆盖配置，编辑文本保留。校验通过只证明可解析，不能替代身份、权限及网络验证。

配置归属如下：

| 位置 | 负责人及用途 |
| --- | --- |
| `/etc/config/photon` | 服务开关和 YAML 路径 |
| YAML | 本机 Photon 协议配置 |
| bbolt 数据库 | 身份与已验证网络事实 |
| `/etc/config/network`、`/etc/config/firewall` | netifd/firewall4 的主机网络意图 |
| `/run/photon` | 临时 socket、BIRD 配置、PID 等运行文件 |

签名、委派、IPAM 与路由授权继续走 Photon 原有验证流程，面板配置不能替代授权。

## 构建与安装

### 静态主程序

需要 Go 1.25 以上；默认构建六种目标：

```sh
contrib/openwrt/build.sh
# 也可指定部分目标：
contrib/openwrt/build.sh amd64 386 armv7 arm64
```

| 目标 | CPU/浮点基线 |
| --- | --- |
| `amd64` | AMD/Intel x86-64，`GOAMD64=v1` |
| `386` | 32 位 x86，`GO386=softfloat` |
| `armv5`、`armv6`、`armv7` | 相应 `GOARM` 与 softfloat |
| `arm64` | ARMv8 AArch64，`GOARM64=v8.0` |

产物、每目标 SHA256 和本次调用的 `SHA256SUMS` 默认位于 `build/openwrt/`。可用 `PHOTON_BUILD_DIR`、`GO`、`GOCACHE`、`GOMODCACHE` 指定输出和工具缓存。脚本还接受可选 `mips/mipsle` softfloat 编译探测，不能据此宣称 MIPS 固件可用。

这些名字不是 opkg/apk 包架构。包的 CPU/ABI、内核和 libc 条件必须由相应 SDK 确定；不能重命名某架构或固件的包来适配其他目标。

### SDK 两个包

本次使用官方 ImmortalWrt 25.12.1 x86/64 SDK、固定的 base/packages/luci/routing feeds 和 SDK Go 1.26.4，已完成两包构建及设备安装。SDK 压缩包 SHA256 为 `02ad8cfc775001ccae8e9282d19696de54e3ab3963f005737ad61f8698263edd`。产物位于 `build/openwrt/sdk-immortalwrt-25.12.1-x86_64/`，目录内 `SHA256SUMS` 覆盖全部 15 个 APK，`PROVENANCE.md` 记录 SDK 来源、feed commits、隔离构建环境、日志和复现命令。未将 SDK 生成的额外 kmod 装入设备。

原 r1 产物继续保留；当前应用候选为该目录下 `r2/`，其 `SHA256SUMS`、`PROVENANCE.md` 和源码哈希清单单独记录这次构建。主包为 `photon-0.6.0_rc13-r2.apk`，LuCI 为 `luci-app-photon-0.6.0_rc13-r2.apk`，程序版本为 `openwrt-v0.6.0-rc.13-r2`。13 个 strongSwan 包保持原样，r2 主程序包含下述双栈修复。

该发行版公开源缺少 strongSwan，官方失败日志显示 wolfSSL 插件缺 `wolfssl/wolfcrypt/mlkem.h`；本次使用同版本源码，仅选择所需 OpenSSL 组合构建。其他固件仍应使用各自匹配的软件源与 SDK。通用入口如下，Go host 须至少 1.25：

```sh
# 在 SDK 中执行，源码路径换成实际值。
cp -R /path/to/photon/contrib/openwrt package/photon
cp -R /path/to/photon/contrib/luci-app-photon package/luci-app-photon
# 保留 SDK 自带的固定 feed revisions；本次 ImmortalWrt 的 BIRD 在 routing feed。
./scripts/feeds update -a
./scripts/feeds install -a
make menuconfig  # photon 和 luci-app-photon 选 M
make package/photon/compile V=s PHOTON_SOURCE_DIR=/path/to/photon
make package/luci-app-photon/compile V=s PHOTON_SOURCE_DIR=/path/to/photon
```

SDK 的 `package/` 是复制件；脚本、包规则和页面改动须同步后 clean/compile，主程序源码更新也须先 `make package/photon/clean` 以刷新 prepare。主包只复制源码目录和 Go 清单，不复制 `.git`、身份、密钥、运行数据库或构建目录。LuCI 使用 `$(TOPDIR)/feeds/luci/luci.mk`，架构为 `all`。

将实际生成的两个包复制到隔离测试设备后，按固件格式使用 `opkg install` 或 `apk add`；未签名的本地 APK 才使用 `--allow-untrusted`。依赖必须来自匹配软件源，尤其不能混用其他内核的 kmod。包依赖无法补回裁掉的 `CONFIG_NAMESPACES/CONFIG_NET_NS`。

本次 APK 候选需一起提供两个应用包和 13 个 strongSwan 包；将这 15 个包放到专用 `/tmp/photon-candidate/` 后执行 `apk add --allow-untrusted /tmp/photon-candidate/*.apk`，其余依赖由匹配源解析。同版本本地包重编译后，使用 `--force-reinstall` 并核对文件 SHA，确保 charon 的默认插件加载列表也更新。

安装后检查 `ubus -v list luci.photon` 和 LuCI“服务 → Photon”。本次 LuCI 包的标准安装脚本自动重载 rpcd，六方法直接注册成功；Photon 已有 UCI/YAML 配置被保留，新的默认 UCI 文件写为 `.apk-new`。其他固件新插件未注册时可重载 rpcd，再重新登录使 ACL 生效。标准包安装可能建立开机调用链接，但 UCI `enabled=0` 时不启动 daemon；面板分别显示和管理这两个开关。

### 配置与服务

包默认 `enabled=0`，仅提供 `/etc/photon/config.yaml.example`。在面板读取示例，填写已有身份、可信根和 bootstrap，校验保存后明确“启用服务及开机启动”，再“启动”；没有自动新建根或授予网络权限。运行中修改配置后须明确“重启”。

“启用”只开启 UCI 服务开关和开机启动，不自动启动；“禁用”关闭这两者，不停止当前进程。立即停止另点“停止”。禁用后启动/重启被拒绝，先启用才可启动。保存配置不重启，也不隐式调用 `reload_config`。

默认数据库为持久的 `/etc/photon/photon.db`，可经 YAML 的 `data_dir/state_path` 放到 extroot。示例 BIRD 文件与控制 socket 使用 `/run/photon`，日志交给 procd/logd，不持续写 flash 日志；须确认设备 `/run` 指向临时存储。BIRD `shutdown_policy: stop` 随服务停止关闭自有实例。

命令行使用 `/etc/init.d/photon`；先检查已有 swanctl 配置和 VICI，就绪责任仍属于系统 swanctl。手动编辑 YAML 可调用 Photon reload，UCI 改动可通过 `reload_config` 通知 procd，命令行编辑不经过面板的 SHA 冲突检查。procd 前台单实例运行，退出后按 5 秒间隔有限次重启，停止宽限 30 秒。将 YAML、UCI 和 `/usr/sbin/photon` 均列入 procd 文件哈希；包升级后 init 启动会检测程序内容变化并替换旧进程，相同内容的重复启动保留 PID。

## 已完成的真实设备验收

### LuCI、HTTP、ACL 与配置

`luci-readonly.json`、`luci-http-browser.json`、`luci-login.json` 和 `luci-cleanup.json` 记录了以下结果；浏览器直接访问设备，没有拦截或伪造响应：

- 六个 RPC 在真实 rpcd 注册；只读会话能读取三个方法，三个写方法被拒。读写会话均不能调用 `file.read/file.exec`、`uci.set` 或通用 `service.set`，无 Photon ACL 的会话被真实 LuCI dispatcher 拒绝。
- 最初 SSH 注入临时内存会话验证管理闭环；随后用两个命名临时 rpcd 登录项，分别仅授 Photon read 与 read+write，以及独立的最小主题只读权限。真实 `session.login` 与浏览器用户名/密码表单登录均通过，证明已安装 ACL 到登录角色的映射，页面控件权限正确且无浏览器异常。
- 真实 10 秒状态轮询保留未保存 YAML；非法 YAML 校验失败保留文本；注释级保存成功且 daemon PID 不变；并发恢复配置后，编辑器旧 SHA 保存被拒且不丢文本。最终配置原文和 SHA 恢复。
- 面板真实显示 pending 接入原因、回环 bootstrap 节点、空链路，以及缺失 swanctl/VICI 的诊断；没有把控制接口在线标成网络已通。
- 7 个测试会话全部销毁，只撤销本次命名 login section 的 UCI delta，删除临时主题 ACL；rpcd 持久文件和原 delta 校验恢复。未改 root 密码、既有登录权限，也未为测试账号重载 rpcd。凭据未写入报告或截图。

`luci-form-read-overview.png` 与 `luci-form-write-overview.png` 展示真实页面，配置编辑区截图遮蔽。Photon 自身 ACL 不包含主题框架的额外通用权限。

原生 APK 安装后又用两个临时账号完成真实表单登录复验：SDK 压缩后的 14201 字节 JavaScript 实际返回 HTTP 200，pending 展示与读写权限正确，非法 YAML 校验保留编辑内容，浏览器无异常。`native-apk-luci-browser.json` 与截图记录该轮结果；这两个会话及其临时账号/主题 ACL 也已清理，既有 rpcd 配置和 UCI delta 校验恢复。

### procd 生命周期

脚本为 `build/openwrt/device-lifecycle.sh`，设备日志为临时目录中的 `procd-lifecycle.log`。手工暂存阶段及 SDK 原生 APK 安装后均对隔离 daemon 验证：

- 启用只改 UCI/开机开关，不启动进程；重启替换 PID，始终只有一个 daemon。
- 禁用保留运行 PID，但拒绝新的启动/重启；停止清理控制 socket，canonical live 状态转离线。
- 停止后启用不自动启动；再次启动后仅杀死本次隔离 daemon，procd 约 5 秒重生，临时持久数据库恢复，控制接口重新在线。
- 最终停止并禁用：`running=false`、`enabled=false`、`boot_enabled=false`。

实际 SDK r1→r2 活动升级另外验证：`apk add` 后 daemon PID 从 `4894` 变为 `5053`，运行中 `/proc/PID/exe` 与已安装 r2 ELF SHA 一致；临时身份密钥、YAML、UCI SHA 和 bbolt inode 保留，启用与开机状态保持。单独固定 r2 init、参数和配置，仅原子替换 r1/r2 二进制内容，两次均触发进程替换且始终只有一个 daemon；相同内容再次启动保持 PID。测试后恢复 r2，删除临时身份与数据库，恢复原 UCI，服务停止并禁用。证据为 `device-acceptance-next/upgrade-r2/upgrade.log`；未测试禁用状态升级、卸载重装或跨固件升级。

另用 `build/openwrt/device-missing-vici.sh` 启用真实 strongSwan overlay，将 VICI 指向不存在的隔离 socket。应用仍为 `daemon_online=true`，控制接口可用；canonical `last_link_failure` 与 `Links.LastFailure` 报告 `ipsec_reconcile_failed` 和 ENOENT，日志记录 reconcile 与事件订阅失败。这是真实应用的首次依赖缺失验收，没有使用模拟 VICI 服务。测试后配置 SHA 恢复，服务停止并禁用，无新增 namespace 遗留。

随后用仓库脚本 `contrib/openwrt/tests/device-vici-recovery.sh` 对已安装原生 Photon 完成真实依赖恢复，证据位于 `build/openwrt/device-acceptance-next/native-recovery/`：

- procd 管理的 daemon 始终保持 PID `901`，控制接口一直在线；charon 最初缺失时报告 `ipsec_reconcile_failed`。
- 在独立 namespace 和私有挂载中启动真实 charon 后，reconcile 错误自动清除；charon 日志确认 `child-updown`、`ike-updown` 两个订阅稳定注册。
- 停止该测试 charon 后，错误再次可见；重启后错误自动清除，两种事件重新稳定订阅，Photon 未重启。
- 测试后 host namespace、接口、路由、mountinfo、忽略计数器的 nft 规则及原系统配置恢复；删除临时私钥、数据库和 YAML，服务停止并禁用。

本轮仅使用回环 pending 测试身份且 SA 为空，证明应用读取和订阅真实依赖的恢复，不证明活动 SA 或已有业务链路在 charon 重启后重建。实际 Babel/ESP 流量由下文的独立联合测试覆盖。

原生 APK 在空闲 pending、仅 Gossip 的这次 VM 单点观测 RSS 为 14016 KiB、7 个线程，不能当作低内存路由器、带加密流量或长时间负载的资源结论。`native-apk-preflight.log` 记录实际系统 charon 就绪时的检查：0 项失败、2 项能力/负载待测提醒；检查后新增的 swanctl 服务停止并禁用。

### 隔离 XFRM 与 BIRD/Babel

`isolated-smoke-summary.json` 与对应日志记录六项通过：

| 测试 | 验证内容 |
| --- | --- |
| `TestSystemXFRMDriverIntegrationSmoke` | namespace/XFRM 接口生命周期 |
| `TestExecProcessManagerRootSmoke` | Photon 管理的 BIRD 进程生命周期 |
| `TestBabelTwoNodeRootSmoke` | 两节点实际 IPv4 路由学习 |
| `TestBabelImportFilterNegativeRootSmoke` | 导入过滤的拒绝路径 |
| `TestBabelAnycastFailoverRootSmoke` | Anycast IPv4 路由故障切换 |
| `TestBabelDualInterfaceCostFailoverRootSmoke` | 双接口代价与路由故障切换 |

namespace、主机接口、IPv4/IPv6 全路由表在测试前后相同，没有残留测试 BIRD 进程。本批没有运行 charon/IKE，XFRM 未发送加密流量，Babel 未验证 IPv6 路由学习，也未运行默认主机 VICI 或 host-upstream 测试。

### 隔离真实 charon、双栈加密流量与恢复

`strongswan-smoke-summary.json`、`vici-recovery.log`、`ike-p256.log` 和 `ike-ed25519-dualstack.log` 记录补齐 PKCS1 必要依赖后重新执行的结果：

| 测试 | 已验证事实 |
| --- | --- |
| `TestReconnectingGoviciClientDelayedCharonRecoverySmoke` | socket 不存在时构造成功，`ListSAs` 明确报 ENOENT；真实 charon 6.0.3 启动后返回空 SA 列表及版本；准确 PID 经 SIGTERM/Wait 停止后操作明确失败；重启后同一个 wrapper 自行恢复 |
| `TestStrongSwanDriverIKEBringupSmoke` | 随机 P256 密钥、真实 IKE/CHILD、IPv6 XFRM tunnel 双向 ping |
| `TestStrongSwanAlgorithmInteropSmoke/candidate=false/ipv4=false` | 原 canonical Ed25519，IPv6 双向 ping；A、B 分别发起 CHILD 和 IKE rekey，每次核对 SA ID/SPI 并再次双向 ping |
| `TestStrongSwanAlgorithmInteropSmoke/candidate=false/ipv4=true` | 同一 canonical Ed25519 路径的 IPv4 双向 ping 及双方 CHILD/IKE rekey |

测试运行于独立 network namespace，使用临时 VICI socket、配置、pid 目录和随机测试身份密钥，不连接系统默认 VICI，也不改生产记录或授权。`unshare --propagation private` 隔离 `/run` bind mount；恢复测试核对不同的 mount namespace、私有 pid 目录 inode 及无 shared/master 传播标记的真实 mountinfo。失败诊断使用 `ip xfrm state list nokeys` 保留 SPI/算法信息，避免记录临时会话密钥。

首次 12 包组合的失败日志单独保留，补齐 13 包后的通过日志单独计数；未开启 container 跳过选项，也未更改连接字段或算法提案。最终命名空间、主机接口、IPv4/IPv6 全路由表、mountinfo 与忽略计数器的 nft 规则均与测试前一致，无残留测试 charon/BIRD 进程。

这份首轮证据覆盖实际设备内核和 strongSwan 的隔离协议与数据面。IPv4/IPv6 ping 使用相应隧道内地址，IKE 底层使用 namespace veth 的 IPv4。该表中的 VICI 测试仅覆盖 wrapper；上文的后续原生 procd 测试另外覆盖空 SA 时的应用 watcher/reconcile 恢复。

### Babel 经真实 IPsec 的联合双栈流量

`pkg/transport/ipsec/babel_ipsec_smoke_test.go` 的 `TestBabelOverIPsecDualStackSmoke` 使用独立门槛 `PHOTON_IPSEC_BABEL_SMOKE=1`。两个隔离 namespace 各运行真实 charon、XFRM 和生产 BIRD 配置生成器、进程管理器及客户端；临时测试密钥和前缀不涉及生产身份或授权。

严格测试先暴露了两个生产兼容问题，失败记录保留，未计为通过：

1. `joint-parser-failure.log`：同一 BIRD static protocol 混合 IPv4/IPv6 通道，被设备 BIRD 拒绝为 `Different channel type`。生成器现按族拆开混合 static 配置，单族协议名保持原样。
2. `joint-after-bird-fix.log`：两族路由均实际由 Babel 学到，IPv6 业务 ping 与 SA 计数通过，但 IPv4 三包全部不可达，XFRM 接口出现三个 TX 错误。真实 CHILD 仅协商 `::/0`，IPv4 缺少 ESP policy。生产 CHILD 选择器现同时承载 IPv4/IPv6 payload，不再由诊断隧道地址族决定；身份、if_id、底层地址族和授权契约保持原样。

修复后以原有严格断言重新执行，`joint-final.log` 记录 **20.13 秒通过**：

- 每侧只宣告本机 loopback 的 IPv4/IPv6 测试前缀。远端前缀须由 BIRD 的 Babel 协议选中，并以 `proto bird`、XFRM 接口进入 namespace 内核路由表；没有静态远端业务路由。
- 先 IPv6、后 IPv4，以双方 loopback 业务地址为源和目的双向 ping。每族单独核对 `route get` 确实走 XFRM，以及双方真实 SA 入站和接口收发包计数增长。
- 停止仅本轮 BIRD B 后，A 的两族远端前缀从 BIRD 和内核表撤回；恢复 B 后重新收敛，再次验证两族双向业务 ping 和计数。
- 因生产选择器为共享逻辑，又重跑 P256 IPv6，以及 Ed25519 canonical IPv4/IPv6 的双方 CHILD/IKE rekey 与双向 ping，全部通过；日志为 `p256-after-ts-fix.log`、`ed25519-dualstack-after-ts-fix.log`。

该测试的 IPv4/IPv6 指 **ESP 内业务 payload**，IKE/ESP underlay 是两个 namespace 间 veth 的 IPv4；不代表真实 IPv6 underlay 或公网 NAT/WAN 已验证。Babel Hello/Update 经生产配置字段设为 1 秒以限定测试时长，不是默认计时或持续负载结论。它也不证明有活动 SA 时 charon 重启后的应用业务重建。

最终 namespace、host 接口、IPv4/IPv6 全表路由、mountinfo 和忽略计数器的 nft 规则与执行前逐字一致，无残留测试 charon/BIRD 进程。汇总为 `build/openwrt/device-acceptance-next/joint-summary.json`；真实 LAN 接入、生产多节点与持续流量仍待单独验收。

原有 network、firewall、dropbear、rpcd、uhttpd 配置 SHA 保持一致，firewall4 规则在忽略计数器后相同。上述结果只说明本次有边界的验收与恢复，不代表业务或全部网络路径已经验收。

## 本地回归与剩余工作

本地已完成服务脚本模拟检查、实际 YAML 解析、真实 Unix control socket canonical 响应、RPC 配置/并发/超时回归，以及 VICI 缺失、拒绝连接、恢复、永久错误和关闭后的模拟服务测试。18 项 LuCI Node 回归仍属于模拟 DOM/RPC，与上述设备浏览器证据分别计数。

```sh
sh contrib/openwrt/check.sh
node contrib/luci-app-photon/tests/luci.test.cjs
go test ./internal/photonopenwrt ./internal/photonlinux ./pkg/transport/ipsec
go test -race ./internal/photonopenwrt ./pkg/transport/ipsec
go test ./app/photon -run 'TestOpenWrt'
```

`contrib/openwrt/preflight.sh` 是只读检查入口；全部通过也不证明 namespace 创建、实际算法和流量通畅。已有 `docs/scripts/ipsec-xfrm-preflight.sh` 会创建临时接口/namespace，不能混作只读检查。

下一步先完善主机路由和地址的撤回：当前 `internal/photonlinux/routing.go` 的 `EnsureRoutes` 只执行 replace，ARS 前缀缩减或清空后，旧主机路由和源地址不会自动删除。`app/photon/routing_reconcile.go` 停用只停止同步，没有拆除既有配置。接入 LAN 前需以 Photon 拥有的对象为边界核对期望与实际状态，撤回旧对象并保留第三方路由，不能直接删除整条接口。

其次补备份恢复：默认 `/etc/photon/` 已由 SDK conffiles 生成的 keep 规则覆盖，但自定义 YAML、数据库及密钥路径不自动纳入；直接复制运行中的 bbolt 也不能作为一致性备份。需要保存原运行状态、停止后备份或使用事务快照，并在隔离环境验证恢复。

协议验收仍需有活动 SA 时 charon 重启后的应用链路与业务重建、整机重启、真实 IPv6 underlay、WAN/NAT 变化、firewall4 reload、端口轮换与权限撤回。ARM32/ARM64 还需各自 SDK 和目标设备执行，最后测量吞吐、长时间内存与 flash 写入。

LAN 自动接入尚未实现。主机 input、Photon namespace 与 `inet fw4` 是不同处理环节；接入前须明确 LAN/mesh 接口、双向 forwarding 和允许前缀，按原流程取得路由/IPAM 权限，再检查实际 IPv4/IPv6 流量。独立 nft 表的 accept、隧道握手或 Babel 路由学习都不能单独证明 LAN 可用。

## 参考来源

2026-10-18 核对的官方源码，master 链接会变化，包清单以目标固件版本为准：

- [本次 SDK 及校验清单](https://downloads.immortalwrt.org/releases/25.12.1/targets/x86/64/)、[固定 feed 清单](https://downloads.immortalwrt.org/releases/25.12.1/targets/x86/64/feeds.buildinfo)、[官方 strongSwan 构建失败日志](https://downloads.immortalwrt.org/releases/faillogs-25.12/x86_64/packages/strongswan/compile.txt)
- [OpenWrt strongSwan 包与插件](https://github.com/openwrt/packages/blob/master/net/strongswan/Makefile)、[swanctl/procd](https://github.com/openwrt/packages/blob/master/net/strongswan/files/swanctl.init)、[ImmortalWrt strongSwan](https://github.com/immortalwrt/packages/blob/master/net/strongswan/Makefile)
- [iproute2](https://github.com/openwrt/openwrt/blob/master/package/network/utils/iproute2/Makefile)、[iputils](https://github.com/openwrt/packages/blob/master/net/iputils/Makefile)、[BIRD](https://github.com/openwrt/packages/blob/master/net/bird2/Makefile)
- [OpenWrt 内核模块](https://github.com/openwrt/openwrt/blob/master/package/kernel/linux/modules/netsupport.mk)、[ImmortalWrt 内核模块](https://github.com/immortalwrt/immortalwrt/blob/master/package/kernel/linux/modules/netsupport.mk)
- [Go 构建接口](https://github.com/openwrt/packages/blob/master/lang/golang/golang-package.mk)、[架构映射](https://github.com/openwrt/packages/blob/master/lang/golang/golang-values.mk)、[procd 接口](https://github.com/openwrt/openwrt/blob/master/package/system/procd/files/procd.sh)
- [LuCI JavaScript 示例](https://github.com/openwrt/luci/tree/master/applications/luci-app-example)、[rpcd 会话与 ACL](https://github.com/openwrt/rpcd/blob/master/session.c)、[LuCI 登录与权限](https://github.com/openwrt/luci/blob/master/modules/luci-base/ucode/dispatcher.uc)
