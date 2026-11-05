# Photon / FlClash Windows 接入验收

## 范围与环境

2026-11-06，Windows 11 测试 VM `10.16.252.11`，使用已有 `windows-test.catofes.` 身份、配置和数据库。未新建入网身份，未改服务器授权、路由或代理服务部署。测试前后核对原配置文件字节；数据库继续由独立 Photon 后台独占。

FlClash v0.9.3 (`be847366`)，Mihomo 子模块 `024245dc`，prism_ui `63450c0a`；Flutter 3.47.6、Go 1.27.1、Rust 1.99.0。Photon 后台用 Go 1.25.14。源码由 `app/photon-flclash/prepare.sh` 准备，完整 Windows 构建启用真实原生 hook。

代码按切片本地提交：`7e037628` 详细界面、`a4a993c5` 多代理、`dad6054c` 双 TUN/DNS 防回环、`61b5cfac` 阻断与重连恢复。未推送、触发线上 CI、打 tag 或发布 Release。

## 已验证的用户流程

- Windows 侧栏进入 Photon，使用保存的已有配置连接；在概览、隧道、节点、路由、代理服务和诊断六页切换。自动化操作真实 Flutter 控件；另用 PVE QMP 读取已登录桌面。
- 从真实签名状态读到 11 个服务发布者、33 个 SOCKS5 端点，勾选洛杉矶、新加坡、东京的三个独立 local 端点。配置中包含手选、自动择优和一致性哈希负载均衡组，实际请求验证这些组。
- 清空选择时，正在使用的 Photon 配置关闭已有连接并以 `MATCH,REJECT` 阻止新公网请求，Photon 后台继续运行；重新勾选后恢复。该测试不等于生产服务发布者的真实撤销验收；签名/授权撤销另有 Go 回归。
- 停止 Photon 时先停其代理接管；再次连接保留多个选择，重新启用代理后真实 TUN 请求恢复。
- 测试结束恢复先前的 TUN、系统代理和日志开关，停止自有 Photon 与代理连接，原配置文件字节保持不变。

## 真实数据面

| 路径 | 结果 |
| --- | --- |
| Mihomo HTTP → Photon IPv6 → 洛杉矶 SOCKS5 | HTTPS 成功，出口 `45.32.95.140` / US |
| Mihomo HTTP → Photon IPv6 → 新加坡 SOCKS5 | HTTPS 成功，出口 `194.156.163.48` / SG |
| Mihomo HTTP → Photon IPv6 → 东京 SOCKS5 | HTTPS 成功，出口 `139.162.104.119` / JP |
| 普通应用，无显式代理 → Mihomo TUN → 洛杉矶 | HTTPS 成功，与所选出口一致 |
| 双 TUN 同时运行时的显式 HTTP 代理 | HTTPS 仍成功 |
| 双 TUN 下内网 `2a0d:2905:1:1::1`，1232 字节 IPv6 ping | 3/3，样本约 2 ms；不是长期丢包或性能结论 |
| 本地 Mihomo SOCKS5 UDP ASSOCIATE → 洛杉矶/新加坡 → IPv4 DNS | 返回有效 DNS 应答 |
| 同样 UDP 查询 → 东京 Neutron | 多次超时，TCP 正常；未通过该端点 UDP 验收 |

运行中查询 Windows 最佳路由：Photon 公网引导地址 `123.57.143.66` 走物理以太网；内网 SOCKS 地址走 Photon；普通公网地址走 FlClash。接口索引只记录当时观测值，不作为持久身份或清理依据。

## 本轮解决的共存问题

1. 原网络观察器比较所有外部接口，代理网卡的创建/重配会重建 Photon。现在观察引导、网关和 Gossip 公网目标的实际源地址、下一跳及所用接口状态；无关虚拟网卡不触发整体重连，影响真实路径的路由变化仍触发。Windows 原生测试用独占测试网卡验证无关变化、实际路径切换和恢复。
2. 开启 Fake-IP 后，Photon 网关域名曾被解析成 `198.18.0.x`。可信目录现在提供规范化引导域名，Mihomo 对这些域名返回真实地址，并通过直连 DNS 解析。首次在线规划尚未完成时，也从当前签名的 IPsec 地址记录生成保护，避免重连短暂丢失规则。配置语法参考 [Mihomo DNS 文档](https://wiki.metacubex.one/en/config/dns/)。
3. 旧快照的过期任务可能排队后误清除新快照，较慢的配置应用还可能让后续勾选失效。现在过期任务核对快照身份，勾选前按需重新验证当前服务授权，阻断配置内容不变时不重复应用。

## 检查与证据

最终前端 101 项相关回归及静态检查通过；此前完整上游/前端回归 1051 项通过。Go 后台及独立入口测试通过，提交快照的 Windows 原生服务签名、域名、出口观察器测试通过。真实桌面测试位于 `app/photon-flclash/overlay/integration_test/`；原始公开结果保存在忽略的 `build/validation/photon-flclash-full-20261105/`，含失败对照，不含身份私钥。

完整便携包由 `app/photon-flclash/build-windows.ps1` 构建，校验上游/子模块/接入文件和工具链，附带 MSVC 运行库、独立后台、Wintun、第三方声明、许可证及 SHA256SUMS。包内不放测试配置或数据库。

## 未完成的范围

目前整个 FlClash 客户端请求管理员权限。首次安装、升级、回滚、卸载、普通用户权限分离、真实物理换网/睡眠、其他 VPN、长时间负载和完整故障矩阵仍由 `todo.md` D1–D8 跟踪。Windows SRv6 和该客户端的 IPv4 内网验收另由 D8 和 D0 跟踪。

最终便携 ZIP：`build/photon-flclash/dist/photon-flclash-windows-amd64-20261106.zip`，66,394,220 字节，SHA256 `864e3c0c45784d4dbcad58997a89e8e5364c0be31acaa6a2d2639ea9f67ea761`。本地逐文件核对 83 个 ZIP 条目与包内校验清单，无测试身份、私钥或数据库。Windows 压缩工具使用反斜杠 ZIP 条目名，核对时规范化分隔符。

已从这个便携目录启动真实 release 客户端，通过 VM 控制台点击连接、查看隧道/服务、应用保存的三个节点，并打开虚拟网卡。显式代理和无代理参数的 HTTPS 请求均实测走洛杉矶出口。切换辅助服务期间首次请求曾中断，切换完成后复核成功；不宣称切换过程无损。桌面入口 `Photon (FlClash)`，目录 `C:\Users\photon-test\Photon-FlClash-Windows-20261106`。交付时窗口保留在原有 test 身份的连接状态，便于直接试用。

## 2026-11-06 配置与授权

Photon 设置、新建配置与离线授权导入集中在 Photon 页。两个 Windows 界面共用 Go 配置表单和保存逻辑。Windows 原生回归验证了新建配置、校验后重试、已有配置的 ACL 保留、替换失败保护及离线授权导入，测试使用临时文件。Flutter 静态检查和 1049 项前端、语言、界面规则与组件测试通过。

真实 Windows 界面打开配置副本，滚动到日志级别并保存，切回原 test 配置后通过三地 HTTPS 出口、内网 IPv6、双 TUN、清空选择阻断及停止重连回归。验收退出码为 0，原配置字节保持不变，退出后无测试 Photon 后台或网卡。旧便携版曾显示一次代理清理超时，本轮未复现；退出时记录了 Core 断开后的路由观察释放日志。证据在 `build/validation/photon-flclash-settings-20261106/`。

桌面入口 `Photon (FlClash)` 已切换到新版便携目录。已打开离线授权表单，并从 Windows 文件夹选择进入新建配置表单，验证缺少根公钥时显示保存错误。首次自动入网的完整授权交换待独立验收。

更新后的 Windows x64 ZIP 位于 `build/photon-flclash/dist/photon-flclash-windows-settings-amd64-20261106.zip`，66,481,410 字节，SHA256 `993cd9bb993fff2d3b44455f6d962a9dffe4227813ac5547328a038ae882234f`。校验通过 76 个文件，包括逐文件校验清单。包内无测试配置、私钥或数据库。
