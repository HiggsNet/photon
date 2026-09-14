# WSL2 行动清单（临时）

## 2026-09-08 PR 收敛决策：剥离 vti/shared，只保留 policy 路线

**出发点**：本项目原 linux-native 能力迁移到 WSL2。多轮探索后，唯一实网端到端验证过的路线是
**policy 后端 + WSL2 NAT IPv4**。VTI 混合部署存在 vti_rcv 静默丢包（未解决而是绕开），
shared 后端从未实网验证。

**依据**：

| 事实 | 内容 |
|---|---|
| 体量 | vti.go 455 行中约 330 行为 vti/shared 专用，policy 专用约 120 行；smoke 测试 1366 行约半数为 vti/shared 场景；两份弯路设计文档 287 行 |
| 隐含承诺 | `xfrm_backend: vti|shared` 一旦被用户设置即遭遇已诊断的静默丢包；文档标"实验性"挡不住误用 |
| 评审教训 | 独立评审揪出的 5 项 must-fix 全部集中在弯路表面（端口比较回归、policy MULTICAST 漏判、smoke 硬编码 VTI），policy 主干无发现 |
| 验证状态 | policy 是唯一对真实 gateway（8.152.2.95）跑通 ICMP+TCP 的后端 |

**处置**：

- Mirrored / IPv6 不按弯路处理：PR 里本无代码，属负结论平台知识。在 quickstart 保留各一段
  （Mirrored 下 Hyper-V 虚拟交换机拦截 xfrm 数据面；NAT 无 IPv6 underlay），替代 287 行设计文档。
- `wsl2-xfrm-explore` 归档分支 = 65f5e47 完整 pre-strip 代码 `-s ours` 合并 wsl2-vti-backend
  （探索历史全量可达）+ 本决策文档。零丢失。
- `wsl2-client` 从 origin/master(28472ea) 重建，目标 +3585 → 约 +2000：

| 原提交 | 处置 |
|---|---|
| ae34d6c fix(GC/firewall) | 原样保留（charon 6.x 兼容 policy 也依赖；firewall 修复 policy 路线必需） |
| f396ee1 feat(config) | 保留；删 SharedMark/SharedLocalAddress{,6}；xfrm_backend 只收 interface/policy |
| e0e1e5b feat(ipsec) | 收缩为 policy 后端 + XFRMPeerRouteInstaller；markBackend() 塌缩为 policyBackend() |
| 7040c09 test | 只留 policy 场景 |
| 484bba3 feat(wsl2) | 保留（模板本就是 policy 配置） |
| ad9aabd + 65f5e47 docs | 合并为一个 docs 提交；后端说明重写约 100 行，含归档分支指引 |
| a6c9e09 fix(评审) | 相关修复折回各自提交 |

## 历史遗留（重建后仍有效）

- **IPv4 IPAM pool**：需 root zone 运营者向 slapaper 委派 IPv4 前缀，ARS/firewall 才能覆盖 IPv4 隧道地址。
- **Adopt 路径**：已收进 `EnsureInterface`；Adopt/Repair/Staged 走同一条 Ensure（2026-04-06 收口）。
- **DPD/rekey/撤销**：长稳实网验证未做。
- **IPv6 mesh**：被平台阻塞（NAT 无 v6 underlay；Mirrored xfrm 不通），非配置问题。
- **charon bypass policy**：`process_route=no` 实验确认有效，生产 charon 配置需默认化。

## 2026-04-06 架构收口：policy 是 XFRMDriver 的第二种 adapter

**决策**：方向保留（`xfrm_backend: interface|policy`，VTI/shared 不回归）。抽象收口——变异点是「本地 L3 附着点」，不是贯穿全栈的字符串开关。对照图见 `docs/wsl2-xfrm-architecture-compare.html`。

**原则**：

- `XFRMDriver` 是真 seam。构造期按 `xfrm_backend` 选出 adapter；运行期调用方不再分支。
- `TransportLinkSpec.InterfaceName` 保持 photon 资源名（`phx<id>`），供 owner / rotate / 诊断使用。policy adapter 内部把地址落到 lo，Inspect 看 lo 上有没有这条地址。禁止把 `lo` 写进 spec/instance。
- 对端路由是 Ensure 的不变量，不是 optional `XFRMPeerRouteInstaller`。Create / Adopt / Repair / Staged 都走 Ensure，自然带上路由。
- `netns.kind: host` 与 `xfrm_backend: policy` 正交，不绑死。
- firewall「xfrm mesh invalid accept」按流量语义留下（解封装后 ct invalid 的 overlay INPUT），与 backend / WSL2 解绑。
- 不引入 `WSL2Driver` / `Platform` 模块；不把 `vti|shared` 配回去。

**推进顺序**：

1. Owner 名不要变成 lo（teardown/cleanup 正确性）。
2. 路由和 lo 地址累积收进 Ensure/Inspect；删掉 `XFRMPeerRouteInstaller` 和 daemon 的 multicast 特例。
3. firewall 规则叙事从 WSL2 挪到防火墙语义（2026-04-06：注释 + `docs/new/firewall.md` §4.3；规则本身未改）。
4. 再把 `SystemXFRMDriver` 拆成两个 adapter 类型；那时 `xfrm_backend` 只在构造函数出现一次。

**本轮范围（1+2，为 4 铺路，不先做类型拆分）**：

- planner / rotateSpec 不再把 InterfaceName override 成 lo。
- policy EnsureInterface：不创建 phx 设备，安装 underlay 对端路由，错误不再吞掉。
- policy AssignAddress：地址落到 lo 且不按 phx 剪枝；DeleteInterface 对资源名是 no-op（不删 lo）。
- policy InspectLink / InspectLinks：观察 lo（UP 即可，不要求 MULTICAST），地址取自 lo。
- ApplyTransportLink / ApplyStagedConnection 不再 type-assert 路由接口；Adopt 走 EnsureInterface（不 load/initiate）。
- daemon 匹配委托 driver 的 `linkStateMatchesSpec`，删除 `policyXFRMBackend()`。
- duplicate GC 注释去掉已剥离的 VTI 叙事。
