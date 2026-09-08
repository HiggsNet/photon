# XFRM 数据面后端：policy 设计与平台事实

本文说明 `ipsec.xfrm_backend` 的设计约束、policy 后端的工作方式，以及在 WSL2 上
验证过的平台事实。部署步骤见 `wsl2-quickstart.md`。

## 1. 问题：标准 WSL2 内核没有 CONFIG_XFRM_INTERFACE

Photon 原生数据面使用 XFRM interface（`phx*` 设备，child SA 以 `if_id` 绑定）。
标准 WSL2 内核（`microsoft-standard-WSL2`）未编译 `CONFIG_XFRM_INTERFACE`，
`ip link add type xfrm` 直接失败，因此原方案在 WSL2 上无法运行。

`xfrm_backend: policy` 在不改动协商协议（IKEv2/charon）的前提下，用纯 xfrm 策略
替代虚拟设备；`xfrm_backend: interface` 保持历史行为不变，两者共享全部信令面代码。

## 2. policy 后端如何工作

无虚拟设备，三个要素：

1. **隧道地址挂 lo**。planner 把 link 的 `InterfaceName` 覆盖为 `lo`
   （`applyPolicyDeviceOverride`），`AssignAddress` 将隧道地址加到 lo；
   地址随链接累积、不剪枝（lo 是共享设备）。
2. **child SA 摘除 if_id 绑定**（`applyPolicyChildSA`）。charon 依据流量选择器
   安装 xfrm 策略与状态，出向包进入 xfrm 框架只由路由决策驱动。
3. **对端路由**（`EnsurePeerRoute`）。内核需要知道"到对端隧道地址走哪个出口"：
   policy 后端沿 underlay 路由发现出口（先 `ip route get <对端underlay>`，
   失败回退默认路由），为 `peerTunnelAddr/32` 安装 `src=本端隧道地址` 的路由。
   缺失该路由时隧道能建立但流量无路径——这是最常见的部署故障点。

配套约束：

- charon 必须 `process_route = no`。否则 charon 对已路由子网安装 bypass 策略，
  mesh 流量绕过隧道直连，表现为"隧道 up 但不通"。
- charon 的 xfrm 策略安装在 photon 的 netns 内（`netns.default.kind: host` 时即宿主）。

## 3. 为什么不是 VTI（含 shared VTI）

探索过程中实现过两个 VTI 系后端（per-link VTI、每 netns shared VTI + 共享 mark），
最终未采用：

| 缺陷 | 说明 |
|---|---|
| 混合部署静默丢包 | VTI 设备的 `vti_rcv()` 要求入向 SA 携带与设备 ikey 匹配的 mark。当对端使用 interface 后端（SA 无 mark）时，解封装后的包不进入 VTI 设备，被内核静默丢弃——无报错、无计数器异常，只能靠 tcpdump 逐层定位 |
| 平台收益有限 | VTI 解决的只是"没有 CONFIG_XFRM_INTERFACE"，而 policy 同样解决且无设备模型副作用 |
| 验证成本 | 两个后端均未在实网完成端到端验证（policy 是唯一对真实 gateway 跑通 ICMP+TCP 的路线），发布未验证路径等于向用户承诺未测试的行为 |

完整的 VTI/shared 实现与调研历史归档在 **`wsl2-xfrm-explore`** 分支，可供未来
双端 VTI 部署（VTI-to-VTI，两端都有 mark，无混合部署问题）参考。

## 4. 平台事实（WSL2）

- **网络模式**：只有 NAT 可用。Mirrored 模式下 Hyper-V 虚拟交换机拦截 xfrm
  处理后的包，纯策略与 VTI 数据面均不通（双栈实验确认，与端口分配无关）。
- **IPv6**：NAT 模式无 IPv6 underlay，因此本方案仅覆盖 IPv4。mesh 双栈在
  WSL2 上是平台限制，不是配置问题。
- **端口**：NAT 模式下 500/4500 可用；若宿主服务占用（如 Windows IKEEXT），
  用 `ipsec.fixed_ike_port` / `fixed_natt_port` 改端口（配置贯通见 C3 提交）。
- **验证状态**：policy + NAT IPv4 已对真实 gateway（interface 后端）完成
  ICMP + TCP 全通验证；DPD/rekey/撤销的长稳行为未测。

## 5. 客户端配置摘要

```yaml
ipsec:
  driver: strongswan
  xfrm_backend: policy     # interface | policy
netns:
  default:
    kind: host
```
