# Windows 逐包授权路径优化

2026-10-09，真实 SCM profile 将热点指向重复 Ed25519 验签，见 [实机采样](profile-testing.md)。本轮先消除同一次事件中的重复工作，保留完成事件重新读取当前状态与精确时间的检查。

## 第一轮实现

- readiness 状态转换日志由 250 ms 生命周期 tick 和授权/IKE 事件检查；IPC 查询仍现场计算。逐包完成不再重复计算 readiness，业务投递不依赖日志状态。
- 每次数据面事件独立生成授权事实：验证本地传输身份、Babel 身份和当前网关，再共用一次 IPAM/路由推导结果，得到本地地址、来源和路由许可。
- daemon 完成事件共用当前视图、时间与网关计划。`observeData` 可能切换 CHILD，因此投递前仍复核活动 SA、generation 和管线归属；旧出站完成拒绝，合法旧入站 overlap 继续按原规则处理。
- 授权事实只供同步事件使用，不存入 crypto job，不跨事件缓存。撤销、精确到亚秒的 delegation 到期、时钟倒退和包的源/目的检查继续生效。

## Portable 基准

`BenchmarkGatewayPacketPath` 使用真实签名的 authority、IPAM、gateway 和 Babel 记录，实际 ESP worker 与 UDP socket；只有 OS packet device 使用内存实现。每个事件读取独立当前视图，fixture 时间固定以隔离执行成本。它衡量串行处理成本，不等于 Windows 吞吐或丢包率。

1200 字节负载，优化前后三轮中位数：

| 路径 | 优化前 | 优化后 | 时间下降 | 每次分配次数 |
| --- | ---: | ---: | ---: | ---: |
| 出站 | 13.055 ms | 2.590 ms | 80.2% | 7384 → 1642 |
| 入站 | 6.794 ms | 1.520 ms | 77.6% | 3851 → 980 |

出站分配字节下降约 75.7%，入站下降约 70.7%。同一小网络的 `ReadView` 仅约 4.2–4.4 µs；本轮没有增加跨事件快照缓存。优化后的 packet-only CPU profile 仍以 Ed25519 验签为主要成本，说明第一轮尚未解决全部瓶颈。

原始 benchmark、固定测试 executable 与 CPU/alloc profile 保存在本地 `build/validation/b6-packet-profile-20261009/`。packet-only profile 与 `ReadView` 微基准分开采集，避免自动校准的大量 snapshot 迭代混入逐包归因。累计调用路径互有包含，不能相加。

全 `internal/photonwindows` race 测试及新增 CHILD 切换、同 revision 亚秒到期、时钟倒退、源/目的和跨 generation 回归通过。实际 Windows 同负载对照单独记录于 [SCM profile](profile-testing.md)，不以 portable 改善替代实机验收。

## 后续优化的边界

不把整次 `VerifyChain`、`VerifyRecord` 或 packet authorization 的成功结果直接缓存。它们不仅检查签名，还检查当前时间、权限、撤销和其他可变输入。简单的“同 revision、同一秒内复用”不足以保留原语义：delegation 和 ParentProof 可以精确到亚秒，地址与端口存在严格 `After` 边界，极端 TTL 的 duration 溢出也不能按整数秒推断；时钟倒退还需要单独处理。

下一片候选仅复用相同公钥、完整带 domain 的 payload 和 signature 的 Ed25519 数学验签成功结果。所有授权逻辑继续执行；缓存必须局部、有界、只保存成功结果，并以内容而非可变对象地址为键。该方向的实现及证据另行提交，不混同本节第一轮测量。
