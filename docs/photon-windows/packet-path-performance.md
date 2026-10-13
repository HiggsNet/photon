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

第二轮仅复用相同公钥、完整带 domain 的 payload 和 signature 的 Ed25519 数学验签成功结果。所有授权逻辑继续执行；缓存局部、有界、只保存成功结果，并以内容而非可变对象地址为键。不混同本节第一轮测量。

## 第二轮实现与校验

`pkg/crypto.Verifier` 将原有校验共用同一实现，只有最终 Ed25519 数学运算可以命中缓存。原包级函数使用 nil verifier，继续实际验签；Linux 和异步 gateway planner 默认不启用缓存。每条 Windows pipeline 独有一个 verifier，供 daemon 串行事件中的提交、完成与控制路径使用，不进入 crypto job 或其他 goroutine。

保存的键由完整公钥数组、完整签名数组及独立 payload 字符串组成。最多 512 项、键与 payload 内容合计 512 KiB；单 payload 超过 4 KiB 时仍实际验证但不保存。容量不足时清空后重建，失败不保存也不挤出成功项。512 KiB 是保存内容的限额，不包含 Go map/object 开销。

回归覆盖缓存预热后仍拒绝权限收窄、有效签名的路由撤回、同 revision 的 transport key 到期和亚秒 delegation 到期，以及未来 Router ID 冲突、当前 CHILD selector 收窄、时钟倒退、签名/内容篡改；另验证传入 buffer 的后续修改不改变缓存键、容量清理和超大 payload。全 Windows 包 race 通过；最终 Windows 实测单独固定产品 revision 和二进制校验值。

相同 portable 基准三轮中位数：

| 1200 字节路径 | 第一轮后 | 第二轮后 | 第二轮每次分配 |
| --- | ---: | ---: | ---: |
| 出站 | 2.590 ms | 0.261 ms | 133352 B / 1694 次 |
| 入站 | 1.520 ms | 0.239 ms | 84659 B / 1006 次 |

相对第一轮，时间再下降 89.9% / 84.3%；相对最初约快 50 / 28 倍。完整 payload 的安全保存使分配略增：第一轮分别为 122984 B / 1642 次、79473 B / 980 次。第二轮 packet-only profile 中 Ed25519 验签累计占比约 0.12%，主要成本转为 JSON 解析、gateway 选择、route set 推导及分配；不能将这些有包含关系的累计比例相加。`after2*` 原始数据继续保存于同一 portable 证据目录。
