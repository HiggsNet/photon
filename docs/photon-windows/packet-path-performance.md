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

## 第三轮：不可变发布快照与精确授权区间

2026-10-12，目标是继续提高实际 Windows 吞吐，使用 [多流工具](throughput-testing.md) 独立验证。第三轮先减少复制和分配，再复用已证明不会变化的签名策略推导；公开 Store 和普通可变 View 的语义保持原样。

- `packetStateView` 只供 daemon 串行逐包 owner 使用。每个事件检查 Store 身份及 verified revision，有新发布立即读取独立快照；同一发布只保留一份只读 State。Gossip checkpoint 不随 verified revision 变化，因此不进入这个视图。小网络 `ReadView` 的 4669 ns / 7832 B / 96 次分配降为此 owner 稳态读取的 5.508 ns / 0 B / 0 次。
- canonical 签名 payload 提前计算容量、直接追加字符串，保留原字节与签名兼容性。ESP 在一份独立输出缓冲区内按 AEAD 允许的精确重叠原地加密，保留调用者输入。1200 字节 Seal 分配由 2576 B / 3 次降到 1296 B / 2 次；约 611 ns 的耗时没有明显变化，不据此宣称 CPU 提升。
- 私有 `prepareSnapshot` 仅接受上述只读发布快照。身份包含 State 指针、revision、实际 config 内容和完整原 DNS planner hint；失败不保存，普通 `prepare` 每次计算并清除旧策略。不是以可变对象地址推断内容未变化。
- 授权区间最迟在下一 Unix 秒结束，并提前止于全网络 delegation / ParentProof 的精确期限、canonical 地址 resolver 实际算出的期限、端口期限。地址/端口严格 `After` 边界保留额外 1 ns；极端 TTL 的 duration 溢出由原 resolver 计算。内存期限若含单调时钟，整个快照回退到逐次验证。墙钟倒退清除复用；原 DNS hint 的 10 秒 elapsed / wall 寿命每次检查，不随业务流量续期。
- 每个事件更新精确 `now`，每次使用仍检查 attachment、generation、当前 IKE/CHILD 寿命与 SA 归属。`observeData` 后再次检查 CHILD；每包 source/destination、traffic selectors、精确本地地址、Babel neighbor/candidate 期限及来源约束继续现场检查。crypto job 不携带策略或事件授权。
- `Leaf.HasRoute` 只回答当前是否存在合法业务路由，避免构造、排序 route 选择数组；仍遍历和清除全部失效候选。需要 next-hop 的调用方保留原 `Candidates` / `Lookup`。小 fixture 的判断微基准为 212.9 → 99.93 ns，256 B / 2 次 → 0 B / 0 次；这不是完整 packet 路径的两倍提升。

同一冻结 executable、真实签名三 zone 与 ESP/UDP、1200 字节 payload、三轮 1 秒 portable 中位数（此对照先于 HasRoute 联接）：

| 路径 | 普通独立 View / 每事件推导 | 只读快照 / 精确区间 | 后者每次分配 |
| --- | ---: | ---: | ---: |
| 出站 | 198.299 µs | 16.955 µs | 5016 B / 15 次 |
| 入站 | 146.340 µs | 23.665 µs | 7554 B / 23 次 |

这是固定 fixture 时间、内存 packet device 的串行事件成本，分别约快 11.7 / 6.2 倍，不能代替真实 Windows 吞吐。最初部分 benchmark 与 race 编译重叠，保留为初测；表中只采用无其他 host / VM 重负载的 `policy/packet-comparison-clean.txt`。

回归包含真实签名 ParentProof fallback、未来 authority key 引起 Router ID 冲突、第三方亚秒到期使冲突解除、TTL 溢出、同 revision 到期、墙钟倒退、config / hint 修改、CHILD 切换与 selector 收窄。另经真实 `Store.ApplyRemoteBatch` 发布签名 IPAM 撤回，确认已加密的旧 completion 被新快照拒绝。完整 Windows 包 race 通过。原始证据保存在 `build/validation/performance-20261012/`；实机各轮固定二进制来源单独记录，1 Gbps 目标仍由真实测量判断。

## 第四轮：主循环直接执行有界 AES

生产 daemon 使用串行数据面 owner：业务包直接执行 AES，Babel 控制仍进入原有 64 项明文作业队列，由同一主循环每 turn 取一项处理。所有生产出站 ESP 序号在这个 owner 中分配，随即重新取当前发布视图和精确时间、观察 CHILD 切换、校验并投递。这样既减少业务 crypto job / completion 的线程调度，也防止已加密的后台 Babel 控制被超过 64 个快速业务包越过，落到对端重放窗口之外。

原独立组件的 worker API 继续存在，与同步路径共用相同 preflight、独立 job 输入副本和 AES 实现。控制队列保持有界；单包不超过既有 ESP / IP 大小上限，主循环仍逐 turn 选择生命周期事件。投递门禁共用唯一 completion 处理逻辑，AES 错误不会被当作成功，也保留 sequence exhaustion 触发 rekey 和 pending CHILD 的认证入站 proof。

同一冻结 executable 的 1200 字节签名 ESP / 真实 UDP 对照，三轮 1 秒中位数（两种模式均含第三轮策略及 HasRoute）：

| 路径 | worker | 直接 AES | 时间下降 | 分配次数 |
| --- | ---: | ---: | ---: | ---: |
| 出站 | 17.862 µs | 12.485 µs | 30.1% | 11 → 8 |
| 入站 | 24.361 µs | 21.899 µs | 10.1% | 21 → 18 |

这些数值包含测试 peer 的加解密、UDP 收发和调度，不能反推单包 daemon CPU 上限。原始数据为 `direct/packet-comparison.txt`。完整 Windows 包 race 通过；新增实际 ESP 测试验证排队的真实 Hello 在 128 个业务包之后才生成序号 129，仍被真实 64 包窗口 Receiver 接受，取消的明文 job 不消耗 nonce。另覆盖双向输入副本、篡改/重放、当前 endpoint / selector / generation / route / SA 归属、旧入站 CHILD overlap，以及签名路由撤回后拒绝已加密的直接处理结果。完整 SCM 吞吐仍须用固定源码二进制独立验证。
