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

## 周期就绪检查

第三轮完整 Windows SCM 的 15.10 秒 profile 中，`leafRuntime.ready` 累计采样 0.51 秒，其中 0.46 秒来自签名检查。周期 `reconcile` 较少（0.15 秒，其中签名 0.13 秒），暂不扩展其生命周期实现。这些是有包含关系的采样时间，Windows 等待栈与 OS 调用混合，不能相加或直接当作活跃 CPU 比例。

daemon 的周期日志检查改用私有 `readySnapshot`，共用当前不可变发布策略；仍即时读取和清除 Babel neighbor / candidate，并要求当前 host、实际设备地址与来源约束同时匹配。普通 `ready` 和 IPC 查询保持原行为。两个独立候选表的差分测试覆盖实时路由/邻居撤回、亚秒寿命、签名授权变化、SA 与原 DNS hint 边界，避免互相清理候选掩盖差异。完整仓库 fmt/vet/test 与 Linux/Windows 构建通过。

固定有效区间的三轮同 fixture 稳态微基准（包含普通 `ReadView` 与新 owner 读取）为 5.168 ms / 137912 B / 2159 次 → 662.5 ns / 320 B / 2 次。它衡量这次重复检查的减法，不是全服务吞吐的相同比例提升。证据为 `policy/ready-snapshot-{tests.log,benchmark.txt,notes.txt}`；统一工具的实际 Windows 对照单列。

## UDP 收包地址分配

共享 UDP reader 使用 `ReadFromUDPAddrPort`，IKE/ESP 分流直接读取值类型 endpoint，仅实际返回 Gossip 时构造原接口要求的 `*net.UDPAddr`。旧 socket 的包/错误仍丢弃，selection generation、IPv4-mapped 规范化、IPv6 zone、错误时 nil 地址、packet 副本与原 16/64 项队列保持原契约。

冻结前后 executable 的真实 loopback UDP 分流微基准，各跑三轮 1 秒：四种 IPv4/IPv6、ESP/IKE 组合均由每包 3 次分配降为 1 次。IPv4 ESP 为 1332 → 1280 B、IKE 为 260 → 208 B；IPv6 ESP 为 1344 → 1280 B、IKE 为 272 → 208 B。中位耗时有升有降（IPv4 ESP 14.244 → 14.793 µs），本片只证明分配减少，不据此宣称 CPU 或完整隧道吞吐提升。

真实 dual-stack socket 验证 IPv4-mapped 源进入 ESP 后保留规范 endpoint/generation，解除 selection 后同一来源返回原 mapped Gossip 地址；超时/关闭仍返回 nil 地址。上述测试与既有共享 socket/rebind 测试的 race、Windows amd64 交叉编译通过，证据保存于 `build/validation/performance-20261012/socket/`。本片晚于四组固定产品测量，不计入它们的 executable。

## 周期设备意图的数学验算

第四轮后真实 Windows 的 8.10 秒 profile 中，`reconcile` 累计采样 0.11 秒，其中 0.10 秒为验签；周期暂停可能影响有界队列，但累计采样不能当作单次暂停时长或丢包原因。已有附着 pipeline 的 `reconcile` 改用其私有、有界的数学 Verifier。当前视图、权限、撤销、时间、gateway/DNS hint、活动 SA、Babel ID、host assignment/announcement 与双端 overlay 仍每次重建检查；没有设备意图或授权结果缓存。初次创建、pending completion 与普通入口使用 nil verifier。

`desiredLeafAttachment` 原来推导的 `GatewayPlan.Routes` 没有消费者，去掉这次推导；实际设备地址及 split routes 仍从当前授权 route set 得到。相同实现的 nil 与 warm 数学 memo、真实签名 fixture、三轮 1 秒中位数为 **1.503 ms → 97.039 µs**。分配由约 36078 B / 542 次增为 42238 B / 573 次，来自完整数学缓存键的临时材料。这是单次周期检查的 portable 成本，不能按约 15.5 倍推算全服务吞吐。

差分回归在同指针/同 revision 的可变 View 上先预热，再撤回真实签名 host/route、改变或篡改 overlay、修改 split/allowlist、退役 CHILD、改变 generation、跨原 DNS hint 寿命和 350 ms delegation 精确期限。双端 overlay 变化拒绝旧 SA 的本地授权绑定；独立 link-local 测试验证新签名 path 仍重算地址。focused race 通过，原始证据为 `leaf-verifier-tests.log`、`leaf-verifier-benchmark.txt` 及 `ready-profile-periodic.txt`。

## UDP 收发锁范围

同一 8.10 秒 profile 过滤 `runtime.cgocall` / `runtime.semasleep` 等待栈后，`WriteTunnel` 累计采样 0.53 秒，包含 mutex spin。原来发送持有共享状态锁直至 UDP 系统调用完成，同时阻挡 reader 分流。现在独立 `writeMu` 串行所有 Gossip/tunnel 发送、rebind、selection、invalidate 和 close；这些入口统一先 `writeMu` 后 `mu`。发送在 `mu` 内取连接并校验 generation/source 后释放它，但持续持有 `writeMu` 至同一秒期限内的实际发送结束，因此收包可以继续，旧发送仍不能跨 socket/selection 更替。

同一冻结 fixture、真实双向 loopback UDP、1200 字节/最多 16 包在途、三轮 1 秒中位数：IPv4 **8834 → 8429 ns**、IPv6 **9697 → 7105 ns**，均为 1280 B / 1 次分配。这仅测 UDP 同步，不含 AES、授权或 Wintun，不能据此宣称 Windows 吞吐或达到 1 Gbps。证据位于 `socket-write-lock/`。

测试用真实 UDP descriptor 的 `RawConn.Write` 暂占写操作，使生产发送实际阻塞；期间 ESP/IKE/Gossip 接收仍成功，selection/rebind/invalidate/close 必须等待旧发送完成，之后旧 generation 被拒绝。还覆盖 1000 包双栈并发收发、来源、generation、顺序和完整 payload。focused race 与 Windows 交叉编译通过；Windows 原生实际确认 RawWrite、上述 socket 回归、周期数学 memo 差分及原 LeafRuntime 全部通过，精确源码指纹和 executable SHA 保存于 `native-dirty-socket-leaf/`。这是提交前源文件验证，不冒充冻结的产品性能版本。

## 同步入站密文副本

同步 `processInbound` 只在调用共同 AES 核心期间借用输入密文。`Receiver.Open` 使用 `AEAD.Open(nil, ...)` 返回独立明文，保留原输入；完成结果在返回前清空 `job.packet`，成功、错误和取消均不保留输入引用。异步 job 继续复制输入，出站继续保留独立明文，供投递前重新检查 selectors 和当前路由。原 preflight、context/generation/SA 元数据、pending CHILD proof 与唯一新鲜交付门禁保持原行为。

冻结前后 executable 使用相同真实签名、ESP/UDP 与当前授权事实代码，仅替换同步入站实现。两个尺寸各跑三轮 1 秒，portable 中位数为：

| IP 包字节数 | 耗时前 → 后 | 分配字节前 → 后 | 分配次数前 → 后 |
| --- | ---: | ---: | ---: |
| 128 | 18.336 → 18.286 µs | 1208 → 1032 B | 15 → 14 |
| 1200 | 21.005 → 21.299 µs | 6809 → 5529 B | 15 → 14 |

每包减少一份密文副本，分别节省 176 / 1280 B；耗时基本不变且有升有降，不据此宣称 CPU 或 Windows 吞吐改善。此夹具包含测试 peer 的加密、真实 UDP 收发与独立当前授权检查，OS packet device 使用内存实现。

ownership 回归验证同步 Open 不修改密文，返回后整个输入 buffer 可以复用而不改变已认证明文；错误、重放和取消不保留密文，预 AES 取消不消耗入站序号。另以真实签名路由撤回验证双向已处理结果均被当前交付门禁拒绝。focused 数据面 race、Windows amd64 交叉编译和 Windows 原生 direct/serial 数据面回归通过。源码、overlay、基准与 race 原始证据位于 `inbound-ciphertext/`，原生执行与精确源码指纹位于 `native-dirty-owner-facts/`；这些是提交前验证，与固定产品吞吐测量分开保存。

## 每事件授权事实的分配

第五组首点 profile 中，过滤 Windows 等待栈后的 `mallocgc` 累计采样为 0.53 秒、`growslice` 为 0.34 秒、GC 为 1.10 秒；这些路径重叠，不相加或当作活跃 CPU 比例。daemon 的当前计划、出站准备、AES 完成和周期 readiness 改用调用方局部 `packetAuthorization`。`prepareSnapshotInto` 填入这一事件自己的事实，失败时清空输出；原指针入口委托相同实现。policy 与 crypto job 都不保留输出指针，没有增加另一份策略状态或改变成功策略的精确有效区间。

现在、当前 attachment/SA、发布 revision、wall rollback、原 DNS hint 及投递前重新检查保持原行为。签名事实中的不可变 slices 仍按原快照 ownership 共享；事件的时间和 plan 值彼此独立。普通 mutable View 的 `prepare` 不变。

同一真实签名/Babel route fixture、固定时间、三轮 1 秒的准备及授权微基准，中位 **625.9 → 589.3 ns**，**192 B / 1 次分配 → 0 B / 0 次**。前版使用 `9c48297` 原指针实现及仅适配相同输出形状的 benchmark helper，后版使用调用方输出；两版其余源码相同，先后独占运行。这只证明此稳态事件的分配减少，不含完整 ESP、Windows I/O 或全服务吞吐，helper 的值复制也不能用于推算精确服务时间收益。

新回归验证两个事件的时间独立、改变调用方值不改 policy、当前 generation 仍拒绝旧事实，配置缺失、精确 SA 到期和换代都清空旧输出。既有签名 deadline/撤销/CHILD 差分仍通过相同核心；focused race 与最新 Windows 原生 Dataplane/CallerFacts 均通过。原始源码、overlay、executable SHA、escape evidence 和基准位于 `event-facts/`；原生材料仍是 `native-dirty-owner-facts/` 的提交前源码验证，实际吞吐另用 clean 产品测量。

## 同一处理线程的有界连续收包

独立诊断轮固定 `4 flows / 每流窗口 1024 / IPv4` 的 profile 区间，三个既有 queue-full 增量为 raw 2738、leaf 28571、ESP 890。该点 echo 丢失 32214 包、约 8.00%，leaf 队列是最大观察项。这不是完整端到端账本，三个层与方向的计数不能相加归因全部丢包；测试标签的原子计数也可能影响吞吐。

daemon 在处理首个 ESP 或 leaf 包之前设定 250 µs admission deadline，首包之后仅非阻塞逐包取出已就绪包。同一轮两个方向共享最多 8 包，包含首包。每包立即完成原 preflight、AES、重新读取当前 snapshot/time 与唯一交付门禁，然后才考虑下一包；不预收批次、不共享事件 facts、不积攒批末投递，也不改变队列大小、端口或 nonce 分配顺序。

取消、handler 失败、generation/pipeline 变化会停止连续收包；已就绪 IKE 或 plaintext control job 会让出下一次主 select，认证 Babel 新排出的响应也会立即触发这一检查。其它 IPC、rebind、planner 与 tick 保留原 select 行为。250 µs 是准入预算，不是硬实时期限；它包含首包和阻塞发送时间，发送返回后若已耗尽预算则不再接下一包，因此不会在一轮连续启动八次一秒期限的慢发送。回到主 select 提供控制事件处理机会，不宣称随机 select 对某个事件有硬公平保证。

回归覆盖两个方向合计 8 包、空队列不等待、首包已超预算、阻塞 handler 不重启预算、取消/错误/控制任务及时退出；真实 signed root IPAM 撤回经 Store publication 后下一包不能投递，真实 ESP 内 Babel retraction 也立即改变下一包的 route verdict。已有双向 ownership、CHILD overlap 与当前交付矩阵继续验证相同核心。普通 Windows 编译证明新增同步 handler、yield 及其授权 closure 不逃逸，helper 不保留 deadline、通道或 callbacks，局部 facts 没有新的 heap move；不据此宣称整条 packet path 零分配。

focused race、普通/测试标签 Windows 编译、完整 tagged race 和 `make check` 通过。Windows 原生新 burst、既有数据面/事实/计数及真实 Wintun 双栈回归全部通过，执行前逐文件验证冻结源码 SHA，执行后独立清理自有 PID、目录和网卡。源码、构建及检查材料保存在 `packet-burst/`，原生执行材料位于 `native-packet-burst/`。

同计数标签、同首点 profile、同工具和参数的标准六点复测中，单流由 457.42/435.97 降为 401.50/375.42 Mbps，四流变化约 -1% 至 +2.5%，大窗口仍丢失约 7.8%。独立诊断轮 leaf 拒收为 28571 → 28140，到期请求为 32214 → 32205，没有明显缓解已观察到的拥塞；两个 profile 位置不同的轮次不交叉归因。每点仅一次短测，不证明单项因果或稳定收益。因此生产代码已回退到逐包主循环，保留尝试提交与完整测量记录；来源和两轮对照见 [吞吐记录](throughput-testing.md)。
