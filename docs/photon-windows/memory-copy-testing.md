# Windows 内存复制、分配与局部复用对照

2026-10-13，基于 `windows` / `44316d00` 完成真实Daemon业务路径的只读所有权审计及九个Windows原生对照点。当前单个完整IPv4 echo有四次大块显式copy，共4948B；还识别出四个Go packet backing buffers。同样四段copy和完整校验，复用destination中位239ns，每次新建四个destination中位1151ns；结果支持优先研究buffer allocation及运行时成本，尚未证明完整产品约450Mbps主要受memory bandwidth限制。局部复用和原地解密有减少分配的空间；本轮没有实施新的生产优化。

## 真实路径账目

固定1200B UDP application payload、IPv4无options：inner为1228B，ESP padding为2B，含padding/trailer的AEAD plaintext为1232B，ESP wire为1264B。一次echo是Windows请求出站及回复入站，application goodput每pair只计一次1200B。

| 步骤 | 显式大块copy | 新Go packet backing | 所有权边界 |
| --- | ---: | ---: | --- |
| Wintun Receive → 独占heap packet | 1228B | 1 | `wintun_windows.go:127-135`：detach后立即ReleaseReceivePacket；满raw64队列也已发生copy，随后丢弃 |
| raw64 → configured Read → leaf64 → Daemon | 0 | 0 | 两个channel传slice header/event，configured wrapper检查closed；不复制包体 |
| `processOwnedOutbound` | 0 | 0 | `console.go:518` / `dataplane.go:216-227`：原leaf packet由串行owner持有直到completePacket结束，旧dataplane clone已消除 |
| Sender.Seal → ESP output | 1228B | 1 | `esp.go:84-100`：独立workspace先copy inner，再在该workspace原地AES写1232B ciphertext及16B tag |
| 当前交付授权 → UDP WriteTunnel | 0（本层） | 0（本层显式packet分配） | 同步socket写，不据此声称OS网络栈无copy/无allocation |
| UDP共享receive workspace → esp64 | 1264B | 1 | `gossip_socket.go:142-175,261-285`：下一次receive会覆盖共享wire，成功入队必须detach；ESP不走Gossip返回的copy |
| `processInbound` → Receiver.Open | **0普通memcpy** | 1 | `dataplane.go:195-209`不再clone；`esp.go:147`的Open(nil)认证并向新buffer写1232B plaintext，返回1228B inner；AES解密输出不是额外memcpy |
| 当前交付授权 → Wintun Write | 1228B | 0（driver ring） | `wintun_windows.go:168-185`：AllocateSendPacket后copy完整inner，successful allocation Send一次 |

四处显式copy为1228×3+1264=**4948B/echo**。另有Sender/Receiver各12B的salt/IV nonce填入，未计入大块账目；nonce已改为锁内私有工作区，Sender和Receiver各仍保留一个output allocation。按Go1.26.5的1280B size class，上述四个IPv4 packet backings约**5120B/echo**，不代表整个Daemon恰好4alloc或5120B TotalAlloc；授权、控制、runtime、socket及接收工作区等成本还在账目之外。IPv6无扩展头对应inner1248/wire1284，四处copy总计5028B，不能混用IPv4尺寸。

以每方向1Gbps application goodput和1200B完整echo估算，约104167echo/s，显式copy逻辑量约**515MB/s**；仅计源读+目的写约1.03GB/s。450Mbps对应约232MB/s逻辑copy。此估算排除了AES、OS、零填充、cache等访问，不是实测DRAM带宽，也不是瓶颈证明。

## zero-copy 的实际边界

[Go AEAD契约](https://pkg.go.dev/crypto/cipher#AEAD)支持exact input/output overlap，Open失败时目标存储可能已被改写。当前Seal已利用原地加密，但先保留独立原plaintext：AES前后都检查selector与route，`completePacket`在AES后重新读取发布状态和时间，`accept`以原inner重新授权。不能以覆盖原leaf plaintext或缓存之前verdict来消除copy。取消、generation、当前SA与active CHILD检查也必须保留。

UDP demux得到的queue-owned ciphertext适合研究消耗型原地Open，但旧Receiver.Open返回detached inner的契约已有所有权测试，不能直接改为alias。专用真实consumer必须在认证/padding/inner失败时不暴露数据，保持认证和完整校验后才推进replay，丢弃已消费ciphertext，并在交付/drop结束前不复用buffer。这可以节省一个output allocation/独立工作区，AES输出写入本身仍存在。

[Wintun官方API](https://git.zx2c4.com/wintun/tree/api/wintun.h)允许修改Receive借用packet内容，但必须在Release前完成使用，并与End/关闭同步。现有两次queue交接通过独立copy及时释放ring；直接传借用slice需要新的释放生命周期，不能只删copy。Receive slice也没有ESP prefix/padding/tag所需headroom/tailroom，出站仍需要原plaintext供post gate检查。

直接decrypt到send ring还受Allocate/Send约束：当前API没有单次allocation的abort入口，成功Allocate必须形成完整packet再Send。认证、padding、inner或当前授权失败都要求不发送；未验证的padding也不能用来预先确定完整inner长度。因此当前约束下不能用失败时仍Send或缩短slice来回收不合法packet。

## 有限候选

1. 串行owner复用ESP Seal output workspace：保留原plaintext并保留现有copy，同步delivery/drop结束后才复用，主要减少Sender allocation。
2. 仅为独占ciphertext真实consumer研究原地Open：旧Open继续detached，主要减少Receiver allocation；失败、replay、route撤销、generation与关闭保护不放松。
3. 有界ingress buffer复用：copy仍存在；只有consumer归还点明确，且full/drop/cancel/error/close各路径正确归还时才安全。跨queue的同步成本也需要独立对照。

这些候选没有生产实现；esp与photonwindows跨package的真实调用边界需窄范围审阅，不为研究新增泛public buffer API。

## 独立copy对照方法

完成三个mode各三轮、共九个Windows原生点：`copy-reuse`复用四个destination，`heap-copy`每pair新建四个destination，`real-esp`使用当前真实Sender.Seal→Receiver.Open。单worker、实际Go P8/affinity `0xff`，256个distinct有效IPv4 inner源轮转；各点1024pair预热，计数清零但source cursor和真实ESP sequence/replay lifetime继续。约一秒窗口每128pair检查期限，实际末批和join计入时长；三轮mode顺序为A/B/C、C/A/B、B/C/A，保留全部点。

copy模式四段长度为1228/1228/1264/1228，synthetic wire只是1264B framing-shaped数据，不能称为合法ESP ciphertext。heap模式的四个新destination是allocation对照模型：真实Wintun Write使用driver ring，真实第四个Go backing来自Open的解密输出，不能说模型与生产恰有四次make对应。copy模式逐pair完整检查四个输出，real-esp检查完整inner一次；验证成本不同，不能把两者耗时相减当纯AES或GC时间。

各mode记录实际P/mask、Go版本、PID/OS创建身份、实际时长、全部pair、CPU、分配与完整性；真实ESP使用新随机key且整个点不重建SA，测后验证duplicate replay。source/oracle/destination工作集分别记录容量和setup allocation，三mode工作集不相同；256slot轮转也不能当作cold DRAM bandwidth测量。此对照不经过Wintun、UDP、Daemon调度、selector与动态授权，不是完整产品吞吐证明。

## 九点原生结果

冻结源码为 `44316d00e36d545308fe917bc064d3f56ab4f314`：877个原文件（含725个Go文件）逐字节一致，只在独立archive添加两个research test helpers。Go1.26.5 / windows amd64 / GOAMD64v1 / CGO0 / FIPS off；实际AES、PCLMULQDQ、SSE41及SSSE3可用。九点均为P8、process mask `0xff`、单worker；不是单CPU绑定对照。

| 模式 | 第一轮 ns | 第二轮 ns | 第三轮 ns | 中位 ns（范围） |
| --- | ---: | ---: | ---: | ---: |
| 四段copy，复用destination | 254.662 | 236.330 | 239.005 | **239.005**（236.330–254.662） |
| 四段copy，每次分配destination | 1151.338 | 1148.361 | 1219.499 | **1151.338**（1148.361–1219.499） |
| 真实Sender.Seal + Receiver.Open | 1088.254 | 1071.519 | 1097.221 | **1088.254**（1071.519–1097.221） |

ns为实际窗口时长除以完成iteration/pair数，并非单包延迟采样。九点实际时长1.000073–1.001787s、完成820736–4231680次，均包含最后128次batch及join；真实ESP sequence/replay始终延续1024次warmup，未复用nonce。

| 模式 | Process CPU 三轮（单核=100%） | B/iteration 中位 | allocs/iteration 中位 |
| --- | ---: | ---: | ---: |
| 复用destination | 99.837 / 99.993 / 96.702% | 0.000038 | 0.000000709 |
| 每次分配destination | 167.128 / 179.560 / 171.723% | 5120.033 | 4.000158 |
| 真实ESP | 142.008 / 138.816 / 149.858% | 2560.031 | 2.000152 |

CPU是实际子进程GetProcessTimes的user+kernel累计值，包含整个进程及runtime工作，不是worker线程独占CPU。B/allocs统计测量loop及同步，排除setup、warmup和测量前显式GC；复用模式的极小非零值来自固定开销。三个指标的中位各自计算，不能当成同一个样本。没有采集本对照的GC CPU或memory-stall分解，不能把额外进程CPU全部标为GC。

同轮heap-copy减copy-reuse为896.676 / 912.031 / 980.494ns，中位**912.031ns**；同轮耗时比4.521 / 4.859 / 5.102，中位4.859。这说明在当前循环中，每次申请四个buffer及相关运行时处理的成本明显高于复用同样destination。差额包含新buffer清零、allocator/回收及相关cache和调度变化，未独立拆分；不是纯GC成本，更不是完整产品采用复用后可节省的时间或吞吐倍数。真实ESP仍有1228B Sender copy、AES输出写入及两个output allocation；它不是zero-copy模式，不能与copy控制相减推导纯AES成本。

各mode的source可见capacity为637952B，oracle为655360B；copy模式destination为1275904B、合计2569216B，ESP destination为637952B、合计1931264B。这些是保留slice的可见capacity账目，不是完整resident heap或实际DRAM working set；Open返回slice限制了cap，allocator size class及其他对象也未全部纳入。setup累计allocation另记，约3.04MB / 7.00MB / 4.37MB，包含预热产生的临时分配，不能称为持续存活内存。

本地ESP普通/race检查、修正metadata后的helper普通/race检查及Windows交叉构建均通过。Windows原生15项功能检查全部PASS无skip，包括完整输入/输出所有权、四次真实heap allocation、warm lifetime、OpenSSL向量、认证失败不推进replay及sequence边界；九个正式子进程全部实际exit0，PID与OS creation token精确到100ns一致，whole-matrix校验接受全部九点。功能进程及九个测量进程的10个原PID、独占exe进程和唯一远端目录由独立cleanup确认不存在；`native.exit=0`。准备阶段两次metadata/checker修正均发生在正式执行前，保留原资料且各为0个native点；正式结果未挑点重测。

研究材料保存在ignored `build/validation/performance-20261013/memory-copy-control/`：

- [冻结清单](../../build/validation/performance-20261013/memory-copy-control/freeze.json)：SHA256 `4daa1ea63d184e273cebe9ee8f0e4cb2931a07827e7a5c16e1ce38b9ff7b222f`；exe SHA256 `a5e6f94e7d66ed399cf018a8b73c48177bd5b23ffbddcdeb61052e75d2e507fa`。
- [完整九点校验与统计](../../build/validation/performance-20261013/memory-copy-control/validation.json)、[执行顺序及原始数据目录](../../build/validation/performance-20261013/memory-copy-control/downloaded/photon-memory-copy-control-20261013-081150-595678/coordinator.json)。
- [本地检查](../../build/validation/performance-20261013/memory-copy-control/local-validation.json)、[原生功能输出](../../build/validation/performance-20261013/memory-copy-control/downloaded/photon-memory-copy-control-20261013-081150-595678/functional.stdout.log)、[独立清理](../../build/validation/performance-20261013/memory-copy-control/independent-cleanup.log)。

## 现有证据的解释范围

[真实Wintun对照](wintun-capacity-testing.md)保留Receive heap copy、Write ring copy、raw64及可选leaf relay64，隔离echo仍约1.73–2.10Gbps；[真实ESP基线](crypto-performance-testing.md)带Sender copy和独立output buffers，在单CPU/单SA下约10.6–11.2Gbps application-equivalent。它们支持先做copy/allocation量级对照，不支持盲删queue/copy或用速率差额归因。

nonce小片的明确收益是ESP pair 4→2alloc、少32B；Windows中位耗时约低3.6%，但范围重叠，未证明完整隧道提速。[完整产品CPU对照](cpu-control-testing.md)仍约450Mbps且未随CPU数线性扩展，当前没有memory-stall/实测内存带宽证据。局部复用需要自己的性能与所有权验证，稳定1Gbps、72h soak及发布/部署门槛继续保持未完成。
