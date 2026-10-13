# Windows 内存复制、分配与局部复用对照

2026-10-13，第一轮基于 `windows` / `44316d00` 完成真实Daemon业务路径的只读所有权审计及九个Windows原生对照点。当时单个完整IPv4 echo有四次大块显式copy，共4948B；还识别出四个Go packet backing buffers。同样四段copy和完整校验，复用destination中位239ns，每次新建四个destination中位1151ns；结果支持优先研究buffer allocation及运行时成本，尚未证明完整产品约450Mbps主要受memory bandwidth限制。第一轮没有实施生产优化，后续真实consumer实现见下文。

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

以上是 `44316d00` 审计时的候选，后续已将前两项接入真实串行consumer，见下文。有界ingress复用仍未实现。

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

## 后续实现：有界输出复用与独占密文原地解密

2026-10-13，在上述研究提交 `16758d39` 之后，实现两条仅供真实独占consumer使用的路径：

- `Sender.SealInto(dst, inner)`从dst开头写ESP，复用调用方提供的capacity；不自动增长。容量不足或实际输出区域与inner读取区域重叠时，返回`ErrInvalidPacket`，不改buffer、不推进sequence。允许同一backing array中互不重叠的区域。原`Seal`仍返回独立wire，输入明文保持原样。
- `Receiver.OpenOwned(packet)`消耗独占密文，在`packet[16:]`原地认证解密；返回inner的cap限制为len。输入在失败时也视为已消费，失败不返回明文；重放窗口仍在认证、padding及完整inner校验全部成功后才推进。原`Open`继续返回独立明文。两入口共用既有验证和锁内nonce流程。
- Daemon串行业务出站的`processOwnedOutbound`在首次使用时申请一个`esp.MaxPacket`（65504B）workspace，后续复用；取消先于分配。completion仍持有原inner供fresh-after-AES gate重新检查，ESP输出仅在同步delivery/drop结束前有效，下一owned出站可能覆盖它。reset/close释放workspace引用；现有同步`completePacket`流程保持不变。
- console的ESP queue事件接入`processOwnedInbound`：UDP demux已将密文detach给唯一consumer，原地解密后没有ciphertext job引用，也不clear/pool这块存储。当前SA、generation、selectors、route、取消与CHILD overlap/retire检查保持。异步control、普通借用入口和worker继续用原来的独立输出路径。

这减少两个逐pair的ESP output backing allocations，但不删除原账目中的四次普通copy，也不消除AES输出写入。完整业务仍有Wintun读入及UDP入队的Go packet分配；只能将稳定ESP处理层作为零输出分配候选，不能称整个Daemon为零分配或全链路zero-copy。workspace仅由串行owner持有，调用方不可保留completion到下一turn，也不可在authorization/delivery中重入owned出站；当前实际回调不会这样调用。

实现及真实consumer由不同subagent独立审阅。ESP普通/race全通过，新增七组API所有权/容量与重叠拒绝/最大包与序号耗尽/失败不推进replay/IPv6/peer IV及非最小padding/并发检查；consumer新增七组普通/race全通过，覆盖同步delivery/drop之后复用、reset/close、queued control独立、真实UDP与设备交付、AES后签名撤销、当前SA与旧CHILD overlap、auth/replay及取消/preflight。原detached契约回归保留。`make check`（含Windows交叉构建）及`photon_profile`构建标签下的相关ordinary/race回归通过；验证日志保存于ignored `build/validation/performance-20261013/esp-owned-buffers/`。

新增`BenchmarkESP1200ApplicationPair`使用fresh随机key、连续sequence/replay、1228B有效IPv4/UDP inner、完整immutable oracle校验，对比detached与MaxPacket workspace的owned pair。实现提交为`3b72b4a`；其后的Windows原生及完整产品结果如下，不能将前面的synthetic copy差额当作实现收益。

## 真实ESP局部复用的十二点原生对照

固定旧源码`16758d399f5f1a16478d1971c21ea72cb376bac0`、新源码`3b72b4a956ed05f00062d5fadb8fa81e725b3545`。旧/新archive的878/880个原文件（725/727个Go文件）分别核验，只允许上述八个reviewed改动路径，其余逐字节相同；两份research helper完全一致，调用真实API，不复制ESP实现。工具链及硬件AES条件与前述相同。

每点单worker、256个有效IPv4/UDP输入及immutable oracle、1200B application payload、1024次预热；fresh随机key及同一SA的sequence/replay延续至整个`b.Loop`结束。owned使用与生产一致的65504B workspace，两mode均仅保留最近输出。每条件old/new各三轮：第一/三轮P1 old/new后P8 old/new，第二轮P8 new/old后P1 new/old，十二点全部保留。P1实际绑定mask1，P8实际mask255；固定benchmark framework的`-test.cpu=8`及stdout后缀`-8`不代表实际P，实际设置与测后查询记录在JSON。

| 实际条件 / 模式 | 第一轮 ns/pair | 第二轮 ns/pair | 第三轮 ns/pair | 中位（范围） | B/op / allocs/op |
| --- | ---: | ---: | ---: | ---: | ---: |
| P1 / aff1，旧detached | 951.591 | 918.902 | 926.807 | **926.807**（918.902–951.591） | 2560 / 2 |
| P1 / aff1，新owned | 593.167 | 592.313 | 585.050 | **592.313**（585.050–593.167） | **0 / 0** |
| P8 / aff8，旧detached | 1062.154 | 1061.572 | 1082.722 | **1062.154**（1061.572–1082.722） | 2560 / 2 |
| P8 / aff8，新owned | 549.176 | 555.273 | 581.206 | **555.273**（549.176–581.206） | **0 / 0** |

由各组三轮中位数计算，P1耗时降低约**36.1%**、P8降低约**47.7%**。这是相同完整ESP pair与完整byte校验的局部收益，不是完整隧道吞吐增幅。原生独立`AllocsPerRun`也验证old=2/new=0并恢复临时P设置；整个Daemon仍有其他分配和四次copy。

进程CPU中位（一个逻辑CPU=100%）为P1 old99.398% / new100.682%，P8 old124.131% / new100.020%。它含user+kernel及runtime工作，未拆GC或worker线程；P1的101.112%最高观察值完整保留，短窗计数及不同计时源的精度不能解释成允许使用第二个CPU。ns/pair使用Go1.26.5 benchmark的QPC计时；进程CPU使用自己包住累计counter读取及loop的`time.Now`单调窗口。两时钟分别核正值、范围及公式，不强求数值排序；setup/warm不计入benchmark，process边界allocation与benchmark B/op分列。新六点process窗口各仍有固定2malloc/48B边界开销，不能把steady 0B/0alloc写成整个进程零分配。

原生功能三个子进程分别执行13项旧ESP、20项新ESP和32项真实consumer顶层检查，全部PASS、无skip；十二个benchmark子进程全部实际exit0、JSON完整及done，实际P/mask、100ns进程创建身份、fresh key摘要、sequence/replay、完整input/output、分配和速率公式均核验。十五个原PID/creation身份、三份唯一exe进程及唯一远端目录独立清理通过。Root重算全部十二点及SHA，另由subagent独立复核。

保留两类测量工具问题：首次批次在3项功能进程和首个P1-old点后因两计时源的严格排序校验中止，`native.exit=1`和原始样本保留，不参与上表；随后使用相同源码/helper/exe重新执行完整十二点。第二批全部十五个原生子进程及coordinator成功，但wrapper汇总校验因PowerShell文化排序与Python码点排序不同仍返回1。原冻结validator、raw和`native.exit=1`均未改写；独立post-validator仅改为测试名exact集合及无重复核验，对同一完整十二点矩阵重校，实际`post-validation.exit=0`。未重采、未替换或挑选第二批样本，不能将wrapper退出值写成0。

材料位于ignored `build/validation/performance-20261013/zero-copy-control/`，完整矩阵在`attempt-2/`：

- [冻结清单](../../build/validation/performance-20261013/zero-copy-control/attempt-2/freeze.json)：SHA256 `c11da7a6a0d84fc58a97ec0a751e8121b949a107507eef526522d7797f743293`；old/new/consumer exe分别为`487a7558…` / `ab3b099c…` / `33c13cdb…`。
- [完整重校统计](../../build/validation/performance-20261013/zero-copy-control/attempt-2/post-validation.json)、[校验来源证书](../../build/validation/performance-20261013/zero-copy-control/attempt-2/post-validation-certificate.json)，post-validator SHA256 `58dd7aefaa2e256acbda961ba66560ecf00d6a858e14cea61b56aa55e581409a`。
- [原始矩阵及实际进程](../../build/validation/performance-20261013/zero-copy-control/attempt-2/downloaded/photon-zero-copy-control-20261013-115220-1165262/native-results/coordinator.json)、[逐身份独立清理](../../build/validation/performance-20261013/zero-copy-control/attempt-2/independent-cleanup.log)、[两时钟源码证据](../../build/validation/performance-20261013/zero-copy-control/attempt-2/clock-source.json)。

## 同一完整Daemon的三轮前后对照

同日完成六次全SCM服务测试，old为`16758d39`，new为`3b72b4a`，分别从纯生产archive构建，没有局部benchmark helper。Linux产品固定`2c06877d`，Windows发包工具固定`5a009981`，Linux echo固定`c1c8ea8a`；公共四个二进制、四份服务/吞吐脚本逐字相同。执行checkout为文档提交`3ed0a5bf`，其`source-commit.txt`不代表被测Windows二进制源码。

环境补充（用户在本轮结果后说明）：Linux测试主机为`road`（当前hostname已核对），guest地址`10.16.255.8`，运行于PVE `10.16.255.202`的LXC，测试网关/echo另在其Docker bridge容器内；Windows 11 guest地址`10.16.252.11`，运行于另一PVE `10.16.255.200`的KVM。用户认为Windows宿主性能稍强，尚未核对宿主规格或有效CPU预算，不将这个描述作为瓶颈证明。

现有结果保留为上述虚拟化环境中的对照；guest可见逻辑CPU数及进程affinity不等于独占CPU预算。后续应分别核验两台宿主/guest的CPU限额与调度、road的LXC/Docker祖先cgroup限制、Linux同窗口每核/softirq/UDP/XFRM丢包，以及Windows虚拟网卡路径。当前未访问PVE宿主、变更其配置或新增性能采样，不能将虚拟化、网络或宿主限制归因于Photon代码。

三轮顺序为old/new、new/old、old/new；每次完整六点，每点2s预热及8s正式发送，1200B payload、1s deadline、8,000,000包上限，实际服务/生成器P8及affinity`0xff`。保留Wintun、raw64/leaf64队列、真实单CHILD与共享外层UDP，四流有四个inner socket/remote端口，并未变成四个SA或四个数据处理owner。线程CPU采样固定250ms，CPU profile均只采首个`f1-w64-IPv4`，packet-drop诊断关闭。

goodput按完整且唯一的echo payload计算，每pair只计一方向，分母包含实际发送及drain。下表保留全部三轮，括号为最小–最大；增幅按两组中位数计算。

| 条件 | old Mbps中位（范围） | new Mbps中位（范围） | 中位增幅 |
| --- | ---: | ---: | ---: |
| f1-w64-IPv4 | 484.486（464.464–513.299） | 497.977（446.313–525.807） | +2.78% |
| f1-w64-IPv6 | 479.710（466.552–499.475） | 478.176（462.883–500.318） | −0.32% |
| f4-w64-IPv4 | 483.473（422.803–484.365） | 483.649（479.440–489.048） | +0.0365% |
| f4-w64-IPv6 | 464.559（436.678–484.275） | 487.283（325.545–507.353） | +4.89% |
| f4-w1024-IPv4 | 0（0–218.254） | 0（0–513.070） | 不计算 |
| f4-w1024-IPv6 | 464.838（437.494–484.771） | 475.945（470.780–476.896） | +2.39% |

四流IPv4小窗口同轮增幅为13.40% / 0.97% / 0.0365%，单流IPv4第三轮new反而低于old；各组范围重叠。局部ESP耗时降低36–48%没有转化为同等完整吞吐增益，四流IPv4小窗口的完整goodput中位基本不变，不能宣称稳定大幅提速或1Gbps达成。

| 条件 | old → new进程CPU中位，100%=1核 | old → new echo loss中位 |
| --- | ---: | ---: |
| f1-w64-IPv4 | 159.393% → 150.613% | 0% → 0.000241% |
| f1-w64-IPv6 | 155.691% → 145.745% | 0% → 0% |
| f4-w64-IPv4 | 151.697% → 146.201% | 0.345377% → 0.333656% |
| f4-w64-IPv6 | 150.947% → 146.330% | 0.344411% → 0.326713% |
| f4-w1024-IPv6 | 146.945% → 145.749% | 6.934678% → 6.827113% |

CPU与goodput中位各自计算，不代表同一轮。四流IPv4小窗口各轮new进程CPU均低于old，中位下降约3.62%；进程仍使用多个CPU，而串行业务owner未增加。线程观测仍只按相邻有效TID/100ns创建身份统计，不能当成Go owner归属或严格同窗口CPU分解。

六个首单流profile均用匹配二进制离线解析，没有重新采样。raw采样总量与实际进程CPU不等：例如r1 old为25.06s samples/13.40625s进程CPU，new为21.09s/12.40625s，profile与正式测量窗口也不完全相同。不能把`cgocall`的70–74%采样占比当成Windows真实CPU占比；`gcDrain`采样减少只是继续定位的线索，本轮没有allocation profile或DRAM/memory-stall计数，不据此判定GC或AES为主瓶颈。

36个正式点及36个预热点全部保留并通过源指纹、实际runtime、100ns进程身份、逐flow收发/超时/完整性账目、线程采样与速率公式校验。公共日志warm/prior/gap/measurement审计显示30/36点无记录中断；其余为old三轮IPv4压力点、new第二/三轮IPv4压力点及new第一轮四流IPv6小窗口。IPv4压力old为0/0/218.254Mbps，new为513.070/0/0Mbps，两组中位均0；它们处于不同就绪边界，不能作为稳定capacity或改善证明。IPv6压力仍约6.7–7.3%丢包。全部测后恢复通过不等于测内连续ready，没有日志中断也不是稳态证明。

六个SCM rig实际exit0，各次独立确认自有服务、NIC、Event Log source、远端目录、Linux容器及fixture私有输入清理；后台coordinator最终实际`matrix.exit=0`、完整36+36 summary且原PID/创建身份不存在。Root独立重算全部账目、指标及指纹，另由subagent独立重读校验。

首次产品执行的六个old原始点单独保留，不混入上述矩阵：外层工具session实际返回143、inner rig退出未捕获；root曾读到parent`matrix.exit=0`，随后记录外层状态时该文件被误手写为143。事故记录明确保留原0观测来源、人工改写及外层143的不同含义，不能把现文件当作原捕获。独立清理通过；默认sandbox进程空列表不是host退出证明，后续在真实host视图另行确认原runner/rig不存在。第二次仅增加detached启动、信号退出与进程身份核验，负载、源码、二进制和严格校验器不变，从头完成六次fresh run，没有择优补点。

证据位于ignored `build/validation/performance-20261013/zero-copy-control/product-attempt-2/`：

- [冻结清单](../../build/validation/performance-20261013/zero-copy-control/product-attempt-2/freeze.json)，SHA256 `bdaebe39eca873595c2d707ba76e090f3e3a4a6e41c05864512bf652ebb98e04`，47项指纹执行前后均通过；Windows old/new exe为`1e6b432e…` / `e971c1db…`。
- [全部原始点及完整统计](../../build/validation/performance-20261013/zero-copy-control/product-attempt-2/complete-summary.json)、[Root独立复算](../../build/validation/performance-20261013/zero-copy-control/product-attempt-2/root-audit.json)、[真实host最终进程证明](../../build/validation/performance-20261013/zero-copy-control/product-attempt-2/root-final-host-proof.json)。
- [630份case文件及来源证书](../../build/validation/performance-20261013/zero-copy-control/product-attempt-2/result-certificate.json)、[六份已有单流profile解析](../../build/validation/performance-20261013/zero-copy-control/product-attempt-2/profile-analysis/profile-summary.json)。
- [首次中断与状态改写来源](../../build/validation/performance-20261013/zero-copy-control/product/execution-incident-provenance.json)、[首次自有资源清理](../../build/validation/performance-20261013/zero-copy-control/product/cases/zero-copy-product-r1-old/failure-cleanup.log)、[真实host补充核验](../../build/validation/performance-20261013/zero-copy-control/product/root-host-owned-runner-proof.json)。

## 每包时间量级与继续定位的优先级

2026-10-13，重新计算上述new的12个小窗口原始点，以及Ranet当前快照四个既有小窗口点；没有新增采样或改写原始数据。统一1200B application payload，一个成功echo包含Windows出站及入站两个业务包。以下各列独立取三轮中位，不能当成同一个样本或相加后的时间账本：

| 条件 | 成功echo平均产出间隔，µs | 服务进程CPU摊销，µs/成功echo | 平均RTT的三轮中位，ms | 成功请求RTT区间的时间平均并发估算 |
| --- | ---: | ---: | ---: | ---: |
| f1-w64-IPv4 | 19.278 | 27.498 | 1.198 | 61.956 |
| f4-w64-IPv4 | 19.849 | 29.064 | 1.287 | 64.624 |

产出间隔为实际统计秒数/成功echo数，表示并行管线的总产出节拍，不是单包handler耗时。CPU为服务进程所有线程累计CPU差分/成功echo数，含收发、双向处理、控制及失包处理的摊销，不含客户端、Linux或PVE宿主。四流约29.06µs/echo若平均分到出入两个包，约14.53µs/包，但仍不是某个goroutine或函数的实测时间。RTT包括完整客户端/两端OS/网络/队列/服务路径；现有histogram只能将p50限定在(1,2]ms，不能把平均1.287ms写成p50。

对相邻有效TID/100ns创建身份的Windows线程counter区间重算，四流IPv4三轮user/kernel累计分别为4.4375/8.609375s、4.015625/9.1875s、4.703125/8.09375s；相应每成功echo摊销为user **8.840–10.633µs**、kernel **18.299–20.224µs**。kernel占这些匹配区间CPU约63–70%，不是阻塞等待；[GetThreadTimes](https://learn.microsoft.com/en-us/windows/win32/api/processthreadsapi/nf-processthreadsapi-getthreadtimes)分别报告线程在user/kernel模式执行的时间。各线程观察时点与进程counter不完全相同，即使本组三轮sum数值恰与进程差分相同，也不能称严格同窗口的完整分解，不能归属某个驱动/Go owner或Linux/PVE工作。单流前两轮的matched sum仍比process各少0.015625s，原差异保留。

局部owned ESP Seal+Open含Sender copy、锁、framing/replay及完整校验，原生单worker约0.555–0.592µs/pair；四段copy复用控制含校验约0.239µs/iteration。它们分别来自自己的隔离循环，不是纯AES/纯memcpy或完整产品阶段耗时，不能相加，也不能将不同pipeline的吞吐倒数相减：隔离Wintun约4.56–5.55µs/echo产出间隔，shared opaque UDP约11.65–11.70µs，完整产品约19.85µs，三者的范围和并行度不同。当前证据优先指向进一步拆Windows I/O/内核态工作、队列交接和用户态门禁/调度，未精确量化其中各函数成本。

Ranet当前静态SA参照单流约499.5Mbps、平均RTT约1.21ms，与Photon单流量级接近；四流为689–702Mbps、RTT约3.49–3.55ms。按成功RTT总量/实际统计时长（即成功率×平均RTT）估算，Ranet四流约255个成功请求在途；Photon四流三个正常IPv4点约64.61–64.83，IPv6有中断低点单列保留。这是整个测量窗口（含drain）内成功请求在ReadAt RTT区间的时间平均估算，排除read后校验、回包消费及credit release，不是瞬时或全部pending。

Photon四流IPv4正式点分别有1492/1498/1503个Expired、LateEchoed均0，请求期限1s，实际8s发送后另有约0.78–0.92s收尾。配置四流各64共256credits，不等于256个都在成功往返；失包等待超时占用额度是重要线索。不能据这组估算确定raw64、leaf64、esp64、socket或Linux哪个环节丢包，也不能推断扩大队列就能提速。Ranet每条件只有一次短测，省略完整Photon控制/动态授权，生成器版本也不同，不把并发差异归因为某一worker改动。

若单echo CPU成本维持29.06µs，1Gbps/1200B要求约104167echo/s、9.6µs产出间隔，线性CPU预算约3.03核；这不是实际容量预测。若平均RTT也维持1.2–1.3ms，所需成功在途量约125–135，还需要处理有效并发、失包和等待问题，不能只提高GOMAXPROCS或输入池容量。

下一片优先增加受控、低频的实际分段计时，保留现有授权/时间/当前SA/replay/序号门禁与控制调度：leaf64/esp64成功入队至owner消费的queue wait；dequeue后到AES前；AES；加密后的fresh gate；UDP Write/Wintun Write同步调用至完成或拒绝。采用同一Windows QPC时钟并单独标定probe开销，记录样本数和有界分布，不逐包记录payload/地址/key；调用wall-time包含等待/调度，不能叫CPU时间。raw64没有归还/时间metadata契约，不能伪称上述采样已覆盖它；Linux同窗口每核/softirq/UDP/XFRM计数仍需独立补齐。先精确量化，再决定做输入复用、减少同阶段重复读/解析或调整并行交接。

[全部16点数值与ReadAt源码证据](../../build/validation/performance-20261013/zero-copy-control/product-attempt-2/per-echo-accounting-final.json)，SHA256 `49b1eec5920baa42d122b0f87b4a9416c67e7e118dc0aa5c02d3d16d53146e1a`；[Root独立重算](../../build/validation/performance-20261013/zero-copy-control/product-attempt-2/root-per-echo-accounting-check.json)核验全部原始SHA、rate/CPU/RTT/并发公式及12个Photon点user/kernel相邻身份计数。本段尚未实施分段时间戳或新增性能对照，不提供不存在的授权/队列/I/O微秒分账。

## 可继续验证的复用边界

只读审计确认当前Babel没有长期保留原ESP backing：`babel.ParsePacket`在framing/checksum成功后克隆payload，Message及学到的路由保存值，回复由`BuildPacket`新建且queued job再次detach。console注释改为准确的同步completion有效期，未改变代码行为或当前“不clear/pool”的实现。

最窄候选为UDP demux→esp64的入队目的buffer复用，继续保留copy。归还原`datagram.packet`必须在console该turn同步delivery/drop结束后，覆盖旧generation、preflight、取消、认证/replay/inner失败、fresh gate拒绝和设备写失败。按queue64、consumer1、reader另持1计算，预算至少66个入队buffer，另有shared wire；不是65，也不等于现已实现池。reset不会清空旧队列，须按原来源归还；close需要阻止producer再入队并处理排队及迟归还，不能持socket锁等待consumer。普通ReadDatagram/IKE/Gossip借用入口没有ack，不能在next read悄悄覆盖交出的slice。

Wintun ring只借用至`ReleaseReceivePacket`，现copy让其及时释放；普通Read没有归还契约，回收跨configured wrapper、raw64/leaf64及关闭路径，改动范围更大。本轮未实现上述两处输入复用，也未证明它们会提高完整吞吐。当前应保留已验证的ESP复用，继续区分入队分配、串行调度及I/O约束，不能把内存带宽或GC当作已证瓶颈。

## 现有证据的解释范围

[真实Wintun对照](wintun-capacity-testing.md)保留Receive heap copy、Write ring copy、raw64及可选leaf relay64，隔离echo仍约1.73–2.10Gbps；[真实ESP基线](crypto-performance-testing.md)带Sender copy和独立output buffers，在单CPU/单SA下约10.6–11.2Gbps application-equivalent。它们支持先做copy/allocation量级对照，不支持盲删queue/copy或用速率差额归因。

nonce小片的明确收益是ESP pair 4→2alloc、少32B；Windows中位耗时约低3.6%，但范围重叠，未证明完整隧道提速。[此前完整产品CPU对照](cpu-control-testing.md)约450Mbps且未随CPU数线性扩展；本轮ESP局部复用实现2→0 output allocations，完整四流IPv4小窗口仍约483Mbps。当前没有memory-stall/实测内存带宽证据，稳定1Gbps、72h soak及发布/部署门槛继续保持未完成。
