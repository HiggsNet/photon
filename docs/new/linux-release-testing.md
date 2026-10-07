# Linux 重构版测试

本轮旧版固定为 `v0.5.6`（master 提交 `28472ea74615`），新版为
`v0.6.0-rc.5`（修复被动接收方的 IPsec 端口轮换）。新版只供测试，Windows 完整隧道尚未交付。
master 保留旧版；候选版从独立 release 分支发布，不更新 Docker `latest`。

## rc.5 相对 rc.4 的变化：被动接收方端口轮换

- 修复角色映射中明确的空值被当成缺省值、回退为主动拨号方的问题。空值表示仅被动接收连接，轮换时应继续加载被动配置，等待对端发起协商。
- 对端为 `role=out`、本机为 `role=both` 时，修复前可能在端口轮换期间持续报 `load connection: at least one contact point is required`，对端收到 `AUTHENTICATION_FAILED` 或 `NO_PROPOSAL_CHOSEN`；旧隧道仍可能正常传输，但新隧道无法建立。
- 同一配置加载用例在 v0.5.6 和 `cae426da` 的父提交通过，在 `cae426da`（2026-09-08，统一 IPsec 单代运行资源推导）失败。空角色判断的隐患在旧版已存在，该次重构开始覆盖轮换配置的角色，触发本次故障。
- 回归测试覆盖 IPv4/IPv6 被动轮换配置加载、不主动拨号、保留旧运行资源及等待对端协商；同时覆盖按 link/runtime 查找角色和旧调用缺省行为。

此修复不需要修改对端的 `role=out` 配置。发布包和本地测试不替代部署后的双向数据面与轮换验收。

## rc.4 相对 rc.3 的变化：Checkpoint 与读取性能

- 纳入性能提交 `de2b6859`：纯 GossipCheckpoint 更新走独立提交回调，不再复制、编码或写入 VerifiedState；verified revision 不变。
- 内存应用指定字段的 patch，只复制受影响的 peer；磁盘按 peer 保存小型 JSON，未变化的 peer 不重写。持久化成功后才发布内存状态。
- 同步会话只读取相关 peer；撤销清理只查询当前撤销结果和受影响的 checkpoint，不再复制整个网络和记录历史。
- 旧整块 checkpoint 在首次写入时原子迁移。直接回退 RC.2/RC.3 会丢弃可恢复的同步提示，但保留 verified 数据；重新升级时优先采用旧版新写入的 payload。此说明不代表承诺可以无损回退 v0.5.6。
- 没有修改事件队列容量、背压/丢弃策略和协议调度架构；短时采样不能证明队列拥塞已经消失。

2026-10-06 在 less 上分别采集相邻 180 秒 Go CPU profile（均含启动）：优化版 07:58:57–08:01:57 CST，原 RC.3 对照 08:02:01–08:05:01 CST。两轮在线流量不完全一致，以下是现场观察而非同负载基准。

| CPU 样本 | 原 RC.3 | 优化版 |
| --- | ---: | ---: |
| 进程合计 | 13.04 s | 2.90 s |
| Checkpoint 更新调用链 | 5.41 s | 0.07 s |
| 撤销清理调用链 | 2.06 s | 0.13 s |
| ReadView 调用链 | 2.97 s | 0.76 s |

调用链累计时间存在重叠，不能相加；Go profile 不包含子进程 CPU 或等待时间。采样后 less 已恢复原 NixOS RC.2，本分支未部署。

剩余 ReadView 复制主要来自 discovery（0.31 s）、生命周期 suppression（0.24 s）和 catalog/state view（0.18 s）。后续优先收窄查询，避免为了取摘要、活动时间、端点而复制 records/history；不要用未经证明的跨轮缓存替代验证，也不要仅按 verified revision 缓存受时间和 checkpoint 影响的结果。

进一步按 CPU 样本栈作互斥粗分（先归入 ReadView，再归后台 GC 等；不是把累计调用链相加）：

| 优化版样本类别 | CPU 时间 | 后续判断 |
| --- | ---: | --- |
| ReadView 内同步工作 | 0.76 s | 收窄查询 |
| 后台 GC 标记、清扫与回收 | 0.76 s | 先减少临时对象；归因到具体分配点仍需 alloc profile，不直接调 GC 参数 |
| ZoneDigests/ZoneRoot 摘要计算 | 0.28 s | 检查同一事件内复用和按变更 zone 重算 |
| ICMP 探测 | 0.16 s | 使用非阻塞 socket 与 Poll 等待，未发现明显忙循环 |
| 授权链验签 | 0.14 s | 保留验证；只有相同输入、相同有效期内的重复计算可考虑复用 |
| 其他及未归类 | 0.80 s | 包含撤销清理、调度、写盘、启动和零散平台/协议工作 |

其中 checkpoint 更新整个调用链只有 0.07 s，当前不是进一步拆分磁盘字段键的优先理由；JSON 解码累计 0.13 s、诊断对象复制 flat 0.03 s，也不是主导项。这些补充调用链已包含在上表，不能再次加总。样本总计只有约 290 个 10ms CPU tick，小于 0.1 s 的项目应通过更长采样或针对性基准确认后再改。

`ReadView` 之外约 2.14 s 并非全部业务计算，后台 GC 就占 0.76 s。继续减少复制可能同时降低 GC，但本次 CPU profile 不能精确断言每份垃圾来自哪条分配路径。现场出现的 111ms checkpoint 墙钟耗时也不能直接算作 CPU；若继续研究提交延迟，应另外统计事务/fsync 耗时。

本轮随后补充了窄读取和单段哈希分配优化，范围如下：

1. 已完成：`gossipStateView` 通过 `ReadCatalog` 在同一读锁内取得 managed zone 与 zone digests，不再构造完整 `ReadView`。catalog 的哈希计算另占 0.28 s，可先减少同一事件内的重复计算；若以后缓存单个 ZoneRoot，仅使变更 zone 失效，并按当前时间重新过滤撤销。
2. 已完成：`gossipSuppressions` 通过 `ReadPeerActivity(now)` 读取撤销结果及 peer 的 LastSync/ObservedLastSeen 时间。生命周期策略仍留在 daemon，每次重新判断未来撤销及 checkpoint 变化，不缓存超时结果。
3. 暂不扩大范围：单 peer 来源地址验证与全局 discovery 仍保持原路径，今后可考虑分开取数。保留父链、授权与撤销检查，避免每次收到包都构造整个网络和全部 checkpoint。跨事件缓存必须覆盖授权到期、未来撤销、端点 TTL 和 checkpoint 更新，不能只看 verified revision。

临时分配 profile 确认：旧目录查询主要分配在记录/字节切片深复制；移除复制后主要是哈希状态与编码 buffer。仅对 `Hash` 的单段输入使用库的 `blake2b.Sum256`，不引入缓存或对象池；测试覆盖空输入、块边界、单/多段等价和结果隔离，哈希及签名格式不变。

同一合成网络 fixture 的三次本地基准：

| 操作 | 改动前每次分配 | 本轮完成后每次分配 |
| --- | ---: | ---: |
| 目录读取和摘要计算 | 2,048,141 B | 454,298 B |
| 生命周期输入读取 | 1,485,906 B | 3,424 B |
| 单段哈希 | 416 B / 2 allocs | 32 B / 1 alloc |

目录窄查询约 0.39–0.42 ms；生命周期窄查询约 7–8 us。基准存在运行噪声，分配量比单次耗时稳定。上方 2.90 s 现场 CPU 结果来自前一阶段，不包含本轮补充；本轮没有再次部署 les，不能据此宣称新的线上 CPU 降幅。discovery 全量读取和多段摘要编码仍有开销，本轮到此收尾。

已验证完整 Go 测试、state/host/daemon 的 race 检查、go vet 和 Windows 公共依赖交叉编译；RC.4 准备分支的 `make smoke-all` 与 `make install-script-check` 也已通过；迁移、写盘失败回滚、未变 peer/verified 数据保留、未来撤销和查询隔离有测试覆盖。RC.4 的发布检查仍需按下文执行，长时间运行与特权数据面验证不由 CPU 采样替代。

## rc.3 相对 rc.2 的变化

- 增加 `component=sync event=slow_operation` 日志，覆盖 Gossip 事件处理、同步发起、来源地址和会话检查点、快照应用，以及路由、防火墙、IPsec 协调。
- 操作耗时达到 100ms 时记录；每个阶段最多每 30 秒输出一次，后续慢操作日志汇总期间被抑制次数及最大耗时。
- `queue_before` / `queue_after` 是操作边界的队列长度，`max_sampled_queue` 是慢操作边界采样的最大值，不代表连续测量的队列峰值。正常快速路径不构造日志字段或分配内存。
- 本版仅增加诊断，保持事件队列容量、丢弃策略和调度架构不变。日志不构成队列拥塞修复。
- 本版未合入 Windows 分支上的后续隧道开发。

## rc.2 相对 rc.1 的变化

- 兼容 iproute2 JSON 中十六进制字符串形式的 XFRM `if_id`，避免批量观察持续失败并回退逐接口读取。
- 默认 `photon gossip peer` 列表隐藏超过 cleanup_after、没有有效端点的历史节点；bootstrap 保留。按名称、`--filter`、`--verbose` 和 debug 仍可查询，最近活动或有效端点恢复后重新显示。此改动不删除数据库记录。
- 不包含现场 ln 数据库的手工恢复操作，也未新增 Rotate 状态日志或改变轮换策略。

## 下载和安装

使用一台专用 Linux 测试机，与仍运行旧版的节点互通。安装器支持 amd64/arm64，
会检查运行依赖并校验下载包的 SHA256。以下命令面向普通 systemd 安装；
NixOS、容器或自定义 unit 应沿用原部署方式，显式固定版本。

```sh
curl -fL --retry 3 -o /tmp/photon-install-rc.sh \
  https://raw.githubusercontent.com/HiggsNet/photon/v0.6.0-rc.5/contrib/install.sh
```

先在测试机安装旧版，完成入网并确认双向通信，作为基线：

```sh
sudo sh /tmp/photon-install-rc.sh --version v0.5.6
photon version
```

首次安装仍需按 [运维文档](operations.md) 配置身份、授权和网关，再启动
`photon.service`。安装包本身不会替你加入网络。

升级前停止 Photon，备份配置和数据库。默认 service 使用 `/etc/photon`；
先用 `systemctl cat photon` 检查实际配置、数据库和环境变量路径。
自定义路径必须一起备份，有其他 Photon 服务使用相同数据时也须先停止。

```sh
sudo systemctl stop photon
sudo install -d -m 0700 /var/backups/photon-before-rc5
sudo cp -a /etc/photon /var/backups/photon-before-rc5/etc-photon
sudo cp -a /usr/local/bin/photon /usr/local/bin/photon-services /var/backups/photon-before-rc5/
sudo sh /tmp/photon-install-rc.sh --version v0.6.0-rc.5 --no-service
sudo systemctl start photon
photon version
sudo systemctl status photon --no-pager
```

备份步骤只在首次升级前执行一次，保留原始旧版快照，勿用新版数据覆盖备份。
备份包含私钥，保持 root 私有。试用期间暂停该测试机的自动版本更新，避免切回正式版。

## 需要验证的行为

同一台机器先跑旧版、再跑新版，保持配置、对端、网络和负载相同：

| 场景 | 通过条件 |
| --- | --- |
| 基本联网 | 信息同步正常，IPv4/IPv6 双向实际流量可达 |
| 新旧混用 | 测试机运行新版，其他节点仍用旧版，正常同步和通信 |
| 重启及故障恢复 | 重启 Photon、strongSwan、BIRD，以及断网恢复后能自动恢复通信 |
| 授权更新 | 新授权生效，撤销后受影响的实际流量停止，其他节点不受影响 |
| 升级读取 | 旧版数据直接用于新版时，身份、授权和配置保留，无重复入网要求 |
| 持续运行 | 先跑 24 小时，定期传流量和重复故障恢复；发布前延长至 72 小时 |

记录每次故障发生、恢复连通的时间；记录丢包、CPU、内存和重启次数。
长时间运行应覆盖实际配置的密钥轮换周期，并检查轮换期间通信。
不能只根据进程 active 或 links 显示已连接判定成功；同时检查两端
`photon links`、`swanctl --list-sas`、实际路由和双向流量。
一台测试机只能验证新版与旧网的混合运行，不能替代全新版多节点组网验收。

故障注入放在专用测试节点；让节点断网或重启网络组件前，准备控制台或带外访问。
原始日志可用 `sudo journalctl -u photon --since '24 hours ago'` 导出，分享前去除敏感信息。

## 回退

本次未承诺新版写过的数据库可由旧版直接读取。回退应恢复旧程序及升级前数据，
会丢弃测试期间的本地变更；恢复后的节点仍需重新同步当前网络授权。
默认路径示例（先停止所有使用该数据库的服务）：

```sh
sudo systemctl stop photon
sudo mv /etc/photon /etc/photon-rc5-saved
sudo cp -a /var/backups/photon-before-rc5/etc-photon /etc/photon
sudo cp -a /var/backups/photon-before-rc5/photon /var/backups/photon-before-rc5/photon-services /usr/local/bin/
sudo systemctl start photon
photon version
```

`/etc/photon-rc5-saved` 必须尚不存在，保留新版数据供诊断。回退后再次确认真实通信，
必要时重启测试机清理运行中的网络状态，不只检查程序版本。

## 发布者检查

发布前执行 `make check`、`make smoke-all`、`make install-script-check`；
记录特权数据面测试、真实升级和长时间测试是否实际执行，不以基础检查替代它们。
GitHub Actions 必须提供两种 Linux 架构的归档和校验文件，Release 标记为
Pre-release，RC.5 Docker 镜像使用显式 `v0.6.0-rc.5` 标签，正式 `latest` 保持不变。
