# 操作与兼容性说明

- 修改配置文件后须重启 daemon。`routing_reload` 仍可强制路由 reconcile/reload，但不会重新读取整份配置文件。
- `health.metrics.remote_write_url`、`remote_write_queue_capacity` 和 `observer.ui_path` 尚未实现，现在配置这些字段会明确报错（包括空字符串或默认队列容量）。删除这些字段；本地 metrics spool 仍可使用，Observer 使用根路径内置 UI。
- debug ping 和内核路由查看要求 daemon 在线。CLI 通过控制接口请求 daemon 执行；系统命令的权限和网络 namespace 取决于 daemon 的运行环境。
- HealthView 已从 Targets/Samples 分列改为统一 `links` 行；Links 查询使用扁平摘要和统一 JSON 名称。Health 不再附带原始 instance，Links 不再输出 owner token。仓库前端已同步；外部客户端必须更新字段映射。
- 离线 admission 和 sync 数据来自 checkpoint / last-known，只表示上次已知状态，不能作为实时在线结果。
- 禁用路由会停止新的 reconcile，不自动拆除之前创建的资源。需要拆除时须显式执行相应运维操作，不能把 disabled 当作资源清理。
- `debug db dump` 使用通用递归原始 bucket 展示，已删除 `_meta` / `zone:*` 旧布局专用解码；指定 zone 时解码当前 VerifiedState 并只输出该 zone；旧布局不再支持 zone 筛选，启动升级迁移仍保留。`stats` 递归统计叶子键及键值逻辑字节数（不是磁盘分配量）。读取锁等待约一秒后报错；daemon 持有数据库时应停止 daemon 或使用一致的数据库副本。
- Links/rotate 内部诊断字段 `StoredSAs` 改为 `ReconcileSAs`、`ReplannedDesired` 改为 `LastDesiredCount`：它们来自最近一次 reconcile 的内存观察，不是 DB 持久值或当前重新规划的结果。控制接口直接消费这些诊断字段的客户端也须更新。
- `debug links` 的链路详情、action/skip，`debug rotate` 的 current/staged 与 SA 对照，以及 `debug peers` 的生命周期与时间信息使用分组表格。原先解析缩进键值文本的脚本需要调整。普通 links 查询只读取 daemon 最近一次观察；`debug rotate` 通过 `links_view` 的 `live_sas: true` 显式补充实时 SA，实时查询失败仍展示缓存及错误。
- Link routing DTO 和 Observer 已删除始终为占位值的 `bird_neighbors`、`bird_best_routes`，保留 `bird_state`；实际 BIRD 邻居和路由请使用 `debug routing bird` 子命令。诊断不再接受未使用的 planned spec 输入，不根据缺失的计划数据重建 StrongSwan 配置。

## 数据库单向迁移范围

启动 daemon 和离线 owner 读取均经 `openState -> restoreState`，在同一个 bbolt 写事务中迁移并加载；离线读取旧库也可能完成升级，并非字节级只读。直接查看原始 DB 使用 debug dump 路径。

- `_meta/cli_state` 加 `zone:*` 是旧 aggregate 布局；迁入 `photon:common-state` 与 `photon:linux-runtime` 后删除旧记录，失败时整个事务回滚。新旧表示共存或旧数据不完整时拒绝加载。
- 已分区 Linux payload 的旧 `peer_cleanups` 标记迁入 GossipCheckpoint，不属于 aggregate 格式升级。
- 已分区 common state 的 root authority 修复也走这一启动事务，修复发生时更新 verified revision；不能随 aggregate decoder 一起删除。
- 旧 `identity_key_path` 不是现行身份来源，迁移时忽略；身份私钥、transport key 和 Endpoint ACL 仍按各自 owner 恢复。

当前仓库 VERSION 为 0.5.6，未声明旧 aggregate 直接升级的截止版本。版本号本身不能证明旧库已完成迁移；截止版本尚待发布计划明确，此次审计未取消旧库支持。

迁移实现仅在 app 私有 decoder 中保留 legacyPeerState；旧 aggregate 的 stateFile 中转模型已删除。当前在线 inspect 仍使用地址宽限期与拒绝记录 DTO，这些响应字段不随旧库迁移退场。
