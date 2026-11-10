# 操作与兼容性说明

- 修改配置文件后须重启 daemon。`routing_reload` 仍可强制路由 reconcile/reload，但不会重新读取整份配置文件。
- `health.metrics.remote_write_url`、`remote_write_queue_capacity` 和 `observer.ui_path` 尚未实现，现在配置这些字段会明确报错（包括空字符串或默认队列容量）。删除这些字段；本地 metrics spool 仍可使用，Observer 使用根路径内置 UI。
- debug ping 和内核路由查看要求 daemon 在线。CLI 通过控制接口请求 daemon 执行；系统命令的权限和网络 namespace 取决于 daemon 的运行环境。
- HealthView 已从 Targets/Samples 分列改为统一 `links` 行；Links 查询使用扁平摘要和统一 JSON 名称。Health 不再附带原始 instance，Links 不再输出 owner token。仓库前端已同步；外部客户端必须更新字段映射。
- 离线 admission 和 sync 数据来自 checkpoint / last-known，只表示上次已知状态，不能作为实时在线结果。
- `photon gossip peer` 默认隐藏超过 `peer_lifecycle.cleanup_after` 且没有有效 Gossip endpoint 的历史节点；配置的 bootstrap 始终保留。按名称或 `--filter` 查询、`--verbose`、`photon debug peer <peer>` 和 `photon debug peers` 仍可诊断历史节点。筛选在线和离线查询均生效，只改变列表展示，不删除 checkpoint、签名 zone 或授权；checkpoint 继续用于防止陈旧记录重建离线链路。有效端点或最近活动恢复后，节点重新进入默认列表。
- 禁用路由会停止新的 reconcile，不自动拆除之前创建的资源。需要拆除时须显式执行相应运维操作，不能把 disabled 当作资源清理。
- `debug db dump` 使用通用递归原始 bucket 展示，已删除 `_meta` / `zone:*` 旧布局专用解码；指定 zone 时解码当前 VerifiedState 并只输出该 zone；旧布局可查看原始 bucket。`stats` 递归统计叶子键及键值逻辑字节数（不是磁盘分配量）。读取锁等待约一秒后报错；daemon 持有数据库时应停止 daemon 或使用一致的数据库副本。
- Links/rotate 内部诊断字段 `StoredSAs` 改为 `ReconcileSAs`、`ReplannedDesired` 改为 `LastDesiredCount`：它们来自最近一次 reconcile 的内存观察，不是 DB 持久值或当前重新规划的结果。控制接口直接消费这些诊断字段的客户端也须更新。
- `debug links` 的链路详情、action/skip，`debug rotate` 的 current/staged 与 SA 对照，以及 `debug peers` 的生命周期与时间信息使用分组表格。原先解析缩进键值文本的脚本需要调整。普通 links 查询只读取 daemon 最近一次观察；`debug rotate` 通过 `links_view` 的 `live_sas: true` 显式补充实时 SA，实时查询失败仍展示缓存及错误。
- Link routing DTO 和 Observer 已删除始终为占位值的 `bird_neighbors`、`bird_best_routes`，保留 `bird_state`；实际 BIRD 邻居和路由请使用 `debug routing bird` 子命令。诊断不再接受未使用的 planned spec 输入，不根据缺失的计划数据重建 StrongSwan 配置。

## 数据库版本边界

当前版本只接受 Common schema 2，Linux 另读取自己的 schema 1 分区。daemon 启动和离线状态查询都用只读事务打开，遇到旧的整库布局或 Common schema 1 会拒绝加载。若还持有旧库，先备份配置、身份和一致的数据库副本，再用上一版 Photon v0.6.6 打开，确认完成迁移后才切到当前版本。

旧的整块 Gossip checkpoint 和 Linux 清理提示不参与恢复。当前按 peer 存储的 checkpoint、已验证的 Zone、身份和平台配置按各自分区读取。

混跑新旧版本时，旧节点收到新节点发出的 UDP `FETCH_ZONE` 只会返回摘要。如果节点之间依赖 UDP 分块传输 Zone，需把两端升级到当前协议版本。
