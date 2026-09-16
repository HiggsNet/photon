# 操作与兼容性说明

- 修改配置文件后须重启 daemon。`routing_reload` 仍可强制路由 reconcile/reload，但不会重新读取整份配置文件。
- `health.metrics.remote_write_url`、`remote_write_queue_capacity` 和 `observer.ui_path` 尚未实现，现在配置这些字段会明确报错（包括空字符串或默认队列容量）。删除这些字段；本地 metrics spool 仍可使用，Observer 使用根路径内置 UI。
- debug ping 和内核路由查看要求 daemon 在线。CLI 通过控制接口请求 daemon 执行；系统命令的权限和网络 namespace 取决于 daemon 的运行环境。
- HealthView 已从 Targets/Samples 分列改为统一 `links` 行；Links 查询使用扁平摘要和统一 JSON 名称。Health 不再附带原始 instance，Links 不再输出 owner token。仓库前端已同步；外部客户端必须更新字段映射。
- 离线 admission 和 sync 数据来自 checkpoint / last-known，只表示上次已知状态，不能作为实时在线结果。
- 禁用路由会停止新的 reconcile，不自动拆除之前创建的资源。需要拆除时须显式执行相应运维操作，不能把 disabled 当作资源清理。
- `debug db dump` 支持当前嵌套 bucket；指定 zone 时解码当前 VerifiedState 并只输出该 zone。`stats` 递归统计叶子键及键值逻辑字节数（不是磁盘分配量）。读取锁等待约一秒后报错；daemon 持有数据库时应停止 daemon 或使用一致的数据库副本。
- Links/rotate 内部诊断字段 `StoredSAs` 改为 `ReconcileSAs`、`ReplannedDesired` 改为 `LastDesiredCount`：它们来自最近一次 reconcile 的内存观察，不是 DB 持久值或当前重新规划的结果。控制接口直接消费这些诊断字段的客户端也须更新。
