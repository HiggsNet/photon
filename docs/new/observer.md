# Photon Observer（只读 Web 状态控制台）设计与实现

> **本文档状态：2026-07**
> 描述 Photon 只读 observer 的当前实现：`internal/observer` 的 HTTP server / SSE hub / 内嵌静态 UI，`app/photon` 中的配置解析、Provider 接线与事件广播，以及健康时序（local spool）数据源。
> 本文以当前代码为准；与原设计文档（`docs/web-status-dashboard-design.md`）的差异在第 9 节显式标注，原设计文档仅作背景参考。

Observer 是 Photon daemon 的**只读观测面**。它在 daemon 进程内启动一个独立 HTTP 监听，对外提供 REST 快照 API、SSE 事件流和一个零构建的静态 Web UI，用于可视化 daemon 的实时状态（Zone/Peer/Link/Health/Route/BIRD）。它**不接受任何写操作**：所有 API 仅响应 GET，不修改 daemon 状态，也不经过 control socket 的认证通道。

完整配置字段见 [config.md](config.md)，状态来源（stateFile / StateStore 快照）见 [daemon.md](daemon.md)，健康状态与 spool 的产生见 [health.md](health.md)，授权路由集与 BIRD 观测见 [routing.md](routing.md)。

---

## 目录

1. [范围与定位](#1-范围与定位)
2. [配置模型](#2-配置模型)
3. [架构与 daemon 集成](#3-架构与-daemon-集成)
4. [REST API](#4-rest-api)
5. [SSE 事件流](#5-sse-事件流)
6. [静态 Web UI](#6-静态-web-ui)
7. [健康时序数据源（local spool）](#7-健康时序数据源local-spool)
8. [安全模型](#8-安全模型)
9. [已知限制与实现缺口](#9-已知限制与实现缺口)

---

## 1. 范围与定位

### 1.1 职责边界

| 做什么 | 不做什么 |
|---|---|
| 以只读 REST API 暴露 daemon 当前快照（status/zones/peers/links/health/routes/bird） | 不提供任何写接口、不触发 reconcile、不修改状态 |
| 通过 SSE 推送轻量变更通知（仅事件类型，无详情 payload） | 不做事件回放/续传，不保证事件不丢失 |
| 内嵌静态 SPA（`internal/observer/web`），无前端构建步骤 | 不做用户认证/鉴权，依赖绑定地址与外部访问控制 |
| 从本地 health spool（JSONL）聚合短历史时序 | 不内置 TSDB，不查询 remote write 端点，不做跨节点聚合 |

### 1.2 关键原则

- **只读**：所有端点经由 `requireGET` 限制为 GET；Provider 接口只返回快照副本，调用方无法借 observer 触达 daemon 的可变路径。
- **快照而非流式数据源**：REST 返回的是 `snapshotState()` 在请求时刻的读视图；SSE 只发"有变化"的通知，详情由客户端重新拉取 REST 获得。
- **可缺失**：observer 未启用时 `NewServer` 返回 nil，`notifyObserver` 是 no-op，daemon 主流程不依赖 observer 的任何结果。
- **降级友好**：SSE 断线或事件被丢弃时，前端自动退化为 5s 轮询，数据正确性不依赖事件送达。

### 1.3 架构位置

```text
daemon event loop（app/photon/daemon.go）
  └─ notifyStateChanged()                 # 检测到状态变化后
       ├─ notifyObserver("state_changed") # 经 d.observerHub 广播（hub 为 nil 时 no-op）
       ├─ flushFirewallReconcile
       ├─ notifyObserver("route_changed" / "bird_updated")
       ├─ flushRoutingReconcile / flushIPsecReconcile
       └─ notifyObserver("link_updated" / "peer_updated" / "health_updated")

daemon 启动序列（daemon.go run）
  └─ startObserverServer                  # control server 之后、IPsec event watcher 之前
       ├─ newObserverServer → observer.NewServer(provider, cfg)
       ├─ d.observerHub = srv.hub         # 接线广播入口
       └─ httpServer.Serve(ln)            # 独立 goroutine

HTTP 请求路径
  └─ observer.Server.Handler              # internal/observer/server.go
       ├─ /api/v1/*  → Provider 方法（app/photon/observer_server.go 实现）
       ├─ /api/v1/events → Hub.Subscribe（SSE）
       └─ /*         → 内嵌 webFS 静态文件（SPA fallback 到 index.html）
```

---

## 2. 配置模型

observer 的配置段为 `observer.*`（YAML），解析逻辑在 `app/photon/observer_config.go`：

```yaml
# observer:
#   disabled: true
#   listen: 127.0.0.1:8080
#   ui_path: ""
#   event_buffer_seconds: 0
```

| 字段 | 类型 | 默认 | 语义 |
|---|---|---|---|
| `enabled` / `disabled` | bool | 段缺失 = 禁用 | 段存在即启用，除非 `disabled: true`（或旧写法 `enabled: false`）；二者冲突时报错（`enabledFromPresence`） |
| `listen` | `host:port` | `127.0.0.1:8080` | 监听地址；host 不能为空，port 须在 1–65535 |
| `ui_path` | string | `""` | **已解析但未使用**（见第 9 节） |
| `event_buffer_seconds` | int ≥ 0 | `0` | 事件回放缓冲保留时长；`0` 关闭缓冲（见 5.4） |

解析结果 `observerConfig{Enabled, BindAddr, Port, UIPath, EventBufferSeconds}` 在 `startObserverServer` 中被映射为 `observer.Config{Enabled, BindAddr, Port, EventBufferSeconds}`（`internal/observer/server.go`）。

行为要点：

- 段缺失或 `Enabled=false` 时 `startObserverServer` 返回空 cleanup，不监听任何端口。
- 绑定非 loopback 地址时 daemon 记 `observer/non_loopback_bind` warn 日志，提醒管理员自行加访问控制（`observer_server.go:81`）。loopback 判定由 app 层 `isLoopbackBind()` 完成（精确匹配 `127.0.0.1` / `::1` / `localhost`）。
- `observer.Config.IsLoopbackBind()`（`server.go:32`）是另一份判定，基于 `net.ParseIP + IsLoopback`，覆盖整个 127/8；当前仅作为 transport-neutral 的工具方法存在，告警路径用的是前者。

---

## 3. 架构与 daemon 集成

### 3.1 分层

| 层 | 位置 | 职责 |
|---|---|---|
| transport-neutral server | `internal/observer/server.go` | 路由注册、统一响应包装、SSE handler、静态文件服务；不认识 daemon 类型，只依赖 `Provider` 接口 |
| 事件 hub | `internal/observer/hub.go` | 订阅者集合管理与非阻塞广播 |
| app 层接线 | `app/photon/observer_server.go` | `observerProvider` 实现 `Provider`，从 daemon 快照构造各端点数据；`startObserverServer` 生命周期；`notifyObserver` 广播入口 |
| 配置 | `app/photon/observer_config.go` | `observer.*` YAML 解析与校验 |

`Provider` 接口（`server.go:42`）是 server 与 daemon 之间的唯一耦合点：

```go
type Provider interface {
    Status() (any, error)
    Zones(filter string) (any, error)
    Peers(filter string) (any, error)
    Links(filter string) (any, error)
    Health(filter string) (any, error)
    HealthSeries(linkID string, query map[string]string) (any, error)
    Routes() (any, error)
    Bird() (any, error)
}
```

### 3.2 生命周期

- 启动：`daemon.go:226`，在 control server 之后启动。`net.Listen` 失败会**导致 daemon 启动失败**（error 向上返回），其余情况（未启用/配置为空）静默跳过。
- 就绪后：`d.observerHub = srv.hub`，此后 `notifyObserver` 才真正广播。
- 停止：返回的 cleanup 以 5s 超时执行 `httpServer.Shutdown`（graceful）。
- HTTP server 参数：`DefaultHTTPServer` 固定 ReadTimeout 10s / WriteTimeout 30s / IdleTimeout 120s（`server.go:334`）。注意 SSE 长连接不受 WriteTimeout 影响的前提是响应持续 flush——当前实现对每条事件立即 `Flush`。

### 3.3 数据来源

所有 Provider 方法都经由 `d.snapshotState()` 读取 stateFile 的提交快照（StateStore 存在时为 committed 视图），因此 observer 看到的是与 reconcile 一致的读视图，不会阻塞事件循环的写路径。各端点与数据族的对应关系见第 4 节。

### 3.4 错误模型

- Provider 返回 `observer.APIError{StatusCode, Err}`（或 `observer.Errorf`）时，HTTP 状态码取 `StatusCode`；其余错误一律 500（`writeProviderResult`，`server.go:138`）。
- 统一响应包装为 `APIResponse{ok, error, data}`；成功时 `ok=true` 且 `data` 为 Provider 返回值，失败时 `ok=false` 且 `error` 为错误消息。
- 非 GET 方法 → 405；未匹配的 `/api/` 路径 → 404（由 `HandleStatic` 中的 `/api/` 前缀检查兜底，`server.go:272`）。

---

## 4. REST API

路由注册见 `Server.Handler()`（`server.go:106`）。带 `{filter}` 的端点通过 `pathFilter` 截取路径后缀作为过滤参数，空 filter 表示列表。

### 4.1 端点总览

| 端点 | Provider 方法 | 数据内容 | 响应类型（`internal/inspect/http`） |
|---|---|---|---|
| `GET /api/v1/status` | `Status` | daemon 全局摘要 | `StatusResponse` |
| `GET /api/v1/zones` | `Zones("")` | Zone 树摘要列表 | `ZonesResponse` |
| `GET /api/v1/zones/{zone}` | `Zones(zone)` | 单 Zone 详情（含 history）；根 zone `.` 无法作为路径段（ServeMux 会重定向），用 `GET /api/v1/zones?zone=.` | `inspect.BuildZoneDetail` 输出 |
| `GET /api/v1/peers` | `Peers("")` | 全部 peer 同步状态 | `PeersResponse` |
| `GET /api/v1/peers/{peer_id}` | `Peers(peerID)` | 单 peer 详情 | `PeerJSON` |
| `GET /api/v1/links` | `Links("")` | link 实例与 reconcile 状态 | `LinksResponse` |
| `GET /api/v1/links/{link_id}` | `Links(linkID)` | 单 link 详情 | `LinkJSON` |
| `GET /api/v1/health` | `Health("")` | 全 link 健康 + 上下文 | `HealthResponse` |
| `GET /api/v1/health/{link_id}` | `Health(linkID)` | 单 link 健康（按 instanceID 或 probeID 匹配） | `HealthContextItem` |
| `GET /api/v1/health/{link_id}/series` | `HealthSeries` | 本地 spool 聚合时序 | `HealthSeriesResponse` |
| `GET /api/v1/routes` | `Routes` | 授权路由集 | `RoutesResponse` |
| `GET /api/v1/bird` | `Bird` | BIRD 实例观测 + 最近路由错误 | `BirdResponse` |
| `GET /api/v1/events` | —（Hub） | SSE 事件流 | `text/event-stream` |
| `GET /api/v1/events/recent` | —（Hub） | 事件回放缓冲（见 5.4） | `{"events": [...]}` |

### 4.2 全局状态 `/api/v1/status`

`StatusResponse`（`internal/inspect/http/status.go`）字段：

| 字段 | 含义 |
|---|---|
| `peer_id` / `managed_zone` / `listen_addr` | 本节点身份与 gossip 监听地址 |
| `daemon_online` | `Sync`/state 可用时为 true；否则整个响应只有 `daemon_online: false` |
| `state_revision` | common Store 的 verified revision |
| `last_link_error` / `last_routing_error` | 当前 daemon observation 中的 reconcile 错误 |
| `known_zones` / `known_peers` | `state.Network.Zones` / `state.SyncPeers` 计数 |
| `link_instances` / `desired_links` | 实际 link 实例数 vs IPsec reconcile 期望数 |
| `last_sync_unix` | 所有 peer 中最大的 `LastSyncUnix` |
| `last_reconcile_unix` | `max(ipsec_last_run, routing_last_run)`（由 `BuildStatusResponse` 合成） |

### 4.3 Zones / Peers

- 列表：`ZonesFromNetwork(state.Network, now)`；单 Zone：`inspect.BuildZoneDetail(..., IncludeHistory: true)`，未命中返回 404 `zone not found`。
- Peer 列表由 `inspectPeerSetInput` + `BuildPeerIDs` 汇总（bootstrap 配置 + SyncPeers + 发现路径），单 peer 带 `configured_addr` / endpoints / backoff / 统计；未命中且不在已知集合时返回 404 `peer not found`。

### 4.4 Links

- 数据由 `buildLinkInspectionFromReconcile(runtime, state, healthStatus)` 现算，输入为 IPsec reconcile 的 desired/actual 视图叠加快照中的健康状态。
- 单 link 按 `LinkJSON.ID` 精确匹配，未命中 404 `link not found`。

### 4.5 Health

- 列表：`d.healthStatusResponse()`（health.Manager 快照）经 `inspecthttp.BuildHealthContext` 与 `state.LinkInstances`、IPsec desired state 做 join；每条输出 `HealthContextItem{health, instance, desired, peer_zone, group_id, interface_name, endpoint, actual_state, local_tunnel_addr, peer_tunnel_addr}`，按 `(instance_id, probe_role)` 排序。只有实例没有健康数据的 link 以 `state: "unknown"` 补齐。
- 响应同时携带 `datasource` 信息（见第 7 节），前端据此决定是否展示历史曲线。
- 单 link：`link_id` 可匹配 `instance_id` 或 `probe_id`（含 `#old` / `#staged` 后缀形式），未命中 404。

### 4.6 Routes / Bird

- `Routes`：`routing.BuildAuthorizedRouteSet(state.Network, now)` 现算授权路由集，再经 `RoutesFromAuthorizedSet(state.ManagedZone, ars)` 输出；不读 BIRD 的实际 RIB。
- `Bird`：直接返回 daemon `LinuxObservation` 中的 BIRD instance 快照与最近 routing error；实例数据由 routing reconcile 周期性重建（见 [routing.md](routing.md)）。

---

## 5. SSE 事件流

### 5.1 协议

`GET /api/v1/events` 返回 `text/event-stream`：

- 连接建立后立即发送 `event: connected`，payload 为 `{"type":"connected","payload":{"client_id":"sse"}}`。
- 之后每个广播事件以 `event: <type>\ndata: <Event JSON>\n\n` 帧发送，逐条 flush。

### 5.2 Hub 机制（`internal/observer/hub.go`）

- 每个订阅者一个 **buffer=16** 的 channel；`Subscribe` 返回 channel 与 unsubscribe 闭包（从 map 删除并 close）。
- `Broadcast` 为**非阻塞**：channel 已满的慢客户端直接丢弃该事件，前端靠轮询兜底恢复；调用方未填时间戳时由 hub 填入（`Event.Time`，unix 秒）。
- 事件体 `Event{Type, Time, Payload}` 刻意轻量：payload 只携带 id（列表），不带 diff、不带大对象；客户端收到事件后重新拉取对应 REST 快照。

### 5.3 事件 payload 与触发点

大部分事件都在 `notifyStateChanged()`（`app/photon/daemon.go`）中按固定顺序发出；`health_updated` 另有一个 `handleHealthUpdate`（health reconcile 路径）触发点：

| 事件 | 触发位置 | Payload | 含义 |
|---|---|---|---|
| `connected` | SSE 连接建立 | `{client_id}` | 握手帧（hub 之外，由 handler 直写） |
| `state_changed` | `notifyStateChanged` 入口 | nil | stateFile 发生替换（Zone digest 变化等） |
| `route_changed` | firewall flush 之后 | nil | 路由相关数据可能已变 |
| `bird_updated` | 同上 | nil | BIRD 观测数据可能已变 |
| `link_updated` | routing/IPsec flush 之后 | `{link_ids: [...]}`（state.LinkInstances 键） | link 实例/SA 状态可能已变 |
| `peer_updated` | revocation 二次清理之后 | `{peer_ids: [...]}`（state.SyncPeers 键） | peer 列表/状态可能已变 |
| `health_updated` | 同上；及 `handleHealthUpdate` | `{link_ids: [...]}`（health.Manager 快照 targets） | 健康状态可能已变 |

注意：事件语义是"**可能**有变化，请重新拉取"；广播点是批量通知（`healthUpdates` 通道为 `chan struct{}`、flush 为全量 reconcile），拿不到单一条目 id，因此 payload 是快照派生的 id 列表而非单条 id。事件在 `drainingEvents` 时仍会在入口发 `state_changed`，后续事件被跳过（直接返回前）。

### 5.4 事件回放缓冲与 `/api/v1/events/recent`

- `observer.event_buffer_seconds > 0` 时 hub 启用回放缓冲：每次 `Broadcast` 先 prune 掉早于 `now - N` 秒的事件再追加，另有 1024 条硬上限防内存膨胀；`== 0`（默认）关闭缓冲，保持原语义。
- `GET /api/v1/events/recent` 经 `requireGET`，返回 `{"events": hub.Recent()}`（按时间升序的副本）；缓冲关闭时返回空列表而非错误。
- 前端 Events 页消费该端点，且任意 SSE 事件到达都会使 `/events/recent` 键失效重取。

---

## 6. 静态 Web UI

### 6.1 服务方式

- UI 文件经 `//go:embed all:web` 内嵌进二进制（`internal/observer/web/`：`index.html`、`style/{tokens,base,pages}.css`、`src/` 原生 ES modules），无外部静态目录、无构建步骤。
- `HandleStatic`（`server.go:250`）：GET 之外 → 405；`/api/` 前缀 → 404；路径清洗后读 `web/<path>`，未命中时 **fallback 到 `index.html`**（SPA 前端路由的前提）；按扩展名设置 Content-Type（html/css/js/json/svg，其余 octet-stream）。
- `WebSubFS()` 暴露 `web/` 子树供测试使用。

### 6.2 前端行为（`web/src/`）

- 零构建原生 ES modules SPA：`main.js` 入口装配 `router.js`（hash 路由）+ `events.js`（SSE）+ `store.js`（按 endpoint 的缓存/失效/订阅）；页面模块在 `src/pages/*`，纯函数组件在 `src/components/*`，所有动态文本经 `src/format.js` 的 `esc()`。
- hash 路由携带选中态与过滤条件（`#/<page>[/<selection>][?f=<filter>]`），可深链、刷新不丢；8 个页面：Overview / Gossip / Zones / Overlay · Control Plane / Routes / BIRD / Health · Data Plane / Events（时间线页数据源为 `/events/recent`，需 `event_buffer_seconds > 0` 才有内容）。
- 每页声明依赖的 endpoint（`deps`），store 负责拉取与并发去重：overview→status/links/health/zones，gossip→peers，zones→zones，overlay→links，health→health，routes→routes，bird→bird/status。
- 连接策略：`EventSource('/api/v1/events')` 收到 `connected` 后置为 **Live**；事件按类型→endpoint 映射只失效并重取对应键（如 `link_updated`→`/links`、`health_updated`→`/health`），不再整页刷新；携带 id 列表 payload 的事件（`peer_updated`/`health_updated`）还会做**条目级失效**——gossip 选中 peer 的详情缓存与 health sparkline 缓存只重取受影响条目；任意事件同时失效 `/events/recent` 键；`onerror` 时降级为 **Polling**（5s 轮询当前页依赖的键），并每 10s 尝试重建 SSE；侧栏指示器显示 Live / Polling / Disconnected 三态。
- 重绘前记录 `#content` 的 scrollTop / 活跃输入框 / `<details open>` 状态，重绘后恢复（取代早期 foldState 补丁）。
- Health 页 sparkline 在卡片可见时才懒加载 `/health/{id}/series?metric=rtt&range=30m&step=1m`，详情图按 5m/30m/1h/6h/24h 档位手动加载（step 10s–30m）；series 有多条 `lines` 时按 probe 视角分线，否则退化为单条 active 线。

---

## 7. 健康时序数据源（local spool）

series 端点的数据完全来自 health 子系统的本地 JSONL spool（产生侧见 [health.md](health.md) 第 8 节），查询实现在 `app/photon/health_spool.go`：

- 配置前提：`health.metrics` 启用且 `local_spool_path` 非空（`healthSpoolConfigured`）；未配置时 series 返回 **503 health datasource not_configured**，`datasource` 信息为 `{configured: false, type: "none"}`。
- 查询参数（`/api/v1/health/{link_id}/series`）：

| 参数 | 默认 | 约束 |
|---|---|---|
| `metric` | `rtt` | `rtt`(ms) / `loss`(percent) / `jitter`(ms) / `state`(code)；`babel_rtt`、`babel_metric` 显式报"not available yet"；其余 400 |
| `range` | `1h` | 正 duration；超过 `local_spool_max_age` 时截断到 max_age |
| `step` | `30s` | 正 duration；最小 1s，大于 range 时取 range |
| `probe_role` | （全部） | 非空时按样本 `probe_role` 过滤 |

- 聚合：读取 `samples.jsonl` 中该 `instance_id` 在 `[now-range, now]` 的样本，按 step 分桶取**平均值**（`bucketHealthSamples`），同时按 probe（`probe_id`，缺省回退 `healthProbeID(instance_id, probe_role)`）拆出 `lines[]`；`state` 指标编码为 healthy=0 / degraded=1 / down=2 / unknown=3 / probe_error=4 / suppressed=5。
- 参数非法（duration 解析失败、非正数、未知 metric）→ 400；spool 未配置 → 503。
- spool 写入与 prune（`local_spool_max_age` 截断、tmp+rename 原子替换）在 health reconcile 路径完成，observer 只读不改。

---

## 8. 安全模型

- **无认证**：observer 没有任何 authn/authz。设计文档预留的 `auth.*`（static_token/mTLS）未实现。
- 默认绑定 `127.0.0.1:8080`，仅本机可达；绑定非 loopback 地址时仅有 warn 日志，访问控制完全交由部署方（防火墙、反向代理等）。
- **只读保证**来自两层：HTTP 层 `requireGET` 拒绝一切非 GET；Provider 只读 `snapshotState()` 快照与 health.Manager 快照，不持有任何可变句柄。daemon 的变更操作仍只走 control socket（有独立认证），observer 与其完全隔离。
- 静态文件服务的路径清洗只做 `TrimPrefix("/")` 与 embed FS 查找：embed FS 内容在编译期固定，不存在目录穿越面；`/api/` 前缀被显式拦截，避免 API 路径被 SPA fallback 吞掉。

---

## 9. 已知限制与实现缺口

| 项 | 现状 |
|---|---|
| `observer.ui_path` | 已解析、归一化（补前导 `/`），但 server 始终从根路径提供内嵌 UI，该值无任何消费方 |
| `observer.event_buffer_seconds` | 已实现：hub 回放缓冲按时间窗保留（1024 条硬上限），`GET /api/v1/events/recent` 提供回放（见 5.4） |
| SSE 续传 | 未实现 `Last-Event-ID`；断线期间的事件不重发，依赖前端轮询兜底 |
| 设计中的部分端点 | `/api/v1/link-groups`、`/api/v1/zones/{zone}/records|delegations|revocations` 未实现（`/zones/{x}/records` 会被当作 zone filter 而 404） |
| Events 页面 | 已实现：Events 时间线页消费 `/events/recent`；SSE 续传（`Last-Event-ID`）仍未实现，断线期间靠轮询兜底 |
| 事件 payload | 已实现 id 列表级 payload（`link_updated`/`health_updated` → `{link_ids}`、`peer_updated` → `{peer_ids}`），前端据此做条目级失效；无 diff、无单条精确 id（广播点为批量通知） |
| `babel_rtt` / `babel_metric` series | spool 尚不含 BIRD 观测样本，查询显式报错 |
| 非 loopback 保护 | 仅 warn 日志，无绑定确认开关或强制拒绝 |
| 时序留存 | 短历史完全取决于 health spool 的 `local_spool_max_age`；spool 未配置时 Health 页无曲线 |

测试覆盖：`internal/observer` 的 `hub_test.go`（订阅/广播/慢客户端）、`events_test.go`（SSE 帧）、`server_method_test.go`（非 GET 拒绝）、`static_test.go`（静态服务与 SPA fallback）、`webapp_test.go`（内嵌资源完整性）；`app/photon` 的 `observer_config_test` 族（随配置测试）、`observer_server_test.go`（启动/事件广播）、`observer_api_status_test.go` 与 `observer_api_resources_test.go`（各端点响应与 404/405 行为）。

---

## 10. 未来扩展与历史决策

本节保留原设计文档中关于后续演进方向的记录，便于在扩展 observer 时参考。当前实现均未落地。

### 10.1 未来控制接口预留

observer 当前只读。若后续需要支持 Web 控制，建议按以下阶段引入认证与审计，而不是直接开放无认证写接口：

1. **静态 Token**：`observer.auth.mode: static_token`，请求头携带 `Authorization: Bearer <token>`。
2. **Unix Socket 模式**：HTTP server 可改为监听 Unix Domain Socket，与 control socket 类似，便于 Nginx/反向代理接入。
3. **mTLS**：通过 `client_ca_file` 验证浏览器证书。
4. **审计日志**：所有写操作记录到结构化日志，包含操作人、来源 IP、操作内容摘要。

### 10.2 BIRD 深度集成计划

当前 `/api/v1/bird` 只返回 routing observation 中已有的字段。后续可扩展 `birdc` 输出，新增：

- `/api/v1/bird/protocols`
- `/api/v1/bird/neighbors`
- `/api/v1/bird/routes`

并在 UI 上：

- Route 页面增加「控制面路由 vs 数据面学习路由」对比视图。
- Health 页面把 BIRD neighbor RTT/metric 与 Photon probe RTT/loss 放在同一 link 详情里对比。
- 增加前缀树 / 路径分析图。

### 10.3 metrics/remote write 与 observer 的关系

当前 health series 完全来自本地 JSONL spool。原设计预留了更灵活的时序后端：

- 可接入本机 **VictoriaMetrics** / Prometheus-compatible API 或 push pipeline，作为 `/api/v1/health/{link_id}/series` 的 datasource。
- 即使接入外部 TSDB，observer 也不得把前端传入的任意 PromQL 直接透传给 TSDB；只允许固定 metric 枚举、固定 label filter 和受限 time range，避免 observer 变成通用 TSDB proxy。

### 10.4 MVP 决策记录

observer 第一版实现前已决策的关键问题：

1. **前端技术栈**：第一版采用原生 HTML/CSS/JS，不引入 Node.js 构建链；拓扑图库后续增强时再引入。
2. **默认启用策略**：未声明 `observer:` 时默认关闭；声明后默认监听 `127.0.0.1:8080`，可用 `disabled: true` 暂停。
3. **离线诊断子命令**：第一版只提供 daemon 内嵌 observer；独立的 `photon observer` 离线 DB viewer 延后到后续阶段。
4. **SSE 持久化/回放**：SSE 仅做实时通知，不持久化、不重放；前端断线后自动降级为 5s 轮询。
5. **拓扑图优先级**：第一版以表格 + raw JSON 为主，可视化拓扑图留到后续增强。

### 10.5 Web UI 重构

现有 UI 的视觉与信息架构重构设计已定稿，见 [observer-ui-redesign.md](observer-ui-redesign.md)：零构建约束下以原生 ES Modules 模块化前端、建立设计 token 体系、逐页重构信息架构（Overview 仪表盘化、Overlay/Health 职责分离、Zones 双栏 + Inspect 折叠），并可选补完事件 payload 与 Events 时间线页。实施任务见 `../../todo.md` Phase 9。
