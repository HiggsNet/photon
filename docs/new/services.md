# Photon Services

本文描述 2026-11 的实现。`photon-services` 独立渲染配置和编排发布；Photon daemon 管理 Gossip、签名、IPAM、路由和 endpoint ACL，容器生命周期由 Docker Compose 或 NixOS systemd 单元管理。

## 三种同级代理

`http`、`socks5`、`trusttunnel` 都使用 Mihomo，分别配置网络、地址、端口、resolver 和 ACL。新格式使用 **`version: 2`**：省略某个 block 就不生成该代理，省略全部则仅生成网络。

| block | 数据面 | 默认端口 | Compose project | 签名目录 |
|---|---|---:|---|---|
| `http` | HTTP 代理、HTTPS CONNECT；不提供 UDP | 3128 | `photon-http` | `service.http.v1` / `services/http` |
| `socks5` | SOCKS5 NO AUTH，TCP CONNECT、UDP ASSOCIATE | 3128 | `photon-socks5` | `service.socks5.v1` / `services/socks5` |
| `trusttunnel` | 仅 HTTP/3，承载 TCP 和 UDP | 4433 | `photon-trusttunnel` | `service.trusttunnel.v1` / `services/trusttunnel` |

每个发布 network 使用一个只连接该 network 的容器，不映射 host 端口。SOCKS5 保持单网络进程，避免 wildcard UDP 回包选错源地址。默认镜像 `metacubex/mihomo:v1.19.34`，可用 `images.mihomo` 覆盖。

## 完整配置

默认文件 `/etc/photon/service.yaml`，可用 `--config` 覆盖。完整示例见 [service.example.yaml](../../service.example.yaml)：

```yaml
version: 2
output_dir: /etc/photon/services
images:
  mihomo: metacubex/mihomo:v1.19.34
network_defaults:
  trusted_host_interfaces: [phv2mesh]
networks:
  main:
    ipv4: "local;172.30.0.0/24;172.30.0.128/28;172.30.0.1"
    ipv6: "auto;::/112;::100/120;::1"
http:
  networks: {main: "::21"}
  publish: {main: local}
  port: 3128
  allow_zones: ["*.catofes."]
socks5:
  networks: {main: "::20"}
  publish: {main: local}
  port: 3128
  allow_zones: ["*.catofes."]
trusttunnel:
  networks: {main: "::22"}
  publish: {main: local}
  port: 4433
  allow_zones: ["*.catofes."]
```

`::20`、`::21`、`::22` 是网络内相对 IPv6 地址。已有网络应保留原来的 subnet、动态池和 gateway，不能因为启用代理而替换正在使用的 Docker network。

- 地址须属于对应 network 的地址族，不能是 subnet 基址、IPv4 broadcast、gateway 或动态池地址。不同代理不能共用容器 IP，即使端口不同。
- `publish` 将 network 映射到 region，`local` 表示固定节点。HTTP/SOCKS5 可发布多个本地或 shared Anycast endpoint；TrustTunnel 首版只支持普通非 shared assignment 的 `local`。
- 每个 block 的 `resolver` 默认 `mode: ipv4_first`、`servers: [8.8.8.8, 1.1.1.1]`。还支持 `ipv6_first`、`ipv4_only`、`ipv6_only`；`*_first` 允许另一地址族回退，`*_only` 限制域名解析结果。显式 IP 目标不依赖域名解析。
- HTTP 默认无应用层认证，可选 `http.auth: {username: ..., password: ...}`，两项须同时填写。密码仅写入本机权限 `0600` 的 Mihomo 配置，不进入 Gossip 或客户端目录。
- `images.gost`、`socks5.http_auth` 是旧格式字段，v2 会提示改用 `images.mihomo`、`http.auth`。

### 网络描述符

描述符为 `来源;subnet;动态池;gateway`：

- `local` 只创建本机网络，不能发布该地址族的服务入口。
- `auto` 选同地址族唯一的 active、非 shared assignment。
- `assignment:<prefix>` 选择精确 assignment。
- `tag:<tag>` 选择 shared assignment 的稳定 tag；同一 tag 在每个地址族中须唯一。
- IPv6 的 `::/112`、`::100/120`、`::1` 相对所选 assignment 解析。路由宣告的是完整 assignment，不是容器 subnet 或 `/128`。

`network_defaults.trusted_host_interfaces` 可在单个 network 覆盖，须使用实际 host 侧 overlay 入接口。发布地址族设置 `gateway_mode_ipv4/ipv6: nat-unprotected`，允许 overlay 直达未映射到 host 的代理端口。该模式下访问边界是 Photon endpoint ACL，trusted interfaces 本身不构成限制；network-only 不自动启用这一模式。

## 渲染、启动、发布

发布节点 daemon 和 CLI 都须支持相应 record。HTTP、TrustTunnel 使用独立控制方法，新 CLI 连接旧 daemon 会明确失败，不会误发布成 SOCKS5。

```bash
photon-services validate
photon-services render
# 新建网络时执行；已有网络不要删除或重建。
docker compose -f /etc/photon/services/networks/docker-compose.yml up -d
# 在监听端口启动之前安装 ACL。
photon-services prepare
docker compose -f /etc/photon/services/http/docker-compose.yml up -d
docker compose -f /etc/photon/services/socks5/docker-compose.yml up -d
docker compose -f /etc/photon/services/trusttunnel/docker-compose.yml up -d
photon-services publish
photon service mine
```

只启动已配置代理的 Compose。artifact 分别位于 `http/`、`socks5/`、`trusttunnel/`，网络位于 `networks/`。工具不会自行启动容器。

`--only http,socks5,trusttunnel` 可过滤 validate/render/prepare/publish 的协议集合，`--only none` 只生成网络，不改输入文件。`withdraw` 使用已发布锁，撤销全部已发布代理，即使该 block 已从当前配置删除。

### 就绪与记录

- HTTP 通过实际代理完成 HTTPS 请求，验证 CONNECT、TLS、出口及配置的认证。
- SOCKS5 验证 TCP 监听和实际 UDP ASSOCIATE/DNS，检查回包源、端口、DNS 事务和答案。
- TrustTunnel 严格校验证书的 HTTP/3 `_check` CONNECT，再通过 `_udp2` 完成 UDP DNS；HTTP/2 回退不算就绪。

通过后刷新 ACL、宣告 shared 路由、发布签名 record、保存 `published.json`。`resolved.json`/`published.json` 是本机锁，不进入 Gossip；render 后配置、assignment、端点或 TrustTunnel 身份变化时须重新 render。

自动客户端校验签名、当前 IPAM 授权和 active 状态，生成 HTTP/SOCKS5/TrustTunnel 节点。HTTP 不标记 UDP。自定义认证的 HTTP 仅发布 `auth_required:true`，自动配置跳过这些节点，客户端须另行填写凭据；不会猜测默认密码。

## 撤销与路由

```bash
photon-services withdraw
docker compose -f /etc/photon/services/http/docker-compose.yml down
docker compose -f /etc/photon/services/socks5/docker-compose.yml down
docker compose -f /etc/photon/services/trusttunnel/docker-compose.yml down
```

先将 record 设为 `active:false`，再删除 ACL 和 shared 路由。HTTP/SOCKS5 共用 shared assignment 时最终只撤销一次该 prefix，更新一个代理也不会撤销另一个仍用的 shared 路由。普通非 shared assignment 通常由 daemon 的 `ipam.announce: [non-shared]` 持续管理，服务停止不撤销它。

更改启用集合时，应先撤销旧发布、停止被删除的 Compose，再 render/prepare/启动新集合并 publish。`render` 不会删除已有文件或停止容器。

## Endpoint ACL

每个地址使用 IP-scope ACL：`http-<network>`、`socks5-<network>`、`trusttunnel-<network>`。`allow_zones` 不进入公开记录。daemon 按当前 active、授权的 route announcement 解析来源前缀，先允许匹配来源，再对服务 IP 精确 drop；没有匹配来源时仍保留 drop。要求启用 managed host firewall，支持 nftables 或 iptables。

| selector | 范围 |
|---|---|
| `node.catofes.` | 精确 Zone |
| `*.catofes.` | `catofes.` 及全部子 Zone |
| `*.` | 全部非 root Zone |

HTTP/SOCKS5 省略 `allow_zones` 表示显式 unrestricted；TrustTunnel 必须配置。不要在代理 IP 上运行安全边界不同的应用。

## TrustTunnel 身份与 UDP

首次 render 生成一年期 ECDSA 自签证书，后续复用 `trusttunnel/tls/`。私钥权限 `0600`；目录只携带 SNI 和证书 DER 的小写 SHA256 指纹。文件不完整、证书/密钥不匹配或过期会报错，不自动旋转运行中的身份；到期前须安排换证、render 和重新发布。

用户名 `photon`、空密码是公开协议标识，入口权限依靠 Photon/IPsec 和 endpoint ACL。客户端固定 `quic:true`、`udp:true`，校验指纹并绑定 Photon 适配器。HTTP/3 仍使用 TLS；UDP 采用可靠 stream 封装，不是 QUIC DATAGRAM，丢包可能等待重传。路径须放行 UDP，当前没有 HTTP/2 回退。

## NixOS 部署

`services.photon.serviceDeployment.settings` 直接映射 YAML。三个 `enable` 默认从非空 block 推断，也可分别设置 `http.enable`、`socks5.enable`、`trusttunnel.enable`；全部关闭时仅管理网络。

外部 `configFile` 不能在 Nix 求值时预读，须显式设置三个开关；为兼容旧部署，外部配置的 SOCKS5 默认 true，HTTP/TrustTunnel 默认 false。含密码时用外部 secret 文件，不要放入公开 Nix store。

依赖顺序：render → networks → prepare ACL → 各独立代理 → publish。发布单元依赖全部已启用代理，HTTP-only 和 TrustTunnel-only 不依赖 SOCKS5。`withdrawOnStop`、`stopContainersOnStop` 控制停止行为。改变现有 Docker bridge 的不可变选项前，须先安排维护迁移。

## v1 兼容与迁移

未写 version 或 `version: 1` 且未显式配置 `http` 时保留旧语义：`socks5` 附带基址加一的 HTTP 地址，默认认证仍为 `photon/2a0d`，兼容 `socks5.http_auth`。保留旧 `photon-socks5` project 和 `h2` 服务名，实际后端统一为 Mihomo。原 shared tags、端点及 SOCKS5 record schema 不变。

迁移到 v2 时，把旧 HTTP 地址写入顶层 `http.networks`，认证迁到 `http.auth`，删除 `images.gost`。v2 的 `socks5` 不再占用相邻地址或生成 `h2`。先撤销旧发布并停止旧 Compose，再启动独立 HTTP project，避免地址冲突。

## 验证

相关 Go 包：`go test ./app/photon-services ./pkg/service ./pkg/core/state ./internal/inspect ./internal/mihomoproxy ./internal/photonwindows ./app/photon`。

真实入站测试设置 `PHOTON_MIHOMO_TEST_BINARY=/path/to/mihomo`，运行 `TestMihomoPlainProxyInterop`，覆盖 HTTP forward/CONNECT、认证、SOCKS5 TCP、IPv4/IPv6 多目标 UDP、32–8192 字节载荷。通过实际请求等待首次规则加载，而不是只等端口打开。

TrustTunnel 测试 `TestTrustTunnelMihomoInterop` 使用 `PHOTON_TT_TEST_ADDRESS`、`PHOTON_TT_TEST_NAME`、`PHOTON_TT_TEST_CERT`、`PHOTON_TT_TEST_PIN`、`PHOTON_TT_TEST_MIHOMO`；可加 `PHOTON_TT_TEST_IPV6`。远端可用 `PHOTON_TT_TEST_TCP_URL`（返回 `trusttunnel-tcp-ok`）、`PHOTON_TT_TEST_UDP4`、`PHOTON_TT_TEST_UDP6` 指定隔离回显目标。

原有 `sudo make services-smoke` 覆盖真实 Docker bridge、ACL、TCP/UDP、BIRD/Babel，见 [testing.md](testing.md)。公网就绪探针不替代长期监控；失败时检查 assignment、地址冲突、网络模式、ACL、路由及回程，并查看实际日志。
