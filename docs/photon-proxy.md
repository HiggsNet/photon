# Photon Proxy

`photon-proxy` 提供一个本地 SOCKS5 入口和一个远端 TrustTunnel HTTP/2 出口。节点之间使用 TCP 和双向 TLS，转发 TCP 连接和 UDP 数据报。固定端点模式可以独立运行，部署时直接使用入口节点可通过 TCP 拨通的出口地址。

## 构建

```sh
go build -o build/photon-proxy ./app/photon-proxy
```

也可以使用 `make build` 或 `make install`。

## 出口节点

准备 PEM 格式的出口证书和私钥，以及用于验证客户端证书的 CA。出口证书的 SAN 要包含客户端使用的服务器名称或 IP，并具有服务器认证用途。客户端证书需要客户端认证用途。建议为代理客户端使用专用 CA，该入口接受这个 CA 签发的客户端证书。

```sh
photon-proxy serve \
  -listen 0.0.0.0:8443 \
  -tls-cert egress.pem -tls-key egress.key -client-ca client-ca.pem \
  -allow 10.42.1.0/24,2001:db8:1::/64
```

`-allow` 明确列出当前入口接受的目的前缀，所有获准证书共享这份列表。用真实目标前缀替换示例，也可只允许单个 IPv4 `/32` 或 IPv6 `/128`。TCP 域名由出口解析，出口对实际拨号地址检查前缀。UDP 按每个数据报的目的 IP 和端口识别会话，并检查目的 IP 是否获准。

## 客户端节点

```sh
photon-proxy socks5 \
  -listen 127.0.0.1:1080 -server egress.example.net:8443 \
  -tls-cert client.pem -tls-key client.key -server-ca egress-ca.pem
```

本地 SOCKS5 仅监听回环地址，支持 `CONNECT` 和 `UDP ASSOCIATE`。需要通过 IP 拨远端时，可以用 `-server-name` 指定证书中的域名。私钥留在各自节点。SOCKS5 的 UDP 域名由客户端解析，再使用 TrustTunnel 的 IP 数据报格式转发。

连接另外要求 HTTP Basic 认证的 TrustTunnel 出口时，用 `-auth-file` 指定本机凭据文件。文件只放一行 `username:password`，凭据随 TLS 内的代理请求提交。

例如，以下命令通过本地入口访问出口站点的内网 HTTP 服务：

```sh
curl --socks5-hostname 127.0.0.1:1080 http://10.42.1.23:8080/
```

UDP 业务经可靠流跨站传输。`photon-proxy` 为 TCP 和 UDP 业务使用不同的 HTTP/2 连接池；同一 UDP 承载上的丢包重传仍可能增加尾延迟。

## 通过 Gossip 发现代理

在两端 `photon daemon` 的配置中启用只读的本机目录，路径应位于管理员控制的目录内：

```yaml
proxy_directory_socket: /run/photon-proxy/directory.sock
```

目录 socket 权限为 `0660`。代理使用独立系统用户时，可以预建管理员拥有、代理组可遍历的 setgid 父目录，例如 `root:photon-proxy`、模式 `2750`。发布和撤销使用原有管理 socket，运行转发的进程只需访问目录 socket。

两端管理员分别发布自己的代理证书公钥。发起方省略 `-endpoint`，出口填写实际可拨通的 TCP 地址。`-control-socket` 可指定管理 socket，默认读取 `PHOTON_CONTROL_SOCKET` 或使用 `/run/photon/photon.sock`。

```sh
# 入口节点
photon-proxy publish -tls-cert client.pem

# 出口节点，可以使用带 A 和 AAAA 记录的域名
photon-proxy publish -tls-cert egress.pem -endpoint proxy.example.net:8443
```

静态 IPv4 使用 `192.0.2.10:8443`，静态 IPv6 使用 `[2001:db8::10]:8443`。若出口的 `ipsec.announce_addrs` 和 `ipsec.announce_dns` 合计只有一个明确配置的主机，可以改用 `-announce-port 8443`。daemon 会复用其主机名或 IP，并签名发布指定的 TCP 端口。IPsec 的 UDP 端口、自动扫描地址和 NAT 观测走各自的公告。发布目前手动执行，能力默认有效 24 小时，可用 `-ttl` 设置，上限为证书的到期时间。

出口在上一节 `serve` 命令上增加 `-directory-socket /run/photon-proxy/directory.sock -allow-zones client.example.`。入口在上一节 `socks5` 命令上用 `-server-zone exit.example. -directory-socket /run/photon-proxy/directory.sock` 替换 `-server`。示例 Zone 要换成实际 Zone。证书 CA 和证书名称验证仍生效，代理再校验已签名的公钥绑定。出口允许的 Zone 共享本机 `-allow` 目的前缀规则。

代理约每秒刷新本机目录。撤销命令为 `photon-proxy withdraw`，可加 `-expect-version` 避免旧操作覆盖新公告。撤销或者公钥绑定变化被本机目录观察到后，代理拒绝新会话并关闭关联的现有会话。本机目录失联时，最后一次获取的快照有五秒有效期。快照到期后拒绝新会话，并在下一次目录检查时关闭关联的旧会话。各站点看到更新的时间仍取决于 Gossip 收敛。

### 更换出口端口

1. 保持旧监听运行，用同一证书和授权规则在新端口启动第二个 `serve`。从入口使用固定端点模式验证新端口。
2. 验通后重新 `publish` 新地址或 `-announce-port`，可带上旧公告的 `-expect-version`。收到更新的入口用新地址发起新会话，保留原公钥下的旧会话。
3. 待公告收敛和旧连接结束后，停止旧监听器。两个监听器共享同一条 Zone 公告，停旧监听器时保留新公告。

平时可以一直使用固定端口。当前由管理员掌握备好新监听、切换公告和停旧监听这几个动作。

## 一跳中转

入口 `client.example.` 可以经 `relay.example.` 到出口 `exit.example.`。中转单独运行，并发布自己的中转端点：

```sh
photon-proxy publish -tls-cert relay.pem -relay -endpoint relay.example.net:8443

photon-proxy serve -listen 0.0.0.0:8443 \
  -tls-cert relay.pem -tls-key relay.key -client-ca client-ca.pem \
  -directory-socket /run/photon-proxy/directory.sock \
  -allow-zones client.example. \
  -relay-target exit.example.=egress.example.net:8443
```

入口在原来的 `-server-zone exit.example.` 上增加 `-via-zone relay.example.`。证书信任文件要覆盖中转和出口，`-relay-server-name` 可为中转单独指定证书名称。出口继续在 `-allow-zones` 中允许 `client.example.`，因为出口在内层 TLS 中验证到的是原始入口。中转只能看到请求的出口 Zone 和端点，实际 TCP 或 UDP 目标由出口授权。

`-relay-target` 要同时匹配本机允许的 Zone、地址和端口，以及当前签名公告。它可以重复指定；从这个中转切换出口端口时，可以预先允许新旧两个端点。撤回中转公告会关闭经该节点的关联会话。`-via-zone` 是显式路径，失败时该配置返回错误。备用协议见 [后续设计草案](photon-proxy-design.md)。

### 签名委托模式

可信中转可使用逐跳 TLS。B 通过本机证书建立到 C 的 TrustTunnel 连接，并原样转交 A 的签名头。C 验证 B 的 TLS 身份、A 的签名和两端授权，然后按 A 的授权处理请求。B 在这种模式下可以读取它所转发的代理目标和业务数据。

在 A 生成一把专用于委托的 Ed25519 密钥，并在原有代理能力记录中发布公钥：

```sh
openssl genpkey -algorithm ED25519 -out delegation.key
openssl pkey -in delegation.key -pubout -out delegation.pub.pem
photon-proxy publish -tls-cert client.pem -delegation-pubkey delegation.pub.pem
```

- A 在原来的 `socks5 -server-zone exit.example. -via-zone relay.example.` 参数上增加 `-delegation-key delegation.key`。如果需要 UDP，再加 `-delegation-udp-prefixes 10.42.1.0/24`，多个前缀用逗号分隔。
- B 在原有中转 `serve` 命令上增加 `-relay-server-ca egress-ca.pem`。B 的代理证书需要同时支持 TLS 服务端和客户端用途；到 C 的证书名称从 C 公告的地址取得。
- C 在原有出口 `serve` 命令上增加 `-allow-delegates relay.example. -delegation-endpoint egress.example.net:8443`。继续在 `-allow-zones` 配置允许的原始来源，并通过 `-client-ca` 信任 B 的证书。每个监听的 `-delegation-endpoint` 使用自己的公告地址；换端口时给新监听器配置新的地址。

Gossip 同步 32 字节的授权公钥。请求头值最多 512 字节。A 每次建立 TCP 流或 UDP association 时签一次，签名覆盖来源、中转、出口、出口端点和实际 TCP 目标或 UDP 前缀范围。C 对每个 UDP 目的地址同时检查本机规则和签名范围。凭证从签发起有效 30 秒，出口只接受签发时间介于本次监听器启动与当前时刻之间的凭证，并记住已经使用的一次性编号。参与节点需要同步系统时间。每个公告端点由一个验签监听器负责，防重放记录在该进程内维护。
