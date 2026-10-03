# ESP 与 NAT-T 验收

本阶段承接 [IKE 认证验收](ike-testing.md)，验证协商后的密钥能处理真实数据包。
协议核心位于 `internal/photonclient/esp`，NAT-T 编码与协商位于
`internal/photonclient/ike`；两者不管理 Windows 路由、Wintun 或 Gossip 生命周期。

## 密码学与接收边界

首版为 tunnel-mode IPv4/IPv6、AES-GCM-128、16 字节 tag、4 字节 salt、
8 字节显式 IV、32 位序号且不使用 ESN。每个新协商方向的密钥只能创建一个
发送状态，不得用旧密钥重建发送器并将计数器归零；耗尽序号必须重新协商。

接收方验证 SPI、AEAD、padding、内层 IP 版本和长度后才提交 64 包防重放窗口。
重复、过旧、错误 tag 和畸形报文不能产生明文输出或用伪造的大序号推进窗口。
这些检查不替代调用方对当前身份、TS、路由 origin 和源地址授权的验证。

NAT detection 使用实际 UDP endpoint；结果只是未认证的封装协商信息，不能
授权网关身份或任意地址迁移。UDP 4500 的四零字节 Non-ESP Marker 只属于外层
封装，不进入 IKE header length、HMAC 或 AUTH transcript。ESP 不加该 marker；
单字节 `0xff` keepalive 被分流后忽略，不视为认证后的 liveness。

Sender/Receiver 使用互斥保护序号与窗口，每次调用同步处理一个有大小上限的包，
不启动后台 goroutine。最大 ESP datagram 为 65504 字节、最大内层 IP 为 65470
字节；这是解析/分配上限，不是路径 MTU。真实接口 MTU 仍由后续 packet pipeline
限制。暂不支持 TFC padding、dummy ESP 或 IPv6 jumbogram；IKE_AUTH 显式发送
`ESP_TFC_PADDING_NOT_SUPPORTED`。此层检查 IP 头长度，不校验 IP/ICMP checksum。

实现依据：[RFC 4106](https://www.rfc-editor.org/rfc/rfc4106.html)、
[RFC 4303](https://www.rfc-editor.org/rfc/rfc4303.html)、
[RFC 3948](https://www.rfc-editor.org/rfc/rfc3948.html) 与
[RFC 7296 §2.23](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23)。

## 执行测试

```sh
go test -race ./internal/photonclient/ike ./internal/photonclient/esp
go test ./internal/photonclient/esp -run '^$' -fuzz '^FuzzOpen$' -fuzztime 10s
go test ./internal/photonclient/esp -run '^$' -fuzz '^FuzzAuthenticatedTrailer$' -fuzztime 10s
go test ./internal/photonclient/ike -run '^$' -fuzz '^FuzzNATDatagram$' -fuzztime 10s
bash docs/scripts/windows-native-smoke-build.sh
bash docs/scripts/esp-smoke.sh
```

Windows 测试包包含 composition、CLI、IKE、ESP 四个原生测试程序，执行方式见
[Windows 原生测试](native-testing.md)。真实 strongSwan 数据面验收使用隔离容器，
不改变宿主或生产网关的路由和 IPsec 配置。

`esp-smoke.sh` 默认复用/构建 Ubuntu 24.04 的 strongSwan 测试镜像；可设置
`PHOTON_ESP_IMAGE`。`PHOTON_ESP_NIX_PACKAGE` 可指定宿主已有的完整
`/nix/store/...-strongswan-6.0.7` 包路径，通过只读挂载在容器里运行该版本。
容器使用 `--network none` 和 `NET_ADMIN`，在内部创建 XFRM interface/地址/路由；
退出即清理，不发布宿主端口。

测试使用生产 `StrongSwanDriver` 和默认算法配置（含 `encap=yes`）。Go 在
SA_INIT 中发送 NAT-D，识别网关强制封装，向 4500 发送带 marker 的 IKE_AUTH；
认证成功后用协商的 CHILD key/salt 发 ESP。IPv4/IPv6 内层分别由 Linux 内核
响应 ICMP echo，再通过 XFRM 加密返回，由 Go 验签、解密并检查完整回复。
每个方向验证坏 tag/重复包拒绝；Linux 侧同时核对 XFRM 错误计数增加，之后
合法包仍能收发，避免只靠超时误判。测试外层使用 IPv4 loopback。

## 2026-10-03 验证结果

- Ubuntu strongSwan 5.9.13、Nix strongSwan 6.0.7 均通过上述 IPv4/IPv6 矩阵，
  各约 0.68 秒；每个地址族三次 echo 往返，并接收 Linux 主动发送的 UDP 包。
- 完整 `make check`、IKE/ESP race 通过。独立 Node/OpenSSL 固定向量通过。
- ESP 任意 wire fuzz、认证后 trailer fuzz、NAT-T fuzz 各 10 秒，分别完成
  794246、774763、617135 次执行，无异常。
- Windows 11 amd64 四包原生通过：79 个顶层测试、8 组 fuzz seed suites；
  两个需外部 peer 的 opt-in 测试默认跳过。此次原生运行约 9.66 秒。

上述强制封装覆盖真实 NAT-D/4500/ESP，但环境没有物理 NAT 或多层 NAT。
Windows 原生结果也不替代 Windows 到网关的实际 IKE/ESP 网络测试。

## 未覆盖的产品路径

独立协议测试不等于 Windows 产品已接入隧道。尚需共享 IKE/ESP/Gossip socket
及有界队列接入、当前授权检查、CHILD/IKE rekey、DPD、网络切换、Wintun、
Babel/SADR 和 Windows 到实际网关的端到端验收。
