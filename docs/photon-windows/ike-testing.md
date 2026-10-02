# IKE 基础与认证验收

`internal/photonclient/ike` 分离报文、密码学和 SA_INIT / IKE_AUTH 状态。调用方负责
socket、超时和串行调用；`Request()` 返回独立副本，可原样重传。错误响应不推进
状态。SA_INIT 成功只返回尚未认证的密钥材料，不能授权路由或数据包。

`AuthRequest` 接受调用方预先授权的 FQDN identity、公钥及 CHILD 流量范围快照。
AUTH 使用 Ed25519，验签绑定双方 INIT transcript、nonce 和实际 ID payload。
`HandleAuthResponse` 只有在对端 identity、公钥签名、ESP proposal、双向 traffic
selectors 全部匹配后才返回首个 CHILD 的 SPI 和密钥材料；响应不能扩大请求范围。
导出的 INIT 结果与内部认证状态不共享切片。调用方持有请求报文作原样重传。

协议依据：[RFC 7296](https://www.rfc-editor.org/rfc/rfc7296.html)、
[RFC 7427](https://www.rfc-editor.org/rfc/rfc7427.html)、
[RFC 8420](https://www.rfc-editor.org/rfc/rfc8420.html)。
完成协议认证不代表授权快照仍有效；接入 Daemon 时仍须按当前 revision/时间重新验证
gateway 和路由授权。当前这些接口尚未触发系统路由安装。

当前集合为 AES-CBC-128 / HMAC-SHA256-128 / PRF-HMAC-SHA256 / P-256。
报文大小、payload 数量、nonce 和 PRF+ 均有上限；SK 先校验完整报文 HMAC 再解密。
测试含独立 RFC/NIST/OpenSSL 向量、截断/篡改/非法 padding、proposal 选择和状态推进。

```sh
GOCACHE=/tmp/photon-gocache go test -race ./internal/photonclient/ike
go test ./internal/photonclient/ike -run '^$' -fuzz FuzzDecodeMessage -fuzztime 10s
go test ./internal/photonclient/ike -run '^$' -fuzz FuzzInitPayloads -fuzztime 10s
go test ./internal/photonclient/ike -run '^$' -fuzz FuzzOpenSK -fuzztime 10s
go test ./internal/photonclient/ike -run '^$' -fuzz FuzzVerifyAuth -fuzztime 10s
go test ./internal/photonclient/ike -run '^$' -fuzz FuzzTrafficSelectors -fuzztime 5s
```

Windows 原生测试由 `docs/scripts/windows-native-smoke-build.sh` 打包，复制目录后
用 PowerShell 执行 `run.ps1`，不需要在 Windows 安装 Go。测试包带第三方 notice。

2026-10-02 Windows 11 amd64 VM 原生三包通过，56 个顶层测试/seed suite 通过；
跨主机 Gossip 与 strongSwan 测试按设计默认跳过，后者另由下述隔离容器实测。
Linux 整包 race 与完整 `make check` 通过。三个 fuzz 各跑 10 秒，分别约
121 万、126 万和 86 万次执行，无异常。

## 隔离 strongSwan 互通

```sh
docs/scripts/ike-init-smoke.sh
```

需要 Docker；首次构建 Ubuntu 24.04 测试镜像。可用 `PHOTON_IKE_INIT_IMAGE`
指定已有镜像。容器使用 `--network none`，只在容器 loopback 通信；临时连接不写
proposals，以验证 strongSwan 默认集合。容器和临时目录退出即清理。

2026-10-02 实测 strongSwan 5.9.13 两次通过：Go initiator 发送 184 字节
SA_INIT，收到 200 字节响应，选择上述集合。随后测试故意只发送含 IDi、缺少 AUTH
的加密 IKE_AUTH；strongSwan 成功解密后返回加密 AUTHENTICATION_FAILED（24），
Go 校验响应 SPI/message ID/HMAC 并成功解密。这证明双向密钥派生与 CBC/HMAC
兼容，**不代表身份认证、CHILD SA 或 Windows 隧道成功**。

## 隔离 IKE_AUTH 与首个 CHILD

```sh
docs/scripts/ike-auth-smoke.sh
```

使用同样隔离的 Docker 环境和镜像，支持 `PHOTON_IKE_AUTH_IMAGE` 覆盖镜像。
通过生产 `StrongSwanDriver` 加载临时 Ed25519 私钥和连接，保留 Linux 生成器的
默认 proposals、`encap=yes`、route-based CHILD 和 raw public key 配置。
测试身份只存在于临时容器，不连接生产网关。

Go initiator 和 strongSwan 双方验证 Ed25519 认证，测试再读取 VICI 确认 IKE
`ESTABLISHED` 和 CHILD `INSTALLED`。两方向 AES-GCM key/salt 在内存中与 Linux
XFRM 对比，不输出密钥。错误服务端 pin 必须在 Go 签名校验处失败；错误服务端
identity、客户端私钥由 strongSwan 拒绝。2026-10-02 strongSwan 5.9.13 与
Nix strongSwan 6.0.7 的同一矩阵均实测通过。
IPv4、IPv6 inner selectors 分别建链，使用独立连接/身份/SPI；两种均通过双向
key/salt 对比，outer 均为 IPv4 loopback。原 SA_INIT 加密拒绝测试也回归通过；
新增 signature hash 通知后请求/响应为 194/216 字节。

复用宿主 Nix 构建时，设置 `PHOTON_IKE_AUTH_NIX_PACKAGE` 为包含
`libexec/ipsec/charon` 的完整 `/nix/store/...-strongswan-6.0.7` 路径；脚本只读
挂载 `/nix/store`，在隔离容器中执行该版本，不启动或修改宿主 strongSwan。

本轮完整 `make check`、IKE race 通过。AUTH fuzz 10 秒完成 880339 次、TS fuzz
5 秒完成 272191 次执行，无异常。Windows 11 amd64 原生三包 65 个顶层测试及
5 组 fuzz seed suites 通过；需要外部 peer 的测试仍默认跳过，Linux 隔离测试另行运行。

这是 portable Go 在 Linux loopback 下的真实握手；Windows 原生测试验证同一
协议代码，但尚未在 Windows 与网关之间完成实际 IKE 网络握手。`encap=yes` 的
配置覆盖也不等于 NAT-T 验收：当前未协商 NAT detection、切换 UDP 4500 或传输 ESP。

尚未实现：ESP 数据包处理、Daemon 当前授权绑定、NAT-T、COOKIE retry、
fragmentation、产品重传调度、rekey 和 liveness。
本轮没有接入 Windows Daemon 或更改 Linux 连接生成器/生产网关。
