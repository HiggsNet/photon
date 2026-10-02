# IKE 基础与 SA_INIT 验收

`internal/photonclient/ike` 分离报文、密码学和单次 SA_INIT 状态。调用方负责
socket、超时和串行调用；`Request()` 返回独立副本，可原样重传。错误响应不推进
状态，成功只返回尚未认证的密钥材料，不能授权路由或数据包。

当前集合为 AES-CBC-128 / HMAC-SHA256-128 / PRF-HMAC-SHA256 / P-256。
报文大小、payload 数量、nonce 和 PRF+ 均有上限；SK 先校验完整报文 HMAC 再解密。
测试含独立 RFC/NIST/OpenSSL 向量、截断/篡改/非法 padding、proposal 选择和状态推进。

```sh
GOCACHE=/tmp/photon-gocache go test -race ./internal/photonclient/ike
go test ./internal/photonclient/ike -run '^$' -fuzz FuzzDecodeMessage -fuzztime 10s
go test ./internal/photonclient/ike -run '^$' -fuzz FuzzInitPayloads -fuzztime 10s
go test ./internal/photonclient/ike -run '^$' -fuzz FuzzOpenSK -fuzztime 10s
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

尚未实现：真实 Ed25519 IKE_AUTH、Photon ID/可信 gateway 绑定、CHILD/ESP、
NAT-T、COOKIE retry、fragmentation、产品重传调度、rekey 和 liveness。
本轮没有接入 Windows Daemon 或更改 Linux 连接生成器/生产网关。
