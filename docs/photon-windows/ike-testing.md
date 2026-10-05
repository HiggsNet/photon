# IKE 与 Windows 隧道验收

前半保留各阶段的验收边界；当前实现与 B3 最终矩阵见末尾 2026-10-06 记录。

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

后续 ESP packet 与 NAT-T 验收见 [ESP 测试](esp-testing.md)。
尚未实现：Daemon 当前授权绑定、COOKIE retry、fragmentation、产品重传调度、
rekey 和产品 liveness 调度。空 INFORMATIONAL 协议进展见下节。

## 2026-10-05 空 INFORMATIONAL 存活探测

`InformationalRequest()` 在 AUTH 完成后创建单个 pending 请求，
`PendingInformationalRequest()` 返回原密文副本用于重传；
`HandleInformational()` 验证 SPI、message ID、完整性和空 payload 后提交响应，
或生成对端请求的响应。两个方向独立计数，本地主动请求从 2 开始，对端从 0
开始；只缓存最后一份对端请求及响应，重复请求返回同一密文。32 位序号耗尽
不回绕。错误报文不能消费 ID、覆盖缓存或完成 pending 请求。

依据 [RFC 7296 §1.4](https://www.rfc-editor.org/rfc/rfc7296.html#section-1.4)、
[§2.1–2.3](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.1) 实现该窄范围协议。
调用方仍负责串行调用、endpoint 校验、计时与重传预算；请求超时必须放弃该 SA，
不能跳过未完成 ID。非空 INFORMATIONAL（包括 Delete/Notify）目前明确拒绝，
本实现不构成完整 DPD 或 INFORMATIONAL 引擎。

本轮验证：

- `make check WINDOWS_GO_MOD_CACHE=/home/herbertqiao/go/pkg/mod` 通过，包括
  全量测试、Linux 构建和 Windows amd64 交叉编译；IKE/ESP race 与 diff 检查通过。
- `bash docs/scripts/ike-auth-smoke.sh` 同时运行 AUTH 与 INFORMATIONAL 验收。
  Ubuntu strongSwan 5.9.13 和 Nix strongSwan 6.0.7 均通过 UDP 500 / NAT-T 4500
  两个子用例；各完成 ID 2、3 探测，故意丢弃首响应后原密文重传，校验网关缓存响应，
  最后由 VICI 确认 IKE/CHILD 仍建立。NAT-T 子用例实际协商 NAT-D 并使用 marker。
- Windows 11 amd64 VM 四包原生测试通过，包含本轮双向 ID、认证失败不推进、
  重传缓存及序号耗尽测试；外部 peer 测试继续由独立 rig 验证。

本切片新增约 102 行生产 Go 代码，用于此前不存在的认证后协议交换；仍由现有
Initiator 持有状态，没有新增 socket、goroutine、timer 或平台 owner。
定时 DPD、失败销毁与重连、当前授权绑定、Delete、rekey，以及 Windows 到
网关的真实隧道仍待后续完成。

同轮核对 RC.2：XFRM 十六进制 ID 与 Gossip 历史节点过滤两项修补已在 Windows
分支，patch-id 与 RC 一致；另移植预发布不覆盖 `latest`、GitHub prerelease 标记、
`-rc.N` 校验和 Linux 测试说明。Windows 分支的 VERSION 保持原值，未发布版本。
本轮没有接入 Windows Daemon 或更改 Linux 连接生成器/生产网关。

## 2026-10-06 B3 生命周期与实际 Windows 跨主机验收

此前“未接入 Daemon / 未完成 Windows 握手”等结论是阶段记录。现在 Daemon
使用原有 Gossip UDP owner 分流 IKE、NAT-T ESP 和 gossip；没有第二个 UDP reader。
同一事件循环调度 INIT/AUTH、COOKIE、SKF、DPD、NAT keepalive、CHILD/IKE rekey、
Delete、超时重传和重连。每个方向独立 message ID、单 pending 及末次响应缓存；
重传复用原密文。IKE rekey 切换角色及密钥并转移 CHILD 所有权，ESP 序号不中断。

Windows transport 私钥独立于 common identity，保存在现有 State 数据库；本机发布
实际共享端口与签名 transport 意图。安装/交付时重新验证当前 gateway identity、
pin、contact、TS 和本机签名 transport 意图。撤销、过期、换代及 rebind 先拒绝数据；
无关 gossip revision 不再无条件销毁健康 SA。DNS 复用提示最多 10 秒，不由包流量续期。

资源有明确上限：IKE ingress 16、ESP ingress 64、双 crypto worker、工作/完成队列
各 64、最多 3 个 CHILD（旧 SA 与碰撞候选）、最多 2 个待清理 IKE。peer 发起 CHILD
切换等待有效新 ESP 或旧 CHILD Delete，旧 SA overlap 最多 120 秒；失败最终销毁并重连。
SKF 单次最多 64 片、65507 字节、30 秒，先验完整性后占用重组状态。COOKIE 最多
3 次且不重置总握手预算。控制报文分片目标含 NAT-T marker 为 1200 字节；Windows
逐包 WriteToUDP 为明确的 batch-send 退化路径，每次写最多 1 秒。ESP ingress 不套用
1200 字节 gossip 截断；最终虚拟网卡 MTU/PMTU 属于 B4/B6 的整链路验收。

### 可复现矩阵

- `bash docs/scripts/ike-auth-smoke.sh`：Ubuntu strongSwan 5.9.13；设置
  `PHOTON_IKE_AUTH_NIX_PACKAGE` 后同矩阵运行 Nix strongSwan 6.0.7。
  两者均保留生产连接生成器的默认 proposal；兼容多 proposal、多 transform 和
  INVALID_KE 重试，不通过改窄生产 profile 获得成功。另有明确标识的 P-256 CHILD
  capability 用例，与默认无 PFS 兼容用例分开。
- `TestStrongSwanWindowsTunnel`：outer IPv4/IPv6，两方向 CHILD rekey、旧 CHILD
  Delete，两方向 IKE rekey/角色切换、新 key DPD，每阶段都有实际内核 XFRM IPv4
  ICMP 回包。此前独立 ESP 矩阵继续覆盖 inner IPv4/IPv6。
- `TestStrongSwanSimultaneousChildRekey` 与 `TestStrongSwanSimultaneousIKERekey`
  强制交叉 pending 请求，通过 nonce 裁决冗余 SA、删除旧/冗余 SA，比较 survivor
  XFRM key/salt 并完成新角色 message ID 0 DPD。两版本均通过；重复 Delete 的
  丢响应重传覆盖对端候选尚未注册的时序，不能用两次顺序重协商替代碰撞证据。
- 分片模式强制实际多片 AUTH、乱序/重复和丢响应重传；COOKIE 模式通过保留半开 SA
  触发真实 challenge，再完成 fragmented AUTH。两版本均通过。
- `bash docs/scripts/windows-tunnel-cross-host-smoke.sh`：真实 Windows 11 amd64
  VM 发出共享 UDP，经测试宿主专用 DNAT 端口连接隔离 strongSwan。两版本均通过
  AUTH/NAT-T、DPD、CHILD rekey/Delete、IKE rekey 和跨阶段的四次内核 ESP echo。
  脚本校验清理结果，临时凭据/二进制/容器退出删除；保留日志不输出密钥。
- 最新 B3 Windows 原生包 147 个顶层测试通过（其中 8 个 fuzz seed suites）；
  `make check GO_MOD_CACHE=/home/herbertqiao/go/pkg/mod WINDOWS_GO_MOD_CACHE=/home/herbertqiao/go/pkg/mod`
  通过。首次全量运行的 gossip 计时测试超时，单独复验及全量重跑均通过。
  相关 IKE/Windows race 测试通过。

真实内核 echo 验证用户态 ESP 到 Linux XFRM，不等于 Windows TCP/IP 已经经由
Wintun 路由。当前业务 packet 缺 B4 verdict 默认拒绝，`tunnel_ready=false` 保持诚实；
Wintun/SADR/Babel、系统路由与 SCM 仍须各自完成。没有将这些测试应用到生产网关，
没有 push、打 tag、发布或部署。
