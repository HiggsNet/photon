# ranet-lite 移植范围与来源记录

状态：B3 实现前决策完成；尚未导入第三方源码、依赖或实现 IKE。核对日期：2026-10-02。

本次重新读取 [NickCao/ranet-lite 固定提交](https://github.com/NickCao/ranet-lite/tree/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5)
`24a24a2ff380c9f8ceb0092d640daa32e86b5eb5` 的实际源码、LICENSE、go.mod 与 go.sum。
采用局部移植协议代码、重写产品接线的方式；不直接依赖或 fork 整个产品，也不要求 Linux 为迁就该原型改算法。
原有 [Lite 调研](../photon-lite-research.md) 是背景材料，以下结论以锁定源码和
[Windows design §1.2 的 Linux 兼容基线](design.md#12-linux-算法兼容基线2026-10-01-现场与隔离验证) 为准。

## 1. 来源与可复核证据

检查目录为临时 detached checkout，HEAD 与上述完整 hash 一致，工作树干净。依赖下载到独立
临时 module cache，`go mod verify` 返回 `all modules verified`。
`GOOS=windows GOARCH=amd64 go list -deps ./...` 成功列出依赖图；这只是依赖分析，
本次未将其解释成 Windows 编译、运行或协议安全验收，也未重跑旧调研所记的全部上游测试。

| 文件 | SHA-256 |
| --- | --- |
| LICENSE | `a5f170541dce10ddde7a3f04d1dc18b56a220c7a323594d1e43a304e633b211e` |
| go.mod | `1a7915c7a52f22c45b107f05bc886462452427855fd651ed63710177a82f470f` |
| go.sum | `f1196c0225871bd97d75fae2a38ea09fec25ed19fd0f9a73d1279152fc561c35` |

源码来源索引：[IKE](https://github.com/NickCao/ranet-lite/tree/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/internal/ike)、
[ESP](https://github.com/NickCao/ranet-lite/tree/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/esp)、
[Babel](https://github.com/NickCao/ranet-lite/tree/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/internal/babel)、
[SADR](https://github.com/NickCao/ranet-lite/tree/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/sadr)、
[transport](https://github.com/NickCao/ranet-lite/tree/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/internal/transport)、
[netstack](https://github.com/NickCao/ranet-lite/tree/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/internal/netstack)。

## 2. 逐模块 port map

目标 owner 沿用现有设计：portable 数据面属于 `internal/photonclient`；Windows OS 资源与
composition 属于 `internal/photonwindows`；State/Gossip 仍由公共 core 与唯一 GossipDriver 拥有。
下表路径是后续实现位置，不代表已经创建目录或接口；仅在真实调用者出现时引入包。

| 固定提交中的 source path | Photon 目标 owner | 采用决策与必须改动 |
| --- | --- | --- |
| `internal/ike/header.go`, `payload.go`, `payloads_sa.go`, `payloads_misc.go`, `const.go` | `internal/photonclient/ike` codec | 带 MIT notice 局部移植长度/重复 payload/critical bit/transform parser 与对应测试；codec 不持有 socket/Store。补 CBC、独立 integrity transform 和受限输入 fuzz；不能照搬原型的 AEAD-only proposal 判定。 |
| `internal/ike/crypto.go`, `sk.go` | 同包 crypto | 重写 suite/key layout 与 SK 加解密，复用标准库 AES、HMAC、ECDH、Ed25519。可带来源记录移植 PRF/PRF+、P-256 wire helpers；新增 CBC padding、随机 IV、SK_ai/SK_ar 和 HMAC 验证，禁止把 AEAD salt/IV 规则用于 CBC。 |
| `internal/ike/auth.go`, `der.go` | 同包 authentication | 可移植 RFC 7427/8420 Ed25519 AUTH 编解码；替换 ranet Organization/CN/serial 与 ASN1_DN 产品身份。远端 identity、公钥来自当前 GatewayPlan；CERT 携带材料不能自行授信。实际 Photon ID wire type 须由 StrongSwan 互通确认。 |
| `internal/ike/initiator.go` | 同包 initiator session | 参考消息 ID、重传、响应校验，重写 session composition：传入有界 datagram I/O 和当前授权材料，取消/关闭归 Daemon；不复制静态 registry 或 session 自建 socket。异步完成须验证 revision、网络 generation 与授权有效期，成功才产生 authenticated SA。 |
| `internal/ike/child_proposal.go`, `child_rekey.go`, `ike_rekey.go`, `liveness.go`, `natt.go` | 同包 SA lifecycle | 局部移植可验证的消息流程与测试，重写 CHILD 的 P-256/none 协商与 keymat；保留双方发起、碰撞、删除、重传测试。SA overlap 由显式 SPI 生命周期控制；到期/撤销/序号耗尽后不能因 retry 恢复发送。 |
| `esp/esp.go`, `sa.go`, `replay.go` | `internal/photonclient/esp` | 带 notice 局部移植 AES-GCM-128、SPI、padding、IP 长度、sequence 与 replay window；首版不移植 ChaCha/额外算法。检查并发 replay commit、nonce 唯一性、sequence 上限与 rekey overlap；不让 ESP 包拥有 OS 路由或 trusted State。 |
| `internal/transport/mux.go` | `internal/photonclient` datagram demux；socket owner 在 Windows Daemon | 重写标准 Go UDP 适配，借鉴 SPI/non-ESP marker 分流与有界队列。原实现依赖 WireGuard conn.Bind，且明确忽略指定 local IP，不直接复制。IKE/ESP 与现有 Gossip 的 framing、端口、队列和 rebind 需显式整合；B2 当前 Gossip socket 不能称为已经统一的数据面 socket。 |
| `internal/babel/{const,tlv,hello_ihu,misc,update,rtt,rawpacket}.go` | `internal/photonclient/babel` | B4 局部移植 codec 与 per-peer ESP 内层 IPv6/UDP 构造，保留报文校验测试；不依赖 Windows multicast socket。 |
| `internal/babel/{speaker,route}.go` | 同包 leaf speaker | B4 重写 route 准入/withdraw 和调度接线。必须绑定 authenticated SA、可信 Router ID origin、当前 origin/prefix 授权；不能直接将上游 learned route 写进 SADR。只 originate 本节点授权 prefix，不 transit。 |
| `sadr/table.go` | `internal/photonclient/sadr` | B4 可带 notice 移植纯 lookup 算法及测试，保留 source/destination 优先级；安装入口必须经过 Photon authorization gate。source constraint 未有明确授权规则时拒绝，不降级为 destination-only。 |
| `internal/netstack/{mesh,route}.go` | `internal/photonclient` packet pipeline；Wintun adapter 在 `internal/photonwindows` | 重写所有权/队列/取消，参考有序并行 crypto pipeline；不直接复制 WireGuard tun.Device 依赖。B4 按官方 Wintun API 实现 ring/buffer 归还；OS address/route 归 WindowsDriver。 |
| `internal/registry/{registry,key}.go`, `internal/config/config.go`, `cmd/ranet-lite` | 不移植 | 使用现有 config、唯一公共 State/BoltStore、identity import、GatewayPlan 与 Daemon；不引入第二份注册表、私钥文件模型、生命周期或 CLI。 |
| 各目录 `*_test.go`, `cmd/{iketest,esptest,babeltest}` | 对应 Photon 包测试、隔离互通 rig | 适用的测试与报文 fixture 可带来源移植；手工 demo 重写为可重复验收。复制测试同样保留 notice，不能将原项目通过视为改动后通过。 |

## 3. 算法和 wire 差异

| 项目 | 锁定 ranet-lite 源码 | Photon 首版决策 |
| --- | --- | --- |
| IKE encryption | `ikeProposal` 提供 AES-GCM-256/128 与 ChaCha20-Poly1305；`SASuite` 没有 integrity 字段，`deriveIKEKeys` 不产生 SK_ai/SK_ar，`sk.go` 仅 AEAD | 实现 Linux 实测 AES-CBC-128 + HMAC-SHA256-128；这涉及 proposal、keymat、SK framing 三处，不能只改算法名称。 |
| PRF / IKE KE | SHA384/256；默认 X25519，支持 P-384/P-256 并处理 INVALID_KE_PAYLOAD | 首版 SHA256/P-256；保留必要的错误通知与有限重试，不增加未经互通的算法。 |
| ESP | AES-GCM-128/192/256 的 helper 与 ChaCha；proposal 提供 256/128、ChaCha，no ESN | 首版 AES-GCM-128、16-byte tag、no ESN；按上限及时 rekey，避免 IV/sequence 重用。 |
| CHILD rekey | `RekeyChild` 明确无 DH；`decodeChildExchangePayloads` 明确拒绝 KE payload | 支持 P-256 或 none；Ubuntu 5.9.13 隔离基线为 none，Nix 6.0.7 为 P-256。首个 IKE_AUTH CHILD 和后续 CREATE_CHILD_SA 分开处理。 |
| identity | `PeerConfig` Organization/CommonName/Serial，ASN1_DN；Ed25519 raw public key | 保持 Ed25519，identity 对齐 Photon verified profile 的 Zone 字符串；不能凭相同签名算法认定 ID 编码兼容。 |
| endpoint / TS | 单个 RemotePort 同时承载 IKE/ESP；严格要求完整 IPv4+IPv6 selectors | 端口来自已签 IKE/NATT records，测试 500/4500 与已签自定义端口；TS 与 Linux 生成器实测对齐。全范围 TS 绝不替代 split/逐路由授权。 |

以上来自锁定源码的静态核对；Linux 基线沿用 design §1.2 已记录证据。本次没有新增 Windows/Linux
IKE 互通结果。尤其不能通过给 Linux 强制 GCM-only、none-only CHILD 或 ranet DN 来规避缺口。

## 4. License 与依赖边界

上游 [LICENSE](https://github.com/NickCao/ranet-lite/blob/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/LICENSE)
为 MIT，copyright 为 2026 Nick Cao。第一次复制或实质派生时，同一提交须：

1. 保存未删节的原 MIT copyright、permission、disclaimer 到第三方 notice 文件；派生源文件注明来源完整 commit、原路径和本地主要改动。
2. 将 notice 纳入源代码分发与随二进制交付的第三方许可证材料，不只留一个外链；复制的测试/fixture 同样登记。
3. 更新实际采用文件清单、依赖和 checksum；本表的“计划采用”不能冒充最终实际 provenance。基于该源码改写不宣称 clean-room，也不能因改名删掉 notice。

初次决策只新增本文档。2026-10-02 实际采用三个 codec 文件，逐文件来源和改动见
[third_party/ranet-lite/README.md](../../third_party/ranet-lite/README.md)，完整 MIT
原文位于同目录 LICENSE。密码学、会话与测试为 Photon 新实现；未迁移上游依赖。
Windows build 与原生测试包已包含 third_party notice；当前 Linux 产品未链接此包。

以下按固定 [go.mod](https://github.com/NickCao/ranet-lite/blob/24a24a2ff380c9f8ceb0092d640daa32e86b5eb5/go.mod)
下载 exact module 后读取其 LICENSE/NOTICE 核对。模块级许可证摘要不能覆盖文件级例外：真正引入时
仍按所采用文件/编译依赖形成发布材料，不将 ranet 的 MIT 扩展到全部传递依赖。

| 模块与锁定版本 | 已核对许可证材料 | 此次采用边界 |
| --- | --- | --- |
| `golang.org/x/crypto v0.55.0` | [LICENSE](https://github.com/golang/crypto/blob/v0.55.0/LICENSE)，BSD-3-Clause | ranet IKE/ESP 的外部 crypto 依赖用于 ChaCha；首版 AES/CBC/GCM 可用 Go 标准库，不为移植原型升级 Photon 依赖。 |
| `golang.zx2c4.com/wireguard v0.0.0-20260522210424-ecfc5a8d5446` | [LICENSE](https://git.zx2c4.com/wireguard-go/tree/LICENSE?id=ecfc5a8d5446)，MIT；conn 文件含自身 copyright/SPDX | ranet mux/netstack 引用 conn/tun；决定重写 adapter，不自动纳入此模块。 |
| `gopkg.in/yaml.v3 v3.0.1` | [LICENSE](https://github.com/go-yaml/yaml/blob/v3.0.1/LICENSE) 与 [NOTICE](https://github.com/go-yaml/yaml/blob/v3.0.1/NOTICE)：部分 libyaml 派生文件 MIT，其余 Apache-2.0 | 不是“全模块 MIT”或“任选一个”；Photon 现有 config 已使用该模块，未来发布材料保留对应 LICENSE/NOTICE。 |
| `golang.org/x/net v0.57.0`, `golang.org/x/sys v0.47.0` | 各模块 LICENSE 为 BSD-3-Clause；[net](https://github.com/golang/net/blob/v0.57.0/LICENSE)、[sys](https://github.com/golang/sys/blob/v0.47.0/LICENSE) | ranet Windows 依赖图中出现；Photon 是否已有/实际使用及版本以自己的 go.mod/build graph 为准，不复制版本集合。 |
| `golang.zx2c4.com/wintun v0.0.0-20230126152724-0fa3db229ce2` | [Go binding LICENSE](https://git.zx2c4.com/wintun-go/tree/LICENSE?id=0fa3db229ce2)，MIT | 仅证明 Go binding 的许可；Wintun driver/DLL 的来源、版本、签名、分发许可须在 B4 单独核对，不能用 binding 的 MIT 代替。 |
| `gvisor.dev/gvisor v0.0.0-20260815055033-7d8fb7f28de4` | [LICENSE](https://github.com/google/gvisor/blob/7d8fb7f28de4/LICENSE)，Apache-2.0 | 虽在 go.mod 中，本次 Windows `go list -deps ./...` 未出现 gvisor package；不据依赖声明引入用户态 TCP/IP stack。 |
| `github.com/kr/pretty v0.3.1` | [License](https://github.com/kr/pretty/blob/v0.3.1/License)，MIT | 与下两项列于上游 indirect 集合，未出现在此次非-test Windows package graph；不作为产品依赖直接迁入。 |
| `github.com/rogpeppe/go-internal v1.10.0` | [LICENSE](https://github.com/rogpeppe/go-internal/blob/v1.10.0/LICENSE)，BSD-3-Clause | 实际移植测试若使用则再纳入相应测试/分发依赖审查。 |
| `gopkg.in/check.v1 v1.0.0-20201130134442-10cb98267c6c` | [LICENSE](https://github.com/go-check/check/blob/10cb98267c6c/LICENSE)，BSD-2-Clause | 同上；优先沿用 Photon 标准 testing，不迁移测试框架。 |

`go list` 结果只回答本次目标的包依赖，不是完整 SBOM 或所有平台许可证审计。
Go 标准库与最终编译器/运行时的分发材料也遵循自身许可证；本次没有改变项目发布流程。

## 5. 后续实现顺序与验收门槛

1. 独立落地 IKE codec/parser 与 proposal/crypto：有限报文长度、fuzz、CBC/HMAC/P-256/PRF keymat vectors，先不创建 SA 或改网关配置。
2. 接 B2 当前授权目标实现 IKE_SA_INIT/IKE_AUTH；使用真实 Linux 连接生成器验证 ID encoding、raw Ed25519、端口/NAT-T、错误 identity/key/proposal、重传/fragmentation。异步过期或撤销时拒绝 SA 提交。
3. 实现首个 CHILD 及 ESP，测双向内层 IPv4/IPv6、外层 IPv4/IPv6、replay、tag/padding/length、序号上限与有界队列；从 Wintun 分离，先用隔离 packet rig 验收。
4. 再做双方 CHILD/IKE rekey、P-256/none、同时 rekey/overlap、删除、DPD、网络变化重连；对 Ubuntu 5.9.13 和 Nix 6.0.7 分别验收。任何过期/撤销/nonce 上限不允许 retry 绕过。
5. B4 才接 Babel origin/SA 绑定、逐路由授权、SADR 和 Wintun；按 design §3.1 拒绝未绑定 origin 和未授权 source constraint。

本文件可以关闭 B3 的 port map/license/provenance/决策前置项；其余 B3 实现与互通项仍未完成。
