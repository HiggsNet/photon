# B6 网关出站密文丢包、重复与乱序

完整 Linux `app/photon daemon` / Windows SCM rig 新增独立的
`PHOTON_WINDOWS_IMPAIRMENT=1` 场景。它与 rekey、传输黑洞及性能测量互斥，
沿用真实 Gossip、StrongSwan、BIRD、Wintun 和双栈业务链路。

## 注入与验收边界

仅在本次 bridge 容器的 `eth0` 创建自有 qdisc；匹配网关发往 Windows 的
NAT-T ESP，排除 IKE 的零 marker 和 NAT keepalive。每阶段分别注入 loss、
duplicate、reorder，恢复后才进入下一阶段。宿主网络、Windows 管理网卡、
默认路由与 SSH 均不参与注入。

固定注入为 loss 10%、duplicate 15%，以及 delay 40 ms / reorder 50% / gap 5。
每族每个故障阶段发送 1,000 包，最高 100 pps，发送后另 drain 2 秒；control 和
每次恢复各发送 100 包。记录实际收发数量，不把配置概率当作精确业务损失率。

Windows 每族使用独立 socket、nonce 和递增序号，低压发送固定数量的 96 字节
业务请求。检查全部回包内容、重复、缺失和接收顺序；故障前与每次恢复后另用
独立 nonce 验证完整双栈回包。服务须保持同一 SCM PID、创建时间、live generation
及 IKE/CHILD lease，不能以重新建链通过验收。

Linux 保留实际 tc 参数与计数，并用 tcpdump 只输出时间、公开 ESP SPI/sequence
和长度等文本元数据，不保存 pcap、明文或会话密钥。密文重复和乱序必须实际出现，
且抓包内核丢失为零；仅配置了概率不能算注入已发生。

开始前必须核对两端 UTC 和时间同步状态。签名身份续租使用严格未来 timestamp
检查；时钟落后会暂时拒绝新身份并移除 learned route，不能为通过测试放宽授权。
本轮 VM 时间源未同步，单独校准后再运行；没有修改产品时间校验或永久时间源配置。

```sh
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 \
PHOTON_BIRD_NIX_PACKAGE=/nix/store/<bird-package> \
PHOTON_TC_NIX_PACKAGE=/nix/store/<iproute2-package> \
PHOTON_TCPDUMP_NIX_PACKAGE=/nix/store/<tcpdump-package> \
PHOTON_WINDOWS_IMPAIRMENT=1 \
bash docs/scripts/windows-full-daemon-smoke.sh
```

StrongSwan 6.0.7 另设置 `PHOTON_IKE_AUTH_NIX_PACKAGE`，沿用完整 rig 的参数。

本切片覆盖 **gateway → Windows** 的外层故障。它不关闭双方向、rekey 同时故障、
真实睡眠、物理换网、多层 NAT 或 72h soak 的完整产品门槛。

## 回归与证据

Windows 11 amd64、完整生产 gateway daemon 与 SCM，两版本正式运行退出码均为 0：

| StrongSwan | SCM PID / generation | loss 唯一回复，IPv4 / IPv6（各 1,000） | 密文复制数 | 密文唯一序号逆序 / 最大落后距离 | 全程 ready/live 样本 |
| --- | --- | --- | --- | --- | --- |
| 5.9.13 | 3696 / 3 | 908 / 906 | 309 | 1,406 / 9 | 118 / 118 |
| 6.0.7 | 5508 / 3 | 899 / 905 | 278 | 1,395 / 7 | 119 / 119 |

两版 duplicate/reorder 阶段每族均为 1,000 / 1,000，应用重复、损坏与 worker 错误均为零；
control 及三个恢复阶段每族均为 100 / 100。两版均经过普通 Gossip revision 7 → 8，
仍保持原进程、generation、两 SA lease 和同一 ESP SPI。逐包当前授权检查保持原实现。

tc loss 实际丢弃分别为 186 / 196 包，duplicate/reorder 没有 qdisc 丢弃；
六次抓包均退出 0、kernel drop 为零，阶段结束队列排空并恢复 `noqueue`。
原始文本由独立 subagent 重新计算 SPI/sequence，结果与 coordinator JSON 一致。
最大逆序跨度均小于 64 包窗口，不能推导为任意乱序都能完整交付。
这些证据证明实际密文复制时业务仍完整、唯一；没有逐包 replay 拒绝计数，
不声称每个复制包都已被 Windows 接收并由 anti-replay 丢弃。

后续既有正常停止/重启、强制结束后同 Bolt 恢复、真实地址通知重绑、外部同名网卡保护、
初始化失败与事件源冲突回滚，两版也全部通过。独立检查四轮精确测试资源：服务、
事件源、adapter、地址、路由、进程、远端 fixture 目录均为零；测试容器和解析临时目录另行清理核查。

本轮公开日志保存在 `build/validation/b6-impairment-20261014/`。
全仓 `make check` 与 ESP/Windows focused race 分层执行；沙箱内 race 因禁止
loopback UDP socket 失败的原始日志保留，沙箱外重新执行通过。
两份 PowerShell 的原生 AST 解析、两份 shell 的 `bash -n`、`git diff --check` 通过。
本轮生产代码增删为 0；没有新增平台 owner、兼容入口或产品运行模式。

`ubuntu/`、`nix/` 包含正式流量结果、各阶段 IPC DTO、实际 tc 参数、计数、公开密文摘要、
SA/业务及完整服务回归记录；`scripts-before-matrix.sha256` 固定四个验收脚本。
两版本三个产品/fixture binary 的 SHA 一致，签名私钥、数据库和程序在原 rig 结束时清理。

`failed-tc-schema/` 保留首轮 `loss-random` JSON 字段读取错误；
`failed-phase-transition/` 保留将上一阶段恢复请求误当下一阶段取消信号的错误。
两轮顶层 `Completed=false`，不计入完整通过。第二轮在签名身份续租后还观察到约
13.9 秒 readiness 关闭，SA 仍 live；独立时钟读取确认 VM 落后约 6.4 秒。
校准后的两版续租均通过，符合未来记录暂时拒绝的解释；因失败轮未保留续租记录原件，
不能将时钟偏差认定为唯一原因。时间核对和校准过程见 `clock-calibration.md`，
没有为此放宽签名、时间或路由授权。
