# Windows 服务性能基线

本工具复用 `windows-full-daemon-smoke.sh`：Windows 生产 SCM、Wintun、Babel/SADR、ESP 和共享 UDP，对接隔离容器中的完整 Linux Photon daemon、BIRD、StrongSwan 和 UDP echo。它不修改产品参数，不安装额外业务路由，不接触管理网卡。

## 复现

使用完整 daemon 验收所需的 SSH、Linux LAN 和 BIRD 参数，增加：

```sh
PHOTON_WINDOWS_BASELINE=1 \
PHOTON_WINDOWS_SSH=photon-test@10.16.252.11 \
PHOTON_LINUX_IP=10.16.255.8 \
PHOTON_BIRD_NIX_PACKAGE=/nix/store/<bird-package> \
bash docs/scripts/windows-full-daemon-smoke.sh
```

可通过既有 `PHOTON_IKE_AUTH_NIX_PACKAGE` 切换 StrongSwan。端口与 VM 必须独占，采样时不并行运行其他压力、原生测试或故障注入。脚本先确认双栈业务与授权路由就绪，然后测量，再继续正常重启、崩溃恢复、网络变化及清理验收。

结果为日志目录中的 `baseline.json`；同目录保存源 commit、工作树状态、实际 StrongSwan/BIRD 配置与日志。JSON 保存 Windows 版本、CPU、物理内存、二进制 SHA256、服务 PID/创建时刻、参数、逐轮统计与逐点样本。即使测试失败，也尽量保留已完成结果；只有 `Completed=true` 表示完整基线完成。私钥、数据库及本次服务、目录、网卡和容器沿原 rig 的清理流程删除。

## 固定负载和统计语义

- 1200 字节应用 UDP payload，固定窗口 8 的对照和窗口 64 的压力点；每请求最多等待 1 秒，只在回包或超时后释放槽位。不按超时重发原包，不为追求吞吐扩大队列。
- 窗口 8 下 IPv4、IPv6 各 3 轮，窗口 64 下各 1 轮，每轮 2 秒预热、15 秒发送，发送结束后最多 1.1 秒排空。偶数轮交换地址族顺序，保留每轮结果，不只报告最好值。
- 测量前后各 5 秒 idle 对照。服务 CPU 累计时间、private bytes、working set 每约 250 毫秒采样；该间隔不是硬实时保证。
- 每轮使用独立随机 nonce 和递增序号，检查全部回包内容。`Echoed` 统计实际测量期内唯一完整回包，`LateEchoed` 单独统计已经超出 1 秒窗口的唯一回包。固定 8192 项序号环抑制重复；重复记 `Duplicates`，超出追踪范围记 `Unmatched`，均不增加吞吐。`Expired` 包含超时和最终未完成请求，满足 `Sent = Echoed - LateEchoed + Expired`。
- `GoodputMbps = Echoed × payload bytes × 8 / 实际测量秒数 / 1e6`。分母包含排空时间，是成功 echo 的单方向应用有效载荷速率；每次成功完成包含两个方向各一份载荷，双向合计为该值的 2 倍。同时保留 `DeadlineGoodputMbps`（仅 1 秒内回包）和 `DeadlineMissPercent`（过期请求比例），不以迟到回包抹掉期限失败。它不包含 IP/UDP/ESP 外层开销，不代表链路饱和容量或 TCP 吞吐。
- CPU 单位是一个逻辑 CPU 的百分比，允许超过 100%；不要与整机百分比混用。服务 CPU 与 PowerShell/C# 负载生成器 CPU 分别报告，Linux gateway/内核 CPU 未被本工具计入。
- private bytes 和 working set 是进程观测，不是 Go live heap；短时前后差值不能证明内存泄漏或无泄漏。样本峰值可能漏掉短于采样间隔的瞬时峰值。

`windows-service-baseline-test.ps1 -Helper <windows-service-baseline.ps1>` 在 Windows loopback 上用受控丢包、重复和 1.1 秒迟到 echo 验证唯一回包计数、超时、采样和 idle；只占本机 `127.0.0.1:19096`，结束后关闭自己的 socket/thread。该测试不代替真实隧道基线。

## 验收边界

最低有效性门槛是无损坏载荷、同一服务进程持续存活，且每轮结束后在既有 Check-Business 期限内恢复双栈 echo、live IKE/CHILD 与业务 readiness。测量期零回包或零期限命中允许作为过载结果保存，不等于性能通过；逐轮 RecoveryPassed 单独标记恢复验证。丢包与背压如实报告，不设置未经测量依据的吞吐及 CPU 门槛，也不把存在丢包的结果称为无损吞吐。

这是一组可重复短时基线。72 小时 soak、实际物理睡眠/换网、多层 NAT 和正式发布门槛仍需独立验收。

## 2026-10-09 实测

Windows 11 `10.0.26200` VM，8 个逻辑 CPU（来宾报告 i9-12900H），物理内存约 7.93 GiB；BIRD 2.19.1。生产源码 `645163d2c2f557a99494d3d85cabe951c4563eeb`，Windows executable SHA256 `478c324236c6b31da4d664fc19bbeeec2b12c9e0921871c61dbeb3dba1d6b328`。性能 helper 在该次测试时尚未提交，具体来源状态保留在各日志目录。

StrongSwan 6.0.7 最终完整基线：`/tmp/photon-windows-full-daemon.JxqK2B/baseline.json`，`Completed=true`。全程同一服务 PID 6424；8 个负载点后的同进程双栈恢复均为 `RecoveryPassed=true`。

| 窗口 / 地址族 | 轮数 | 唯一回包 goodput Mbps | 1 秒内 goodput Mbps | 采样期未收到的请求 | 服务 CPU（单核 %） |
| --- | --- | --- | --- | --- | --- |
| 8 / IPv4 | 3 | 中位 0.209，范围 0.207–0.217 | 同左 | 0% | 98.17–99.79 |
| 8 / IPv6 | 3 | 中位 0.208，范围 0.207–0.213 | 同左 | 0% | 98.79–99.77 |
| 64 / IPv4 | 1 | 0.107 | 0 | 82.50% | 97.91 |
| 64 / IPv6 | 1 | 0.105 | 0 | 82.71% | 99.91 |

窗口 64 两个地址族各发送 960 个请求，仅分别收到 168 / 166 个唯一 echo，且全部迟到；1 秒 deadline miss 均为 100%。这两个压力点不满足及时交付，不能因后续业务恢复通过而称为性能通过。每个成功 echo 同时验证 Windows→gateway 请求与返回方向。

负载阶段生成器 CPU 为 0.31–0.73% 单核，远小于服务 CPU。全部样本中 private bytes 峰值 57.25 MiB、working set 峰值 64.64 MiB；idle 前后 CPU 分别 9.97% / 8.11%，idle 前后 private 峰值 56.84 / 56.49 MiB、working set 峰值 64.09 / 63.99 MiB。短时数据没有显示持续上升，但不足以作无泄漏结论。

Ubuntu StrongSwan 5.9.13 留有两个明确不完整的工具试跑，不能标为完整通过：

- `/tmp/photon-windows-full-daemon.WPPbHP`：最初只以 1 秒内 echo 作为有效性门槛，64 窗口发送 960 个请求、期限内 0 个、136 个迟到，服务约 100% 单核，因此中断。该版 `Unmatched` 合并迟到和重复，没有独立迟到计数。
- `/tmp/photon-windows-full-daemon.DK8VlT`：窗口 8 双栈各三轮完成，0 期限丢失；IPv4 中位 0.206 Mbps、IPv6 中位 0.200 Mbps，服务约 98–100% 单核。窗口 64 IPv4 为 161/960 个唯一迟到回包，deadline goodput 0；随后 IPv6 预热受上一压力点积压影响，旧工具的零回包门槛中断，没有取得 IPv6 压力样本或最后 idle 样本。

最终工具保存预热数据，不把零期限命中丢弃，每轮后沿既有 `Check-Business` 时限确认恢复后才继续。受控回环测试验证了迟到与重复的独立计数，保留上述失败证据，未调整产品实现或降低压力窗口以追求通过。

结果足以建立该构建的短时基线，也显示服务在较低业务速率就接近一个满载逻辑核。当次尚未进行 CPU profile，不能仅凭这些数据归因到具体函数。后续 [SCM CPU profile 与同负载对照](profile-testing.md) 已定位重复验签热点；[逐包优化记录](packet-path-performance.md) 保留独立切片、授权边界与 portable 基准，历史基线仍按原构建保留。

Nix 本轮随后完整 SCM 回归也以 exit 0 完成：正常重启、强制结束后恢复、地址增删通知、外部 alias 冲突及解除后恢复均通过。最终另行只读确认三个试跑的临时服务、Event Log source、adapter、远端目录、精确测试地址/route 和 Docker 容器均不存在；本地 fixture 私钥、数据库、程序和独立 helper 目录已清理。

公开证据另保存于 `build/validation/b6-baseline-20261009/`（不包含私钥或数据库）：`nix-complete/`、`ubuntu-partial-initial/`、`ubuntu-partial-window8/` 各保留 JSON、Windows/charon 日志、source commit/status；`controlled-test.log` 与 `cleanup.log` 分别保留最终计数回归和资源复核。该目录为本地验收产物，不随源码提交。
