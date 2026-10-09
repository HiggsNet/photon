# SKF 长序列 fuzz

`FuzzSKFSequence` 对实际 `SealSKF` / `skfReassembly.Add` 使用固定密钥和确定性 IV，
每个输入最多 1024 步。三个同内容分片集合分别有 4、6、64 片；64 片覆盖协议实现上限。
这只是测试材料，不用于生产会话。

操作流包括有效分片、乱序与重复、认证失败、已认证的冲突重复、较大分片总数带来的
PMTU 重启、旧集合重放、错误 message ID、截断、超时和显式 Reset。
独立的已接收序号集合检查完成条件；输出必须与原始明文相同，不能提前暴露部分明文。
每步还检查缓存计数、大小上限、调用方密文不变，以及清理、重启、超时和完成后旧缓冲区清零。
失败输入不能修改缓存；时钟已到期限时允许先执行到期清理。每个序列末尾必须能重新完成
一次 64 片倒序重组，以发现失败后不可恢复的状态。

普通测试执行内置 seeds（包含 256 步序列），持续任务可显式增加运行时长：

```sh
go test -race ./internal/photonclient/ike -run '^(FuzzSKFSequence|TestSKF)'
go test ./internal/photonclient/ike -run '^FuzzSKFSequence$' \
  -fuzz '^FuzzSKFSequence$' -fuzztime=1h -parallel=2
```

保留 Go 失败时写入的 `testdata/fuzz/FuzzSKFSequence` 作为可重放回归，先定位失败再修复。
执行环境禁止写默认缓存时，给上述命令设置可写的 `GOCACHE`。
这些命令不需要管理员、驱动或网络权限；Windows 编译不替代 Windows 原生 seeds 执行。

本项覆盖有限消息材料上的有状态重组，不替代任意 IKE wire parser fuzz、整个会话的消息 ID
推进验证、实际链路丢包矩阵或长期持续 fuzz。B6 的持续 fuzz 门槛继续保持未完成。

2026-10-09，本切片在 Linux 执行 20 秒探索（退出含收尾约 21 秒），11,843 次执行、
新增 13 个 interesting inputs，通过；focused seeds/race 与 Windows amd64 测试二进制编译通过。
此处没有运行 Windows 原生测试，也没有完成小时级或持续调度验收。
