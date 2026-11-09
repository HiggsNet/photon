# Photon 测试入口

本文整理源码树里的验证命令和 smoke 目标。它面向开发、CI 和系统集成验证；日常部署、排障和恢复操作见 `docs/new/operations.md`。

## 基础验证

常规开发验证：

```bash
make check
```

`make check` 会执行格式化、`go vet`、`go test ./...` 和构建。Makefile 默认使用 `/tmp/photon-gocache` 与 `/tmp/photon-gomodcache`，便于在受限环境里复用缓存。

测试包会强制从各自的临时 `data_dir` 推导 control socket；普通 smoke 和 root-smoke 也会为每次 Make 调用创建私有 `TMPDIR`，并按各测试节点的 `data_dir` 隔离 socket。即使误用 `sudo make test` 或 `sudo make smoke`，测试写操作也不会连接生产 `/run/photon/photon.sock`。聚合 smoke 成功后会删除私有目录，失败时保留现场用于排障。

只构建：

```bash
make build
```

只运行 Go 测试：

```bash
make test
```

需要查看 skip 原因或更完整日志时运行：

```bash
make test-verbose
```

## 如何选择验证层级

日常开发不要一上来跑完整 smoke。按改动边界从小到大选择：

| 改动类型 | 推荐入口 |
|----------|----------|
| 纯 Go 逻辑、record、zone、crypto、parser | `make test`，必要时加对应 package 的 `go test ./path -run ...`。 |
| 配置字段、CLI 输入输出、daemon control path | 先跑 focused Go 测试，再跑覆盖该路径的轻量 smoke。 |
| gossip/sync/object pull/NAT observed | 跑对应轻量 smoke；做阶段 readiness 判断时再扩到 `make smoke-all`。 |
| IPsec planner、routing planner、firewall planner | 先跑 dry-run smoke；只有触碰真实系统 apply/reconcile 时才跑真实数据面 smoke。 |
| Observer API/UI/inspect 输出 | `make observer-smoke`。 |
| XFRM、StrongSwan、BIRD、nftables/iptables、netns | 先跑 preflight，再跑 root 或 container 数据面 smoke。 |

做提交前的最低门槛通常是：

```bash
make check
git diff --check
```

如果改动影响多个运行时边界，再补对应 smoke。不要用一个 sandbox 里的 socket 权限失败替代代码判断；先确认它是不是环境限制。

## 轻量 Smoke

轻量 smoke 不要求 root、真实 StrongSwan、真实 BIRD 或系统 firewall 数据面。部分目标会启动本地 UDP/TCP socket，因此受限 sandbox 里可能失败；失败时先区分产品回归和运行环境限制。

常用轻量 smoke：

```bash
make join-smoke
make phase2-run-smoke
make phase3-daemon-smoke
make object-pull-smoke
make ipsec-dry-run-smoke
make routing-dry-run-smoke
make firewall-dry-run-smoke
make observer-smoke
```

常用目标说明：

| 目标 | 说明 |
|------|------|
| `join-smoke` | 不启动 UDP，只验证 root admin -> `catofes.` -> leaf node 的 join、bundle、密钥和本地 trust chain。 |
| `phase2-run-smoke` | 验证双节点记录双向同步、Zone 签名校验和重启后的收敛。 |
| `phase3-daemon-smoke` | 验证 CLI 通过 daemon control socket 写入、本机单 writer 和 daemon 驱动同步。 |
| `object-pull-smoke` | 验证大 record 不塞进超大 UDP 包，而是通过 object pull 收敛。 |
| `ipsec-dry-run-smoke` | 验证 IPsec planner、dry-run apply、fake driver reconcile 和 debug/read model 边界。 |
| `routing-dry-run-smoke` | 验证 route authorization、BIRD 配置生成和 routing dry-run reconcile。 |
| `firewall-dry-run-smoke` | 验证 firewall 配置解析、规则规划和 dry-run reconcile。 |
| `observer-smoke` | 验证 Observer API、SSE、static UI 和相关 inspect 输出。 |

完整轻量集合可以直接运行：

```bash
make smoke-all
```

`make smoke-all` 当前展开为：

```bash
make join-smoke
make zone-sort-smoke
make record-view-smoke
make cli-surface-smoke
make phase2-run-smoke
make phase3-daemon-smoke
make phase3-daemon-fallback-smoke
make admin-daemon-smoke
make multi-node-smoke
make chain-relay-smoke
make discovery-smoke
make reflector-smoke
make bootstrap-join-smoke
make nat-daemon-observed-smoke
make delegation-revoke-smoke
make object-pull-smoke
make chunk-fallback-smoke
make ipsec-policy-smoke
make ipsec-dry-run-smoke
make routing-dry-run-smoke
make firewall-dry-run-smoke
make peer-lifecycle-smoke
make revocation-cleanup-smoke
make observer-smoke
```

补充目标说明：

| 目标 | 说明 |
|------|------|
| `phase3-daemon-fallback-smoke` | 验证 daemon 不在线时 CLI 直接写 DB 的开发/恢复 fallback，下一次 daemon 能加载并传播。 |
| `admin-daemon-smoke` | 验证管理端 daemon 运行时，delegation issue/revoke 经 control socket 写入。 |
| `multi-node-smoke` | 验证三个 daemon 经中间节点传播记录，以及中间节点重启后追上新版本。 |
| `chain-relay-smoke` | 四节点链式拓扑，验证 relay fanout 能减少等待完整周期的时间。 |
| `discovery-smoke` | 验证 signed endpoint discovery 和 peer 地址更新。 |
| `reflector-smoke` | 验证 public IP reflector endpoint 路径。 |
| `bootstrap-join-smoke` | 验证新节点通过 bootstrap admission 加入并同步。 |
| `nat-daemon-observed-smoke` | 验证使用 observed UDP 地址传播记录，以及对端离线时重启仍能恢复该地址。 |
| `delegation-revoke-smoke` | 验证撤销传播到在线 daemon 后，信任校验失效并清理发现地址。 |
| `chunk-fallback-smoke` | 验证 TCP object pull 不可达时 UDP chunk fallback 能补齐大对象（以 daemon 的 `via=udp_chunks` apply 日志确认），并先覆盖乱序丢块 NACK、重复 NACK 和过期/错误 transfer。 |
| `ipsec-policy-smoke` | 验证 IPsec mesh policy URI 解析和 planner rule 匹配。 |
| `peer-lifecycle-smoke` | 验证 peer status、revoked peer 阻断和 peer lifecycle debug 输出。 |
| `revocation-cleanup-smoke` | 验证 deny-first revocation cleanup、peer cache 清理和 IPsec link teardown dry-run。 |

## 真实数据面 Smoke

真实数据面 smoke 会触碰宿主网络、network namespace、XFRM、StrongSwan/charon、BIRD、nftables 或 iptables。它们默认不放进 `make check`，也不放进 `make smoke-all`。

完整 root 数据面入口：

```bash
sudo make root-smoke
```

`root-smoke` 会跑真实 StrongSwan/XFRM、BIRD/Babel、firewall、health fault-injection 和 revocation ordering。它会复用共享 lane，避免再通过 `revocation-data-plane-smoke` 重复跑 firewall/BIRD/StrongSwan 子集。Phase 8 的服务数据面还依赖 Docker bridge，因此不包含在该集合中，需显式运行 `services-smoke`。

下面是按数据面分组的入口，适合局部验证。运行前先跑对应 preflight；container 入口用于隔离宿主差异，通常和同名 root 入口二选一。

```bash
make ipsec-xfrm-preflight
sudo make ipsec-xfrm-smoke
make ipsec-xfrm-container-smoke

make bird-babel-preflight
sudo make bird-babel-smoke
sudo make phase7-1-bird-experiment
sudo make phase7-1-wg-gre-experiment
make bird-babel-container-smoke

sudo make firewall-smoke
make firewall-container-smoke
sudo make health-fault-smoke
make health-fault-container-smoke
sudo make revocation-data-plane-smoke
make revocation-data-plane-container-smoke

# Phase 8：需要 root、Docker、ip、bird/birdc 和 nft
sudo make services-smoke
```

避免重复跑的关系：

| 如果已经跑了 | 通常不需要再单独跑 |
|--------------|--------------------|
| `sudo make root-smoke` | 下面列出的常规 root 数据面 smoke；不包括依赖 Docker bridge 的 `services-smoke`。 |
| `sudo make revocation-data-plane-smoke` | `sudo make firewall-smoke`、`sudo make bird-babel-smoke` 和 revocation 相关的精简 XFRM bring-up；该组合目标内部会再次调用这些 lane。 |
| `make revocation-data-plane-container-smoke` | 对应的 root 组合目标，除非你正在对比宿主和容器权限差异。 |

container 目标默认使用 Docker，也可以切到 Podman：

```bash
PHOTON_CONTAINER_RUNTIME=podman make ipsec-xfrm-container-smoke
```

这些目标会按需构建并复用缓存镜像和 Go cache volume。常用覆盖项：

| 变量 | 说明 |
|------|------|
| `PHOTON_CONTAINER_RUNTIME` | 容器运行时，默认 `docker`。 |
| `PHOTON_CONTAINER_USERNS` | Docker 默认使用 `host` user namespace；设为空可禁用该参数做对比。 |
| `PHOTON_IPSEC_XFRM_IMAGE` / `PHOTON_BIRD_IMAGE` / `PHOTON_FIREWALL_IMAGE` / `PHOTON_HEALTH_FAULT_IMAGE` / `PHOTON_REVOCATION_DATA_PLANE_IMAGE` | 数据面 smoke 的基础镜像，默认 `ubuntu:24.04`。 |
| `PHOTON_IPSEC_XFRM_REBUILD_IMAGE` / `PHOTON_BIRD_REBUILD_IMAGE` / `PHOTON_FIREWALL_REBUILD_IMAGE` / `PHOTON_HEALTH_FAULT_REBUILD_IMAGE` / `PHOTON_REVOCATION_DATA_PLANE_REBUILD_IMAGE` | 设为 `1` 时强制重建对应缓存镜像。 |
| `GO_CACHE` / `GO_MOD_CACHE` | Makefile 侧 Go cache 目录，默认 `/tmp/photon-gocache` 和 `/tmp/photon-gomodcache`。 |

真实数据面目标说明：

| 目标 | 说明 |
|------|------|
| `root-smoke` | 汇总真实 root 数据面验证，覆盖 StrongSwan/XFRM、BIRD/Babel、firewall、health fault-injection 和 revocation ordering。 |
| `ipsec-xfrm-preflight` | 检查 root/netns/XFRM/StrongSwan/VICI 等前置条件，避免半途创建系统资源后失败。 |
| `ipsec-xfrm-smoke` | 在真实系统能力下验证 StrongSwan/VICI + XFRM interface、daemon reconcile、SA 观测和 tunnel ping。 |
| `ipsec-xfrm-container-smoke` | 在 privileged container 中运行 StrongSwan/XFRM smoke，适合隔离宿主环境差异。 |
| `bird-babel-preflight` | 检查 root/netns/BIRD/Babel 相关前置条件。 |
| `bird-babel-smoke` | 验证 managed BIRD/Babel lifecycle、邻居和路由学习、negative import filter、anycast failover 和 daemon restart adopt 等常规真实 routing 数据面。 |
| `phase7-1-bird-experiment` | 显式运行较慢的 Phase 7.1 双接口静态 `rxcost` 方向性、故障切换与恢复实验；不包含在 `bird-babel-smoke` 或 `root-smoke`。 |
| `phase7-1-wg-gre-experiment` | 显式运行 Phase 7.1 三节点共享 WG device、transit-only AllowedIPs、per-peer GRE/Babel、业务前缀转发、MTU/cleanup，以及复用逻辑 key 的 staged WG device rotate、Babel cutover、listener/firewall grace 和引用计数 cleanup；不包含在默认 smoke。 |
| `bird-babel-container-smoke` | 在 privileged container 中运行 BIRD/Babel smoke。 |
| `firewall-smoke` | 使用真实 nftables/iptables backend 验证 firewall 规则 apply 和清理；iptables 子项需要同时安装 `ipset`。 |
| `firewall-container-smoke` | 在 privileged container 中运行 firewall 数据面 smoke。 |
| `health-smoke` | 验证 health manager、OpenMetrics render、本地 spool/series、真实 BIRD neighbor/route 进入 rotate cutover gate，以及 `tc netem` 丢包注入后的状态切换和恢复。 |
| `health-fault-smoke` | `health-smoke` 的显式故障注入别名，用于表达该 lane 覆盖 BIRD cutover gate、数据面丢包和恢复。 |
| `health-fault-container-smoke` | 在 privileged container 中运行 health fault-injection smoke。 |
| `revocation-data-plane-smoke` | 组合 firewall、BIRD 和 StrongSwan 的 revocation 数据面验证，需要 root。 |
| `revocation-data-plane-container-smoke` | 在 privileged container 中运行组合 revocation 数据面验证。 |
| `services-smoke` | Phase 8 的显式 root 入口。先跑 `app/photon-services` 单元测试，再以真实 Docker bridge、SOCKS5 与目标 TCP/UDP DNS 容器、host 到 overlay 聚合路由、overlay 到 host static upstream、BIRD/Babel 验证端到端代理数据面；覆盖 TCP CONNECT、UDP ASSOCIATE、DNS ID/答案和动态 relay 回包源 IP/端口，并运行 BIRD Anycast 成员故障收敛测试。需要 root、Docker、`ip`、`bird`/`birdc` 和 `nft`；不包含在 `root-smoke` 或 `smoke-all`。 |

## 失败判断

smoke 失败时先看目标属于哪一层：

- `join-smoke` 这类纯本地目标失败，通常优先查 trust chain、bundle、record 写入和本地状态库。
- gossip smoke 失败，先看本地 UDP/TCP socket 是否被环境禁止，再看各节点日志和 `advanced sync status`。
- object pull / chunk fallback 失败，区分 TCP object pull、UDP chunk repair 和外部端口阻断工具是否真的可用。
- dry-run 目标失败，通常是代码或测试 fixture 回归，不应归因于宿主系统能力。
- root/container smoke 失败，先看 preflight、容器权限、charon/VICI、BIRD、nftables/iptables 和 netns/XFRM 诊断输出。
- `services-smoke` 失败，额外检查 Docker daemon、临时 bridge/network 与容器清理、host connected route 是否优先于 overlay 聚合路由，以及 BIRD/Babel 和 static upstream 回程。

优先收集这些证据再改代码：

| 场景 | 证据 |
|------|------|
| sync/gossip 不收敛 | 每个节点日志、`advanced sync status --verbose`、`record list`、record history、catalog/object pull 计数。 |
| daemon 行为异常 | control socket 是否在线、`advanced sync status --verbose` 里的 daemon 状态、daemon 日志和本地 state DB。 |
| IPsec/XFRM 异常 | preflight 输出、`debug links`、`health --verbose`、`swanctl --list-sas`、`ip xfrm state`、XFRM interface/address/route。 |
| routing/BIRD 异常 | generated BIRD config、`debug routing`、BIRD control socket、neighbor 和 best route 输出。 |
| firewall/revocation 异常 | planned rules、实际 nftables/iptables 规则、revocation impacts、peer cache 和 link teardown 日志。 |
| sandbox/CI 异常 | `Operation not permitted`、`socket: operation not permitted`、容器 privileged 能力、Seccomp/NoNewPrivs 状态。 |

如果一个 smoke 目标开始频繁失败，不要只按名称判断它过期。先用日志、状态库、generated config、系统规则和 runtime counters 判断是产品 bug、测试夹具不适合当前流程，还是运行环境能力不足。
