# Photon

Photon 是一个实验性的“信任优先” mesh VPN 控制平面。它不把任何单节点的本地配置当成全网真相，而是先维护一份可验证、最终一致的 Zone 状态数据库，再由每个节点的 daemon 把已验证状态收敛成本机的 gossip、IPsec/XFRM、BIRD/Babel、firewall、health 和 observer 等运行时配置。

- 整体架构与模块划分：[docs/new/overall.md](docs/new/overall.md)
- 详细设计文档：[docs/design.md](docs/design.md)

## 安装

Linux `amd64` / `arm64` 可直接从最新 GitHub Release 安装（默认安装 `photon`、
`photon-services` 和 `photon.service`）：

```bash
curl -fsSL https://raw.githubusercontent.com/HiggsNet/photon/master/contrib/install.sh | sh
```

更新到最新 Release：

```bash
curl -fsSL https://raw.githubusercontent.com/HiggsNet/photon/master/contrib/update.sh | sh
```

安装和更新会在替换二进制前检查完整数据面依赖，包括 `ip`、`ping`、
BIRD 2.14+、nftables、iptables/IPv6、`ipset` 和 StrongSwan。缺少依赖时会
列出命令并退出；仅部署控制面或由外部环境提供依赖时，可以显式传入
`--skip-dependency-check`（管道执行时使用 `sh -s -- --skip-dependency-check`）。

原生安装是主要部署路径：它直接集成 systemd、宿主数据面和
`photon-services` 生成的服务编排 artifact。Docker 是固定用户态依赖的备用路径，
不取代管理员对宿主网络、Compose 和服务生命周期的管理。

需要在同一主机额外运行一个管理节点时，显式传入 `--admin`：

```bash
curl -fsSL https://raw.githubusercontent.com/HiggsNet/photon/master/contrib/install.sh | \
  sudo sh -s -- --admin
```

这时才会额外安装 `photon-admin` 和 `photon-admin.service`，并创建 admin 最小配置；
不带 `--admin` 不会创建或修改任何 admin 文件。
`photon-admin` 是包装命令，自动选择 `/etc/photon/admin/config.yaml`、
`/etc/photon/admin/photon.db` 和独立 control socket，因此执行管理命令无需手工传环境变量。
普通节点仍使用 `/etc/photon/config.yaml` 和 `/etc/photon/photon.db`。建议 admin 只运行
authority/gossip 控制面，不配置 overlays、routing 或 firewall。详细约束见
[daemon 文档](docs/new/daemon.md#52-同机双实例)。

`update.sh` 会检测已有的 `photon-admin`：已安装 admin 的节点会自动一起更新，普通节点
仍只更新普通组件。

其他安装方式：

- **Docker**：`make docker-build` 构建基于 Ubuntu 24.04 的运行时镜像，镜像同时包含 `photon` 与 `photon-services`；真实数据面（IPsec/XFRM、BIRD、firewall、netns）仍需要 `--privileged --network host` 和兼容的宿主 Linux 内核。
- **Nix**：`nix build .#photon` 构建软件包，`nix develop` 进入开发环境；NixOS 可导入 `nixosModules.default`，通过 `services.photon` 管理 daemon 和可选的 `photon-services` systemd 部署。
- **源码**：`make build`，产物在 `build/photon`。

## 快速开始

默认读取 `/etc/photon/config.yaml`，可用 `PHOTON_CONFIG=/path/to/config.yaml` 覆盖。本地开发或同机多节点时建议始终显式指定 `PHOTON_CONFIG`。

最小节点配置：

```yaml
data_dir: /etc/photon
trusted_root_public_key: <base64-ed25519-public-key>

gossip:
  peer_id: node-a.catofes.
  listen_addr: "[::]:33434"
  bootstrap:
    - id: node-b.catofes.
      addr: 203.0.113.20:33434
  init:
    managed_zone: node-a.catofes.
    key_path: /etc/photon/identity.key.json
```

加入网络的基本流程：节点生成 key 并提交 join request，由父 Zone 管理端签发 delegation bundle，节点接受 bundle 后即可运行：

```bash
build/photon gossip keygen identity.key.json
build/photon gossip join request node-a.catofes. identity.key.json      # 交给管理端
build/photon gossip delegate issue <request.b64>                        # 管理端签发
build/photon gossip join accept <bundle.b64> identity.key.json          # 节点导入
build/photon daemon                                                     # 长期运行入口
```

完整的从零搭建（root admin → 一级管理 Zone → 普通节点）见 [docs/new/operations.md](docs/new/operations.md)。所有配置项的带注释模板见 [config.example.yaml](config.example.yaml)，字段参考见 [docs/new/config.md](docs/new/config.md)。

## 文档

| 文档 | 内容 |
|------|------|
| [docs/new/overall.md](docs/new/overall.md) | 整体架构：全网事实层与本机执行层 |
| [docs/new/config.md](docs/new/config.md) | 配置字段参考 |
| [docs/new/operations.md](docs/new/operations.md) | 运维手册：信任链初始化、daemon、debug、恢复、排障 |
| [docs/new/gossip.md](docs/new/gossip.md) | Zone 数据库、签名验证、同步协议 |
| [docs/new/daemon.md](docs/new/daemon.md) | daemon 单 writer 模型与 reconcile |
| [docs/new/transport-ipsec.md](docs/new/transport-ipsec.md) | StrongSwan/IKEv2 + XFRM 数据面 |
| [docs/new/routing.md](docs/new/routing.md) | BIRD/Babel、route、IPAM |
| [docs/new/firewall.md](docs/new/firewall.md) / [health.md](docs/new/health.md) / [observer.md](docs/new/observer.md) | 防火墙、健康探测、Web 状态控制台 |
| [docs/new/testing.md](docs/new/testing.md) | 测试与 smoke 目标说明 |
| [docs/design.md](docs/design.md) | 完整设计文档 |

## 开发

```bash
make check    # 格式化、vet、测试、CGO_ENABLED=0 构建
```

常用 smoke：`make phase2-smoke`（双节点同步）、`make multi-node-smoke`（三节点传播）、`make chain-relay-smoke`（链式 relay）、`make observer-smoke`。真实数据面需要特权环境，是显式目标，例如 `sudo make ipsec-xfrm-smoke`、`sudo make bird-babel-smoke`。完整清单与适用场景见 [docs/new/testing.md](docs/new/testing.md)。

发布流程见 `make release-check` / `make release-tag` / `make release-push`，tag 必须严格为 `v$(cat VERSION)`。

## 当前限制

- 私钥以明文保存在本地 bbolt metadata 中（identity 包已有加密 helper，CLI 尚未强制使用）。
- Zone authority 只支持 `threshold=1`；delegation scope 只支持 `direct-child`。
- 同步是最终一致性；复杂 NAT、长期网络分区场景仍需要更完整的 relay/discovery 能力。
- IPsec、BIRD/Babel、firewall 的真实后端依赖 Linux 权限与系统服务；`make check` 不覆盖这些，需要显式 privileged smoke。
- Observer 是只读、无内置认证的本机面板；远程访问请走 SSH tunnel 或带认证的反向代理。

近期配置、诊断与 API 兼容性变化见 [操作与兼容性说明](docs/operator-compatibility.md)。
