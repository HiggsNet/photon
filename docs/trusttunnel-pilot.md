# JTTI TrustTunnel 试点

验收日期：2026-11-17。功能使用本次工作区构建，尚未正式发布。

- 节点：`jtti-hnd.catofes.`，SSH `root@142.248.137.122`。
- 入口：`[2a0d:2905:1:7::22]:4433`，仅 HTTP/3，固定 local endpoint。
- 服务端：`metacubex/mihomo:v1.19.34`，独立 `photon-trusttunnel-main-1` 容器，复用 `photon-main` 网络。
- SNI：`trusttunnel.jtti-hnd.catofes`。
- 证书 SHA256：`1c157db7668d7ad53b91b5beef10a049123b75252bf3e064f02d2674c2cd0492`。
- 用户名 `photon`、空密码；访问边界为 Photon/IPsec 与 `*.catofes.` endpoint ACL。
- 原 SOCKS5/HTTP 容器和三个 SOCKS5 endpoint 保留。

节点的配置、构建、证书和回滚脚本位于 `/var/lib/photon-trusttunnel-pilot/`；原配置、身份文件及停机一致性数据库备份位于该目录的 `backup/`，数据库已通过 bbolt 结构校验。私钥和数据库备份留在节点上。

NixOS 系统服务目录只读，试点使用 `/run/systemd/system/photon.service.d/90-trusttunnel-pilot.conf` 指向试点 daemon。**这是运行时覆盖，重启后 daemon 恢复 NixOS 原版本**；容器采用 `unless-stopped`，配置和记录仍保留。正式持久化部署需把新版 daemon 和 TrustTunnel 服务编排纳入 NixOS 声明。旧 daemon 不能发布/撤销新记录。

当前运行时试点的回滚入口：

```bash
ssh -F /dev/null root@142.248.137.122 \
  'bash /var/lib/photon-trusttunnel-pilot/photon-trusttunnel-rollback.sh'
```

脚本撤销 TrustTunnel 记录、移除对应 ACL、停止独立 Compose project、删除运行时覆盖并重启原 daemon，然后恢复原 SOCKS5 发布服务；保留备份。应在试点 daemon 仍在运行时执行。不会回滚 Gossip 数据库到旧版本，也不重建 Docker 网络。

## 已完成的验收

- 发布探针：严格校验证书的 HTTP/3 `_check`，以及经 `_udp2` 的实际公网 UDP DNS。
- 独立主机：真实 Mihomo v1.19.33 客户端连接 v1.19.34 服务端；TCP、IPv4/IPv6 UDP、多目标、同一 UDP 关联多轮收发，载荷 32/1200/2048/8192 字节，校验回包源和内容。回显目标放在试点网络空间，测试后已清理。
- 错误证书指纹：实际客户端拒绝，日志为 `certificate fingerprints do not match`。
- Gossip：另一台 daemon 已收到 `services/trusttunnel` v1 记录，字段与节点公开证书一致。
- 相关 Go 包测试与 vet、服务记录/状态/配置/探针的 race 检查通过。
- FlClash：隔离临时副本中关闭原生构建 hooks，仅做 Dart 配置测试与分析，12 个测试通过；生产 hooks 未改。Windows console/GUI 交叉编译通过。未完成新 FlClash 原生打包及 Windows 实机验收，现有正式客户端需更新后才能自动消费新记录。

## 短时延迟对照

从 Road 到同一 JTTI 出口，用同版本 Mihomo 客户端、同一 HTTPS URL `https://www.gstatic.com/generate_204`，交替执行各 6 次独立 HTTP 请求。TrustTunnel 进程在请求间保留 QUIC 连接；每次请求的新建目标连接属于实际使用场景。

| 请求序号 | TrustTunnel HTTP/3 | SOCKS5 |
|---|---:|---:|
| 1 | 591 ms | 1677 ms |
| 2 | 341 ms | 788 ms |
| 3 | 373 ms | 407 ms |
| 4 | 171 ms | 1416 ms |
| 5 | 278 ms | 1074 ms |
| 6 | 171 ms | 788 ms |

所有请求返回 204。这里只是单路径、单目标、六次请求的小样本，不代表长期延迟、吞吐或 UDP 丢包表现。HTTP/3 仍使用 TLS，UDP 仍是可靠流封装，首版不启用 Anycast，也没有 HTTP/2 回退。
