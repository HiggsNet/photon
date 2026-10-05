# Linux 重构版测试

本轮旧版固定为 `v0.5.6`（master 提交 `28472ea74615`），新版为
`v0.6.0-rc.2`（在 rc.1 上追加以下 Linux 修复）。新版只供测试，Windows 完整隧道尚未交付。
master 保留旧版；候选版从独立 release 分支发布，不更新 Docker `latest`。

## rc.2 相对 rc.1 的变化

- 兼容 iproute2 JSON 中十六进制字符串形式的 XFRM `if_id`，避免批量观察持续失败并回退逐接口读取。
- 默认 `photon gossip peer` 列表隐藏超过 cleanup_after、没有有效端点的历史节点；bootstrap 保留。按名称、`--filter`、`--verbose` 和 debug 仍可查询，最近活动或有效端点恢复后重新显示。此改动不删除数据库记录。
- 不包含现场 ln 数据库的手工恢复操作，也未新增 Rotate 状态日志或改变轮换策略。

## 下载和安装

使用一台专用 Linux 测试机，与仍运行旧版的节点互通。安装器支持 amd64/arm64，
会检查运行依赖并校验下载包的 SHA256。以下命令面向普通 systemd 安装；
NixOS、容器或自定义 unit 应沿用原部署方式，显式固定版本。

```sh
curl -fL --retry 3 -o /tmp/photon-install-rc.sh \
  https://raw.githubusercontent.com/HiggsNet/photon/v0.6.0-rc.2/contrib/install.sh
```

先在测试机安装旧版，完成入网并确认双向通信，作为基线：

```sh
sudo sh /tmp/photon-install-rc.sh --version v0.5.6
photon version
```

首次安装仍需按 [运维文档](operations.md) 配置身份、授权和网关，再启动
`photon.service`。安装包本身不会替你加入网络。

升级前停止 Photon，备份配置和数据库。默认 service 使用 `/etc/photon`；
先用 `systemctl cat photon` 检查实际配置、数据库和环境变量路径。
自定义路径必须一起备份，有其他 Photon 服务使用相同数据时也须先停止。

```sh
sudo systemctl stop photon
sudo install -d -m 0700 /var/backups/photon-before-rc2
sudo cp -a /etc/photon /var/backups/photon-before-rc2/etc-photon
sudo cp -a /usr/local/bin/photon /usr/local/bin/photon-services /var/backups/photon-before-rc2/
sudo sh /tmp/photon-install-rc.sh --version v0.6.0-rc.2 --no-service
sudo systemctl start photon
photon version
sudo systemctl status photon --no-pager
```

备份步骤只在首次升级前执行一次，保留原始旧版快照，勿用新版数据覆盖备份。
备份包含私钥，保持 root 私有。试用期间暂停该测试机的自动版本更新，避免切回正式版。

## 需要验证的行为

同一台机器先跑旧版、再跑新版，保持配置、对端、网络和负载相同：

| 场景 | 通过条件 |
| --- | --- |
| 基本联网 | 信息同步正常，IPv4/IPv6 双向实际流量可达 |
| 新旧混用 | 测试机运行新版，其他节点仍用旧版，正常同步和通信 |
| 重启及故障恢复 | 重启 Photon、strongSwan、BIRD，以及断网恢复后能自动恢复通信 |
| 授权更新 | 新授权生效，撤销后受影响的实际流量停止，其他节点不受影响 |
| 升级读取 | 旧版数据直接用于新版时，身份、授权和配置保留，无重复入网要求 |
| 持续运行 | 先跑 24 小时，定期传流量和重复故障恢复；发布前延长至 72 小时 |

记录每次故障发生、恢复连通的时间；记录丢包、CPU、内存和重启次数。
长时间运行应覆盖实际配置的密钥轮换周期，并检查轮换期间通信。
不能只根据进程 active 或 links 显示已连接判定成功；同时检查两端
`photon links`、`swanctl --list-sas`、实际路由和双向流量。
一台测试机只能验证新版与旧网的混合运行，不能替代全新版多节点组网验收。

故障注入放在专用测试节点；让节点断网或重启网络组件前，准备控制台或带外访问。
原始日志可用 `sudo journalctl -u photon --since '24 hours ago'` 导出，分享前去除敏感信息。

## 回退

本次未承诺新版写过的数据库可由旧版直接读取。回退应恢复旧程序及升级前数据，
会丢弃测试期间的本地变更；恢复后的节点仍需重新同步当前网络授权。
默认路径示例（先停止所有使用该数据库的服务）：

```sh
sudo systemctl stop photon
sudo mv /etc/photon /etc/photon-rc2-saved
sudo cp -a /var/backups/photon-before-rc2/etc-photon /etc/photon
sudo cp -a /var/backups/photon-before-rc2/photon /var/backups/photon-before-rc2/photon-services /usr/local/bin/
sudo systemctl start photon
photon version
```

`/etc/photon-rc2-saved` 必须尚不存在，保留新版数据供诊断。回退后再次确认真实通信，
必要时重启测试机清理运行中的网络状态，不只检查程序版本。

## 发布者检查

发布前执行 `make check`、`make smoke-all`、`make install-script-check`；
记录特权数据面测试、真实升级和长时间测试是否实际执行，不以基础检查替代它们。
GitHub Actions 必须提供两种 Linux 架构的归档和校验文件，Release 标记为
Pre-release，Docker 镜像使用显式 `v0.6.0-rc.2` 标签，正式 `latest` 保持不变。
