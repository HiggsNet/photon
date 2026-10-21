# WSL2 Photon 客户端：安装与配置

在 WSL2 Ubuntu 里把 Photon 作为 mesh 客户端跑起来。数据面用 `xfrm_backend: policy`，不需要 `CONFIG_XFRM_INTERFACE`。原理见 `wsl2-xfrm-backend.md`。

说明：下面的命令在 WSL2 内执行。`<higgs>` 是本仓库根目录。zone 名带结尾的点，例如 `wsl2-poc.slapaper.`。

## 1. 准备环境

WSL 必须使用 NAT 网络。Mirrored 模式下，Hyper-V 虚拟交换机会丢掉 xfrm 处理后的包，policy 和 VTI 都不通。这与端口无关。

本方案只覆盖 IPv4。WSL2 的 NAT 模式没有 IPv6 underlay。mesh 双栈在 WSL2 上做不到，不是配置问题。

1. 安装依赖。

   ```bash
   sudo apt-get update
   sudo apt-get install -y golang-go make strongswan strongswan-charon \
     strongswan-swanctl libstrongswan-extra-plugins libstrongswan-standard-plugins iproute2
   ```

2. 在国内网络下先设置模块代理，再编译。

   ```bash
   go env -w GOPROXY=https://goproxy.cn,direct
   cd <higgs>
   make build
   ```

3. 做能力预检。预检要求 root 或 `CAP_NET_ADMIN`，不要求 `CONFIG_XFRM_INTERFACE`。此时 charon 还没启动，VICI socket 这一项会失败，其余项必须通过。

   ```bash
   sudo docs/scripts/wsl2-preflight.sh
   ```

`make check` 是全量测试，安装时不必跑。

## 2. 加入 mesh

zone 签名密钥由客户端生成。IKE 用的 transport 密钥由 daemon 写入 `state.db`，不必预生成。

1. 生成 zone 签名密钥。

   ```bash
   mkdir -p ~/.photon-poc
   chmod 700 ~/.photon-poc
   <higgs>/build/photon gossip keygen ~/.photon-poc/zone-key.json
   ```

2. 生成加入请求，把 `join-request.b64` 交给 gateway 管理员。

   ```bash
   <higgs>/build/photon gossip join request <zone> \
     ~/.photon-poc/zone-key.json ~/.photon-poc/join-request.b64
   ```

3. gateway 管理员签发 delegation，把 `bundle-output.b64` 交回客户端。

   ```bash
   photon-admin gossip delegate issue --permissions write --direct \
     <join-request.b64> <bundle-output.b64>
   ```

4. 客户端保存 bundle，写入本地数据库。这一步不联系 daemon。此时还没有 `config.yaml`，不设 `PHOTON_STATE` 会写入 `/etc/photon/photon.db`。

   ```bash
   sudo mkdir -p /var/lib/photon
   sudo env PHOTON_STATE=/var/lib/photon/state.db \
     <higgs>/build/photon gossip join accept --direct \
     ~/.photon-poc/join-bundle.b64 ~/.photon-poc/zone-key.json
   ```

## 3. 写配置

复制 `contrib/wsl2/` 下的模板，替换 `{{...}}`。字段对照见该目录的 `config.yaml.template`、`charon.conf.template`、`env.template`。

`config.yaml` 至少包含这些项：

```yaml
data_dir: /var/lib/photon
state_path: /var/lib/photon/state.db
trusted_root_public_key: <管理员提供的根公钥>

gossip:
  peer_id: <本机 zone>
  listen_addr: "[::]:33434"
  bootstrap:
    - id: <gateway zone>
      addr: <gateway-ip>:33434

netns:
  default:
    kind: host

ipsec:
  role: out
  driver: strongswan
  xfrm_backend: policy
  vici_socket: /run/photon/charon.vici

overlays:
  - id: wsl2-poc
    connect:
      - "strongswan://*"
    tunnel_address:
      mode: derived-pool
      family: ipv4
      pool: 10.60.0.0/24
```

- `xfrm_backend` 不写时默认为 `interface`。标准 WSL2 内核没有 xfrm interface，daemon 起不来。WSL2 客户端必须写 `policy`。
- `vici_socket` 必须和 charon 配置里的 `plugins.vici.socket` 是同一个路径。
- `role: out` 表示本机只主动建隧道。gateway 侧用自己的角色配置，不要照抄这一项。
- overlay 的 `id` 和 `pool` 必须与 gateway 上为这个客户端准备的 overlay 一致。PoC 用 `wsl2-poc`；接入现有 mesh 时改成 gateway 给出的 id。
- `trusted_root_public_key`、`peer_id`、`bootstrap` 由 gateway 管理员提供。zone 名带结尾的点。
- YAML 不展开 `~`。`data_dir` 和 `state_path` 必须写绝对路径，并且 `state_path` 必须就是上面 `PHOTON_STATE` 指向的文件。

端口：NAT 模式下 500 和 4500 可用，上面的配置不用写端口。Windows 的 IKEEXT 占用了这两个端口时，客户端和 gateway 必须改成同一对非默认端口，例如 33700 和 33701：

```yaml
ipsec:
  fixed_ike_port: 33700
  fixed_natt_port: 33701
```

charon 的 `port` 和 `port_nat_t` 必须与这两个值相同。只改一侧时，IKE 协商对不上。

## 4. 启动

先启动 charon，再启动 daemon。charon 和 daemon 都要 root：xfrm 操作需要 `CAP_NET_ADMIN`。

1. 写 charon 配置。`process_route = no` 不能省，见第 6 节。

   ```bash
   sudo mkdir -p /run/photon
   cat > ~/.photon-poc/charon.conf <<'EOF'
   charon {
       install_routes = no
       process_route = no
       port = 500
       port_nat_t = 4500
       make_before_break = yes
       plugins {
           vici {
               socket = unix:///run/photon/charon.vici
           }
       }
   }
   EOF
   ```

2. 启动 charon。

   ```bash
   sudo STRONGSWAN_CONF=~/.photon-poc/charon.conf /usr/lib/ipsec/charon &
   ```

3. 确认 VICI socket 已出现，再做一次预检。这一次 VICI 项也必须通过。

   ```bash
   sudo test -S /run/photon/charon.vici
   sudo docs/scripts/wsl2-preflight.sh
   ```

4. 启动 daemon。`PHOTON_CONTROL_SOCKET` 不设置时，`photon links` 找不到这个 daemon。

   ```bash
   sudo env PHOTON_CONFIG=~/.photon-poc/config.yaml \
     PHOTON_CONTROL_SOCKET=~/.photon-poc/photon.sock \
     <higgs>/build/photon daemon
   ```

5. 另开一个 WSL 终端，查看隧道状态并 ping gateway。`<gateway-tunnel-address>` 从 `links` 输出里取。

   ```bash
   sudo env PHOTON_CONTROL_SOCKET=~/.photon-poc/photon.sock \
     <higgs>/build/photon links --verbose
   ping <gateway-tunnel-address>
   ```

后台启动可以用 `contrib/wsl2/start-wsl2.sh`。脚本从同目录的 `env.sh` 读取变量，并要求同目录已经放好 `config.yaml` 和 `charon.conf`。停止用同目录的 `stop-wsl2.sh`。要用 systemd 时，先在 `/etc/wsl.conf` 里启用 `[boot] systemd=true`，再套 `contrib/wsl2/photon-wsl2.service.template`。

## 5. gateway 侧

客户端加入之后，gateway 还要让这个客户端的隧道地址进路由和防火墙。在 gateway 上操作，不要在 WSL 里执行。

1. 增加一个只匹配该客户端的 overlay。`id` 和 `pool` 与客户端配置相同。已有的 `ipsec-main` 保持不动。

   ```yaml
   overlays:
     - id: ipsec-main
       connect:
         - "strongswan://*"
     - id: wsl2-poc
       connect:
         - "strongswan://wsl2-poc.*"
       tunnel_address:
         mode: derived-pool
         family: ipv4
         pool: 10.60.0.0/24
   ```

2. 由 root zone 运营者向父 zone 委派 IPv4 前缀，再把前缀分给客户端。没有这一步时，客户端地址进不了地址路由系统（ARS），防火墙不会放行。

   ```bash
   photon-admin route ipam pool create --direct <parent-zone> <pool-prefix> \
     --delegated-to <client-zone>
   photon-admin route ipam assign --direct <parent-zone> <assigned-prefix> \
     --to <client-zone>
   ```

3. 等客户端宣告路由。route installer 会在 gateway 的 photon netns 里装回程路由。

Photon 防火墙默认丢弃。IPAM 分配和路由宣告完成之后，firewall reconcile 会生成放行规则。

PoC 可以手工放行，不必等 reconcile。`<client-tunnel-prefix>` 用分配给该客户端的前缀。

```bash
ip netns exec photon nft insert rule inet photon_default photon_default_input \
  ip saddr <client-tunnel-prefix> accept
ip netns exec photon nft insert rule inet photon_default photon_default_forward \
  ip saddr <client-tunnel-prefix> accept
```

也可以跑 `docs/scripts/gateway-wsl2-poc-setup.sh`。这个脚本会装回程路由，并放行解封装后 conntrack 状态为 invalid 的包。

注意：这个脚本写入的路由和防火墙规则在 photon daemon 重启后消失。重启 gateway 的 daemon 之后要再跑一次。长期使用靠 route installer 和 firewall reconcile，不要靠这个脚本。

## 6. 注意事项

警告：不要删除 `state.db`。daemon 会生成新的 transport 密钥，与 mesh 里缓存的旧记录版本冲突。之后必须换一个新的 zone 名，重新走第 2 节。

注意：charon 必须设置 `process_route = no`。不设置时，charon 会给已经路由的子网安装 bypass 策略，mesh 流量不进隧道。现象是隧道状态为 up，ping 不通。

注意：对端路由由 policy 后端在 `EnsureInterface` 里安装。Create、Adopt、Repair、Staged 都会走这一步。路由缺失时隧道能建立，流量没有路径。先查 `ip route get <对端隧道地址>`，确认源地址是本端隧道地址。

说明：DPD、rekey 和撤销还没有做长时间实网验证。policy 加 NAT IPv4 已对真实 gateway（interface 后端）完成 ICMP 和 TCP 连通验证。

说明：`netns.default.kind: host` 表示 charon 把 xfrm 策略装在 WSL 宿主网络命名空间。这项与 `xfrm_backend: policy` 互不绑定，PoC 用 host 即可。
