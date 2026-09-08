# WSL2 Photon Client 快速启动指南

> 前提：WSL2 Ubuntu，**NAT 网络模式**（Mirrored 模式与 xfrm 数据面不兼容，见第 6 节），
> 已安装 strongswan/charon

## 1. 一键部署

```bash
# 在 WSL2 内执行
cd /path/to/higgs

# 安装依赖
sudo apt-get install -y golang-go make strongswan strongswan-charon \
  strongswan-swanctl libstrongswan-extra-plugins libstrongswan-standard-plugins iproute2

# 构建并验证
make build
make check                                  # 全量测试
sudo docs/scripts/wsl2-preflight.sh         # 内核能力预检（不要求 CONFIG_XFRM_INTERFACE）

# 国内网络
go env -w GOPROXY=https://goproxy.cn,direct
```

## 2. 加入 mesh 网络

### 2.1 生成密钥

```bash
mkdir -p ~/.photon-poc && chmod 700 ~/.photon-poc

# Zone signing key（zone 身份）
/path/to/higgs/build/photon gossip keygen ~/.photon-poc/zone-key.json

# Transport key（IKE 认证）——由 daemon 自动生成
# 如需预生成，使用 tools-seedkey 工具
```

### 2.2 创建 join request 并发给 gateway 管理员

```bash
# <zone> 格式: <名字>.<parent-zone>，如 wsl2-poc.slapaper.
/path/to/higgs/build/photon gossip join request <zone> ~/.photon-poc/zone-key.json ~/.photon-poc/join-request.b64

# 将 join-request.b64 内容发给 gateway 管理员
```

### 2.3 gateway 管理员操作

```bash
# 签发 delegation
photon-admin gossip delegate issue --permissions write --direct <join-request.b64> <bundle-output.b64>

# 将 bundle-output.b64 返回给 client
```

### 2.4 client 接受并加入

```bash
# 保存 bundle 后
/path/to/higgs/build/photon gossip join accept --direct ~/.photon-poc/join-bundle.b64 ~/.photon-poc/zone-key.json
```

## 3. 配置

创建 `~/.photon-poc/config.yaml`：

```yaml
data_dir: <data-dir>
state_path: <state-db-path>
trusted_root_public_key: <由管理员提供>

gossip:
  peer_id: <your-zone>
  listen_addr: "[::]:33434"
  bootstrap:
    - id: <gateway-zone>
      addr: <gateway-ip>:33434

netns:
  default:
    kind: host          # WSL2 client 用宿主 netns（无需隔离）

ipsec:
  role: out
  driver: strongswan
  xfrm_backend: policy  # 纯 xfrm 策略数据面，不要求 CONFIG_XFRM_INTERFACE
  vici_socket: <charon-vici-socket-path>
  # 如 500/4500 被宿主服务占用（如 Windows IKEEXT）
  # fixed_ike_port: 33700
  # fixed_natt_port: 33701

overlays:
  - id: wsl2-poc         # 独立 overlay（PoC）或 ipsec-main（正式）
    connect:
      - "strongswan://*"
    tunnel_address:
      mode: derived-pool
      family: ipv4
      pool: 10.60.0.0/24
```

## 4. 启动

### 4.1 charon（需要 root，自定义配置避免端口冲突）

```bash
# 创建 charon 配置（模板见 contrib/wsl2/charon.conf.template）
cat > ~/.photon-poc/charon.conf <<'EOF'
charon {
    install_routes = no
    process_route = no    # 阻止 bypass policy 安装，防止 mesh 流量绕过隧道
    port = 500            # NAT 模式默认端口即可；冲突时改用 fixed_*_port 对应值
    port_nat_t = 4500
    make_before_break = yes
    plugins {
        vici {
            socket = unix://<vici-socket-path>
        }
    }
}
EOF

# 启动 charon（前台或后台）
sudo STRONGSWAN_CONF=~/.photon-poc/charon.conf /usr/lib/ipsec/charon &
```

### 4.2 photon daemon

```bash
sudo env PHOTON_CONFIG=~/.photon-poc/config.yaml \
  PHOTON_CONTROL_SOCKET=~/.photon-poc/photon.sock \
  /path/to/higgs/build/photon daemon
```

### 4.3 验证

```bash
# 查看链接状态
photon links --verbose

# 测试数据面
ping <gateway-tunnel-address>   # 从 links 输出获取
```

## 5. gateway 侧配置要点

### 5.1 独立 overlay（隔离 PoC 流量）

```yaml
overlays:
  - id: ipsec-main        # 现有 mesh overlay
    connect:
      - "strongswan://*"
  - id: wsl2-poc          # WSL2 PoC overlay
    connect:
      - "strongswan://wsl2-poc.*"
    tunnel_address:
      mode: derived-pool
      family: ipv4
      pool: 10.60.0.0/24
```

### 5.2 IPAM 分配（使 client 地址进入 ARS）

```bash
photon-admin route ipam pool create --direct <parent-zone> <pool-prefix> --delegated-to <client-zone>
photon-admin route ipam assign --direct <parent-zone> <assigned-prefix> --to <client-zone>
```

### 5.3 回程路由（client announce 后）

```bash
# 在 gateway 的 photon netns
ip netns exec photon ip route replace <client-tunnel-addr>/32 dev phx<id>

# 或等 client 的 route announcement 自动传播（route installer）
```

### 5.4 防火墙

Photon 防火墙 default-drop，需要 client 地址在 ARS 中。
IPAM assignment + route announcement 后，firewall reconcile 自动生成放行规则。

临时 PoC 放行：
```bash
ip netns exec photon nft insert rule inet photon_default photon_default_input \
  ip saddr <client-tunnel-prefix> accept
ip netns exec photon nft insert rule inet photon_default photon_default_forward \
  ip saddr <client-tunnel-prefix> accept
```

## 6. WSL 网络模式（平台事实）

| 模式 | 结论 |
|---|---|
| **NAT** | 唯一可用模式。IPv4 underlay，标准网络栈，xfrm 数据面正常 |
| Mirrored | **不可用**：Hyper-V 虚拟交换机拦截 xfrm 处理后的包，纯策略与 VTI 数据面均不通（实验确认，与端口无关） |

IPv6：WSL2 NAT 模式无 IPv6 underlay，Mirrored 模式数据面本就不通，因此本方案仅覆盖
IPv4；mesh 双栈在 WSL2 上属平台限制，非配置问题。

## 7. 运维注意事项

- **state.db 不可随意删除**：删除后 daemon 生成新 transport key，与 mesh 缓存的旧 record 版本冲突，必须换新 zone 名重新 join
- **charon 需要 root**：xfrm 操作需要 CAP_NET_ADMIN
- **`process_route = no`**：charon 默认会对已路由子网安装 bypass 策略，会使 mesh 流量绕过隧道直连，必须关闭
- **gateway 防火墙 default-drop**：client 地址需在 ARS 中（通过 IPAM + announcement）才能通 TCP/UDP
