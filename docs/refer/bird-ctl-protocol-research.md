# BIRD control (ctl) 协议与健康检查/debug 解析调研

> 调研目标：明确 BIRD `birdc` Unix socket 控制协议的返回格式，核对 Photon 当前在健康检查与 debug 命令中对 BIRD 输出的解析是否存在假设错误、版本相关正则不一致等问题。
>
> 环境：BIRD 2.19.1（`/run/current-system/sw/bin/bird`），源码参考 CZ-NIC/bird（当前 shallow clone 为 2.19.0）。

> 实施状态（2026-07-16）：调研中列出的解析偏差已在
> `pkg/routing/bird` 修正。控制客户端现在校验 `0001 BIRD ...` 问候语；接口、
> 路由和邻居夹具均使用官方 IP-first / headerless 的实际输出；同时恢复了
> kernel `merge paths on [limit N]` 配置渲染。下文保留原始问题与证据，作为格式兼容性依据。

## 1. BIRD CLI 协议格式（协议层）

BIRD 的 CLI 协议在官方 Programmer's Documentation 中有明确定义，实现位于：

- 服务端：`nest/cli.c`、`nest/cli.h`
- 客户端：`client/client.c`、`client/birdc.c`、`client/birdcl.c`

协议要点：

1. **传输**：基于 stream（Unix domain socket），每条请求是一行以 `\n` 结尾的文本命令；每个回复由若干行组成。
2. **回复行格式**：每行以 **4 位数字回复码**开头，后接：
   - `' '`（空格）：该回复的最后一行；
   - `'-'`：后续还有同码的续行；
   - 若下一行与上一行**回复码相同**且是续行，整行前缀可以简化为单个空格 `' '`。
3. **回复码语义**（`nest/cli.c` 注释）：
   - `0xxx`：操作成功完成；
   - `1xxx`：表项/数据行；
   - `8xxx`：运行时错误；
   - `9xxx`：语法错误。
4. **特殊行**：
   - 异步日志回显以 `'+'` 开头（code `CLI_ASYNC_CODE = 10000`，birdc 显示为 `>>> ...`）。
   - 连接建立后服务端主动发送一行问候语：`0001 BIRD <version> ready.`。
5. **命令结束判定**：客户端读到任意 `XXXX `（空格结尾）的最终行即表示该命令回复结束；常见成功结束码是 `0000 ` 或 `0013 ` 等。

客户端 `client/client.c` 的 `server_got_reply()` 处理逻辑可概括为：

```c
if (*x == '+')            /* 异步消息 */
else if (x[0] == ' ')     /* 续行（与上一码相同） */
else if (strlen(x) > 4 && sscanf(x, "%d", &code) == 1 && code >= 0 && code < 10000 &&
         (x[4] == ' ' || x[4] == '-'))
    /* 正式回复码行 */
else
    /* 无法识别 */
```

> **Photon 现状**：`pkg/routing/bird/client.go` 的 `completeResponse()` 基本符合该协议：扫描到 `0000 ` 或任意 `XXXX ` 最终行即结束；`stripCodes()` 也能正确去掉 `XXXX-` / `XXXX ` 前缀。协议层本身没有明显问题。

## 2. 各命令实际输出格式与 Photon 解析对照

以下均为 BIRD 2.19.1 实测输出（使用 `birdc -v` 显示原始码）。

### 2.1 `show status`

```text
0001 BIRD 2.19.1 ready.
1000-BIRD 2.19.1
1011-Router ID is 1.2.3.4
     Hostname is road
     Current server time is 2026-07-16 13:05:42.765
     Last reboot on 2026-07-16 13:05:41.762
     Last reconfiguration on 2026-07-16 13:05:41.762
0013 Daemon is up and running
```

源码实现（`nest/cmds.c:cmd_show_status`）：

```c
cli_msg(-1000, "BIRD " BIRD_VERSION);
cli_msg(-1011, "Router ID is %R", config->router_id);
cli_msg(-1011, "Hostname is %s", config->hostname);
cli_msg(-1011, "Current server time is %s", tim);
cli_msg(-1011, "Last reboot on %s", tim);
cli_msg(-1011, "Last reconfiguration on %s", tim);
...
cli_msg(13, "Daemon is up and running");
```

**Photon 解析**：`parseStatus()` 使用正则提取 `BIRD x.x.x`、`Router ID`、时间戳。与源码一致，**无明显问题**。

### 2.2 `show protocols all`

```text
2002-Name       Proto      Table      State  Since         Info
1002-device1    Device     ---        up     13:05:41.762  
1006-
1002-direct1    Direct     ---        up     13:05:41.762  
1006-  Channel ipv4
         State:          UP
         Table:          master4
         Preference:     240
         ...
```

源码实现（`nest/proto.c:proto_cmd_show`）：

```c
if (!cnt)
    cli_msg(-2002, "%-10s %-10s %-10s %-6s %-12s  %s",
            "Name", "Proto", "Table", "State", "Since", "Info");

cli_msg(-1002, "%-10s %-10s %-10s %-6s %-12s  %s",
        p->name, p->proto->name,
        p->main_channel ? p->main_channel->table->name : "---",
        proto_state_name(p), tbuf, buf);

if (verbose) {
    ...
    cli_msg(-1006, "");
}
```

**Photon 解析**：

- `protocolHeaderRe` 匹配 `Name Proto Table State Since Info`。
- `protocolRowRe` 按空白分 6 列。
- 缩进续行被追加到前一项的 `Info`。

**问题**：`Since` 列在时间不够长时可能是 `13:05:41.762` 这种只有时间没有日期的形式；`parseTime()` 虽然支持 `06-01-02 15:04:05` 等格式，但**不支持纯时间** `15:04:05.000`。当天内启动的协议，`Since` 会被解析失败（零值），但程序不会报错，只是 silently 丢失信息。这会导致 debug 输出里 `Since` 为空。

### 2.3 `show interfaces`

```text
1001-lo up (index=1)
1004-	MultiAccess AdminUp LinkUp Loopback Ignored MTU=65536
1003-	127.0.0.1/8 (Preferred, scope host)
      	2a0d:2904:0:f5f5::e:1/128 (Preferred, scope univ)
      	::1/128 (scope host)
1001-eth0 up (index=2)
1004-	MultiAccess Broadcast Multicast AdminUp LinkUp MTU=1500
1003-	10.16.255.8/22 (Preferred, scope site)
     	2408:8207:1852:dd30:43fc:3c79:23a2:fb39/64 (Secondary, scope univ)
     	...
1001-vlan.5.photon up (index=3)
1001-br-0566fa9804df up (index=5 master=br-0566fa9804df)
```

源码实现（`nest/iface.c:if_show`）：

```c
cli_msg(-1001, "%s %s (index=%d%s)", i->name, (i->flags & IF_UP) ? "up" : "down", i->index, mbuf);
cli_msg(-1004, "\t%s%s%s Admin%s Link%s%s%s MTU=%d", ...);
WALK_LIST(a, i->addrs)
    if (a->prefix.type == NET_IP4)
        if_show_addr(a);
WALK_LIST(a, i->addrs)
    if (a->prefix.type == NET_IP6)
        if_show_addr(a);
```

注意：**输出没有 `Interface State MTU Link-local` 之类的表头**；第一行直接就是接口名。

**Photon 解析**：`interfaceHeaderRe = (?im)^\s*(?:Interface|Iface)\s+`，`parseInterfaces()` 在找到该 header 之前会一直 `continue`。由于真实输出没有这样的 header，**`parseInterfaces()` 会返回空列表**。这是一个明确的 bug。

Photon 测试里的 `sampleShowInterfaces` 是人工构造的：

```text
1002-Interface  State  MTU  Link-local
eth0       up     1500 fe80::1
```

这个表头在真实 BIRD 输出中不存在，因此单元测试没有覆盖真实行为。

### 2.4 `show route all`

```text
1007-Table master4:
     172.18.0.0/16        unicast [direct1 13:05:41.763] ! (240)
        dev br-0566fa9804df
1008-	Type: device univ
1007-10.16.252.0/22       unicast [direct1 13:05:41.763] ! (240)
        dev eth0
1008-	Type: device univ
1007-2a0d:2904:0:f5f5::e:0/112 unicast [direct1 13:05:41.763] ! (240)
        dev vlan.5.photon
1008-	Type: device univ
```

源码实现（`nest/rt-show.c:rt_show_rte`）：

```c
cli_printf(c, -1007, "%-20s %s [%s %s%s]%s%s", ia, rta_dest_name(a->dest),
           e->src->proto->name, tm, from, primary ? (sync_error ? " !" : " *") : "", info);

if (a->dest == RTD_UNICAST)
    for (nh = &(a->nh); nh; nh = nh->next) {
        ...
        if (ipa_nonzero(nh->gw))
            cli_printf(c, -1007, "\tvia %I on %s%s%s%s", ...);
        else
            cli_printf(c, -1007, "\tdev %s%s%s", nh->iface->name, ...);
    }
```

**Photon 解析**：

- `routeLineRe`：`^\s*(\S+?)\s+(?:unicast|multicast)?\s*\[([^\]]+)\]\s*(\*)?\s*\((\d+)(?:/\d+)?\)`
  - 能匹配 `[proto timestamp] * (pref)` 与 `[proto timestamp] ! (pref)`，因为 `!` 不被 `(\*)?` 消费，后续 `\s*` 会吃掉空格。
  - **但未处理 `blackhole`/`unreachable`/`prohibit` 等 dest 类型**（当前只可选 `unicast|multicast`）。
- `routeViaRe`：只匹配 `via <gw> on <iface>`。
- **未匹配 `dev <iface>`**：对于 on-link 直连路由（如上面的 `dev br-0566fa9804df`），`Iface` 字段不会被填充。
- `routeFromRe`：匹配 `from <gw>`，但 BIRD 仅在 `from != gw` 时输出 `from ...`。
- Source 提取：代码查找包含 `Source:` 或 `source` 的行。但真实 verbose 输出使用 `Type: device univ`，没有 `Source:`。因此 `Source` 字段通常不会被填入，健康检查里的 `birdRouteIsBabel()` 只能依赖 `Protocol` 字段包含 `babel`。

**问题总结**：

1. `dev <iface>` 形式未被解析，导致部分路由没有 `Iface`。
2. `unicast|multicast` 之外的 destination type 会整行不匹配。
3. `Source` 字段设计意图（用于判断路由来源）与真实输出不一致。

### 2.5 `show babel neighbors`

BIRD 2.19.1 实测（无邻居时只有 header）：

```text
1024-babel1:
     IP address                Interface  Metric Routes Hellos Expires Auth  RTT (ms)
```

源码实现（`proto/babel/babel.c:babel_show_neighbors`）：

```c
cli_msg(-1024, "%s:", p->p.name);
cli_msg(-1024, "%-25s %-10s %6s %6s %6s %7s %4s %9s",
        "IP address", "Interface", "Metric", "Routes", "Hellos", "Expires", "Auth", "RTT (ms)");
...
cli_msg(-1024, "%-25I %-10s %6u %6u %6u %7t %-4s %9t",
        n->addr, ifa->iface->name, n->cost, rts, hellos, MAX(timer, 0),
        n->auth_passed ? "Yes" : "No", n->srtt * 1000);
```

即当前格式为 **IP address | Interface | Metric | ...**（IP 在前）。

**Photon 解析**：`parseBabelNeighbors()` 同时识别两种 header：

- `babelLegacyHeaderRe = ^\s*Interface\s+Neighbor`（Interface 在前）
- `babelV219HeaderRe   = ^\s*IP\s+address\s+Interface\s+Metric`（IP 在前）

并对两种列顺序分别解析。

#### 关键验证：旧版 BIRD 到底是什么格式？

为确认 "legacy" 分支是否真实存在，我拉取了多个官方 BIRD 版本的源码核对了 `babel_show_neighbors()`：

| BIRD 版本 | `show babel neighbors` 表头 | 格式 |
|-----------|----------------------------|------|
| 1.6.8 | `IP address Interface Metric Routes Next hello` | IP-first |
| 2.0.0 | `IP address Interface Metric Routes Hellos Expires` | IP-first |
| 2.0.12 | `IP address Interface Metric Routes Hellos Expires Auth` | IP-first |
| 2.15 | `IP address Interface Metric Routes Hellos Expires Auth RTT (ms)` | IP-first |
| 2.16 | `IP address Interface Metric Routes Hellos Expires Auth RTT (ms)` | IP-first |
| 2.19.0/2.19.1 | `IP address Interface Metric Routes Hellos Expires Auth RTT (ms)` | IP-first |

**结论**：在官方 BIRD 1.6.8 到 2.19.1 的所有版本中，`show babel neighbors` 都是 **IP 地址在前、Interface 在后的 5~8 列格式**，从未出现过 Photon 代码里假设的 `Interface Neighbor Metric` 3 列 Interface-first 格式。

Photon 测试夹具里的：

```text
Interface  Neighbor           Metric
eth0       fe80::2             256
```

是**完全虚构的**，与任何官方 BIRD 版本都不符。因此：

- `babelV219HeaderRe` 分支能正确处理所有官方 BIRD 版本。
- `babelLegacyHeaderRe` 分支基于错误假设，永远不会匹配到真实的 BIRD 输出；即使误匹配，按 3 列解析也会把 IP 地址和接口名填反。

> 注：Photon 预检要求 BIRD ≥ 2.0，因此 BIRD 1.6.8 本就不在支持范围内；但即使扩展到 1.6.x，也仍然是 IP-first。如果确实需要支持某个非官方 fork 或补丁版出现的 Interface-first 输出，应当在注释中明确说明其来源，而不是泛称为 "legacy"。

## 3. 健康检查与 debug 命令中的实际影响

### 3.1 健康检查（BIRD/Babel cutover gate）

相关代码：

- `internal/photonlinux/routing_health.go:BirdObservationForInterface()`
- `pkg/health/manager.go:cutoverBlockingLocked()`

逻辑：只有 staged 链路的 `Neighbor == true && Route == true` 时，才允许 IPsec 切换。

- `Neighbor` 依赖 `parseBabelNeighbors()`：BIRD 2.19.x 格式处理正确；旧版 BIRD（2.0~2.16）也是 IP-first，同样能被 `babelV219HeaderRe` 处理。`babelLegacyHeaderRe` 对应的 Interface-first 格式在官方 BIRD 中不存在。
- `Route` 依赖 `parseRoutes()` 与 `birdRouteIsBabel()`：
  - 判断条件为 `Protocol` 含 `babel` 或 `Source` 含 `babel`。
  - 由于 `Source` 基本不会被填入，实际只看 `Protocol`。
  - Babel 路由的 `Protocol` 是 `photon_babel_<netns>`，含 `babel`，因此能匹配。
  - 但如果某条 Babel 路由是 on-link 且使用 `dev <iface>`，Photon 解析不到 `Iface`，该路由会被忽略，可能导致 `Route` 误判为 false。
- `Interfaces` 未被健康检查直接依赖，但 `BirdObservationForInterface()` 的参数 `iface` 来自链路状态而非 BIRD 接口表。

**风险**：在特定场景（on-link Babel 路由、或路由通过 `dev` 而非 `via` 表达）下，健康检查可能错误地认为没有可用路由，从而阻塞切换。

### 3.2 `photon debug bird-dump`

相关代码：

- `app/photon/debug_routing.go:debugBirdDumpWithRuntime()`、`birdDumpOffline()`
- 默认命令集：`show status`、`show protocols all`、`show route all`、`show interfaces`、`show babel neighbors`、各 internal table 的 `show route table <t> all`。

`bird-dump` 主要调用 `client.Raw()`，对原始文本输出友好，**本身不依赖解析器**。但如果用户通过 daemon 的 `routes_dump` 控制接口查看结构化数据，则会受到 `parseRoutes()` / `parseInterfaces()` 准确性的影响。

### 3.3 `photon debug babel`

相关代码：

- `app/photon/debug_routing.go:debugBabelWithRuntime()`、`buildBabelDebugView()`

该命令优先通过 daemon 控制接口获取 `bird_status`，回退到本地状态文件。若 daemon 返回的 `BirdInstances` 中接口/路由/邻居数据来自 `Client.Status()` 的解析结果，则 `show interfaces` 解析为空会直接影响 debug 视图的完整性。

## 4. 发现的问题汇总

| # | 位置 | 问题 | 严重程度 | 说明 |
|---|------|------|----------|------|
| 1 | `pkg/routing/bird/parser.go:parseInterfaces()` | 真实 BIRD `show interfaces` 没有 `Interface/Iface` 表头，解析器会返回空列表 | **高** | 单元测试使用了不存在的表头，未覆盖真实输出 |
| 2 | `pkg/routing/bird/parser.go:parseRoutes()` | 未处理 `dev <iface>` 形式的 on-link 路由 | 中 | 导致部分路由 `Iface` 为空，影响健康检查 `Route` 判断 |
| 3 | `pkg/routing/bird/parser.go:parseRoutes()` | `routeLineRe` 只可选 `unicast\|multicast`，未覆盖 `blackhole/unreachable/prohibit` 等 dest | 中 | 这类路由会被完全跳过 |
| 4 | `pkg/routing/bird/parser.go:parseRoutes()` | 通过 `Source:`/`source` 提取 `Source`，但真实 verbose 输出使用 `Type:` | 低 | `Source` 字段基本不可用；健康检查实际依赖 `Protocol` |
| 5 | `pkg/routing/bird/parser.go:parseProtocols()` | `Since` 字段为纯时间（无日期）时 `parseTime()` 失败 | 低 | 当天启动的协议 `Since` 会显示为空 |
| 6 | `pkg/routing/bird/client_test.go` | 测试夹具 `sampleShowInterfaces` 包含虚假的 `Interface State MTU Link-local` 表头 | 中 | 测试通过但不能验证真实 BIRD 输出 |
| 7 | `pkg/routing/bird/generator.go` | 将 `ecmp on limit N` 写进 `protocol babel` | **高** | BIRD 2.19.1 在该位置报 `unexpected ECMP` 并退出；已改为 kernel `merge paths on limit N` |
| 8 | `pkg/routing/bird/parser.go:parseBabelNeighbors()` | `babelLegacyHeaderRe` 假设的 Interface-first 格式在官方 BIRD 中不存在 | 中 | 该分支永远不会命中；测试夹具 `sampleShowBabelNeighbors` 是虚构格式 |

## 5. 修复建议

### 5.1 立即修复

1. **重写 `parseInterfaces()`**
   - 去掉对 `Interface/Iface` 表头的依赖；直接识别 `^\s*(\S+)\s+(up|down)\s+\(index=(\d+)` 作为接口起始行。
   - 解析后续 `MTU=\d+` 行获取 MTU。
   - 解析缩进的 `\t<addr>/<len> ...` 地址行。
   - 更新 `client_test.go` 中的 `sampleShowInterfaces` 为真实 BIRD 2.19.1 输出。

2. **修复 `parseRoutes()`**
   - 支持 `dev <iface>` 作为 `via <gw> on <iface>` 的替代。
   - 扩展 `routeLineRe` 中的 destination type，覆盖 `unicast`、`multicast`、`blackhole`、`unreachable`、`prohibit` 等。
   - 若仍希望保留 `Source` 字段，应基于 `Type:` 行或 `[<proto> ...]` 的协议名提取，而不是查找 `Source:`。

### 5.2 测试补强

- 将当前基于人工字符串的测试升级为**真实 BIRD 输出 fixture**（可从本调研中的实测输出截取）。
- 增加针对 `show interfaces`、`show route all` 中 `dev` 形式的解析测试。
- 对于 `show babel neighbors`，删除虚构的 legacy fixture，统一使用真实 BIRD 输出（IP-first，8 列）；如需保留 legacy 分支，必须在注释中写明其来源版本或 fork。

### 5.3 版本策略

- Photon 当前要求 BIRD ≥ 2.0。建议：
  - 明确声明官方支持的最小 BIRD 版本（如 2.15+ 或 2.19+）。
  - 重新评估 `parseBabelNeighbors()` 中的 `babelLegacyHeaderRe` 分支：若无法提供对应的真实 BIRD 版本，应删除该分支及虚构测试夹具，避免误导后续维护者。
- 定期对照目标 BIRD 版本的源码更新 fixture，而不是仅依赖运行时的主观假设。

### 5.4 协议层加固

- `client.go` 中对问候语的解析目前只 `ReadString('\n')` 然后丢弃。建议：
  - 检查问候语是否确实以 `0001 BIRD` 开头，否则返回明确错误（可帮助诊断 socket 被其他进程占用等情况）。
- `completeResponse()` 在遇到异步 `+...` 消息时目前会把它当作普通行保留。若未来启用 log echo，需要考虑这些消息不应被当作命令回复的一部分。

## 6. 参考

- BIRD 官方用户文档：`https://bird.network.cz/?get_doc&v=30&f=bird-4.html`
- BIRD Programmer's Documentation：`https://bird.network.cz/?get_doc&v=30&f=prog-1.html`
- BIRD 源码：`https://github.com/CZ-NIC/bird`
  - `nest/cli.c` / `nest/cli.h`：CLI 协议核心
  - `client/client.c`：`birdc` 客户端实现
  - `nest/cmds.c:cmd_show_status()`：`show status`
  - `nest/proto.c:proto_cmd_show()`：`show protocols [all]`
  - `nest/iface.c:if_show()`：`show interfaces`
  - `nest/rt-show.c:rt_show_rte()`：`show route [all]`
  - `proto/babel/babel.c:babel_show_neighbors()`：`show babel neighbors`
