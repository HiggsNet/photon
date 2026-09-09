# BIRD Babel Adapter API Design

> Scope: `pkg/routing/bird/`
>
> Goal: define the public Go API and BIRD configuration model for the Photon
> BIRD/Babel routing adapter. This file is a design document only — no
> implementation files are produced here.

## Package overview

`package bird` implements the Photon routing adapter for the BIRD routing
daemon running the Babel protocol. It is split into three concerns:

1. **Configuration generation** — turn a `BirdInstanceSpec` and authorized
   prefix sets into a `bird.conf` byte stream.
2. **Control client** — talk to a running BIRD daemon over its Unix control
   socket using `birdc` semantics (`show status`, `configure`, `reload in`,
   `reload out`, `down`).
3. **Process management** — start/stop/adopt BIRD processes inside the
   correct network namespace.

The package intentionally keeps a thin, testable API surface. Higher-level
reconcilers in Photon own the lifecycle timing and policy decisions.

## Dependencies

The API uses only standard-library networking and Photon core packages:

```go
import (
    "context"
    "net/netip"
    "time"

    "github.com/HiggsNet/photon/pkg/core/zone"
    photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)
```

`NetNSSpec` is defined locally in this package (mirroring the shape of
`transport/ipsec.NetNSSpec`) to avoid making `routing` depend on `transport`.

## Configuration spec

### `BirdMode`

```go
// BirdMode controls how Photon relates to the BIRD daemon for one overlay.
type BirdMode string

const (
    // BirdModeManaged means Photon creates the netns, generates the config,
    // starts the BIRD process, and performs crash recovery.
    BirdModeManaged BirdMode = "managed"

    // BirdModeExternal means an external operator owns the BIRD process.
    // Photon only connects via the control socket to configure and observe.
    BirdModeExternal BirdMode = "external"

    // BirdModeDisabled disables routing for the overlay. No config is
    // generated and no process is touched.
    BirdModeDisabled BirdMode = "disabled"
)
```

### `NetNSSpec`

```go
// NetNSSpec describes the network namespace where a BIRD instance runs.
// It intentionally mirrors transport/ipsec.NetNSSpec so callers can copy
// the overlay netns config without conversion.
type NetNSSpec struct {
    Kind   string `yaml:"kind" json:"kind"`     // "host", "name", or "path"
    Name   string `yaml:"name,omitempty" json:"name,omitempty"`
    Path   string `yaml:"path,omitempty" json:"path,omitempty"`
    Create bool   `yaml:"create,omitempty" json:"create,omitempty"`
}
```

### `BabelAuthSpec`

```go
// BabelAuthSpec holds per-interface Babel HMAC authentication parameters.
// BIRD requires the password to be present directly in the config file,
// so this struct is only used when auth is enabled.
type BabelAuthSpec struct {
    Enabled   bool   `yaml:"enabled" json:"enabled"`
    Algorithm string `yaml:"algorithm" json:"algorithm"` // e.g. "hmac sha256"
    KeyID     uint8  `yaml:"key_id" json:"key_id"`
    Password  string `yaml:"password" json:"password"`   // raw key material
}
```

### `BirdInstanceSpec`

`BirdInstanceSpec` is the complete configuration for one BIRD instance
bound to one overlay / netns.

```go
type BirdInstanceSpec struct {
    // RouterID is the 32-bit BIRD router id. It is rendered as an IPv4
    // dotted-quad in bird.conf. Use StableRouterID to derive it.
    RouterID uint32 `yaml:"router_id" json:"router_id"`

    // OverlayID identifies the Photon overlay this instance serves.
    OverlayID string `yaml:"overlay_id" json:"overlay_id"`

    // NetNS is the network namespace where the BIRD daemon must run.
    NetNS NetNSSpec `yaml:"netns" json:"netns"`

    // Paths used by BIRD and birdc.
    ControlSocketPath string `yaml:"control_socket" json:"control_socket"`
    PIDFilePath       string `yaml:"pid_file" json:"pid_file"`
    ConfigPath        string `yaml:"config_path" json:"config_path"`

    // TableID is the kernel routing table to synchronize with. "main" means
    // the default table for the netns. Non-main values are passed to BIRD as
    // "kernel table <id>".
    TableID string `yaml:"table_id" json:"table_id"`

    // InternalTableName is the BIRD-internal table name. If empty, the
    // generator derives a stable name from the overlay id.
    InternalTableName string `yaml:"internal_table_name,omitempty" json:"internal_table_name,omitempty"`

    // Metrics applied to Babel interfaces of different generations.
    MetricBase     uint `yaml:"metric_base" json:"metric_base"`
    MetricStaged   uint `yaml:"metric_staged" json:"metric_staged"`
    MetricDraining uint `yaml:"metric_draining" json:"metric_draining"`

    BabelRTTCost        uint
    BabelRTTMin         time.Duration
    BabelRTTMax         time.Duration
    BabelRTTDecay       uint
    BabelHelloInterval  time.Duration
    BabelUpdateInterval time.Duration

    // InterfacePattern is the BIRD interface glob, e.g. "phx*".
    InterfacePattern string `yaml:"interface_pattern" json:"interface_pattern"`

    // Mode selects managed / external / disabled behavior.
    Mode BirdMode `yaml:"mode" json:"mode"`

    // DeviceScanTime is the "protocol device { scan time ... }" interval.
    // Zero means the generator uses its default (5s).
    DeviceScanTime time.Duration `yaml:"device_scan_time,omitempty" json:"device_scan_time,omitempty"`

    // LogTarget is rendered as the BIRD top-level "log" directive.
    // Empty means the generator uses "log syslog all".
    LogTarget string `yaml:"log_target,omitempty" json:"log_target,omitempty"`

    // BabelAuth configures per-interface HMAC authentication. Nil disables it.
    BabelAuth *BabelAuthSpec `yaml:"babel_auth,omitempty" json:"babel_auth,omitempty"`

    // ECMP enables Babel ECMP for equal-cost paths.
    ECMP bool `yaml:"ecmp,omitempty" json:"ecmp,omitempty"`

    // ECMPLimit is the optional "ecmp on limit N" value. Zero means no limit.
    ECMPLimit uint `yaml:"ecmp_limit,omitempty" json:"ecmp_limit,omitempty"`

    // BogonPrefixes are rejected before any accept logic in rendered filters.
    BogonPrefixes []netip.Prefix `yaml:"bogon_prefixes,omitempty" json:"bogon_prefixes,omitempty"`
}
```

Defaults the generator should apply:

| field | default |
|-------|---------|
| `TableID` | `"main"` |
| `MetricBase` | `100` |
| `MetricStaged` | `1200` |
| `MetricDraining` | `2400` |
| `BabelRTTCost` | `1024` |
| `BabelRTTMin` | `10ms` |
| `BabelRTTMax` | `500ms` |
| `BabelRTTDecay` | `12` |
| `BabelHelloInterval` | `4s` |
| `BabelUpdateInterval` | `16s` |
| `DeviceScanTime` | `5s` |
| `LogTarget` | `"log syslog all"` |

## BIRD config model

`BirdConfig` is the intermediate Go representation used internally by the
config generator. Callers usually do not construct it directly; they pass a
`BirdInstanceSpec` plus prefix sets to `ConfigGenerator.Generate`.

```go
// BirdConfig is a structured model of the desired BIRD configuration.
type BirdConfig struct {
    RouterID      uint32
    LogTarget     string
    ListenSocket  string          // Unix control socket path
    DeviceScanTime time.Duration

    // Internal BIRD table names. Empty means disabled for that family.
    IPv4Table string
    IPv6Table string

    // KernelTableID is the numeric kernel table id, or 0 for the default.
    KernelTableID uint32

    Kernel KernelProtocolBlock
    Babel  BabelProtocolBlock

    ImportFilters []FilterBlock
    ExportFilters []FilterBlock
}

// KernelProtocolBlock describes one "protocol kernel { ... }" block.
type KernelProtocolBlock struct {
    Name          string
    IPv4Table     string
    IPv6Table     string
    KernelTableID uint32   // 0 = default/main
    Learn         bool     // import from kernel
    Persist       bool     // persist routes on BIRD shutdown
}

// BabelProtocolBlock describes one "protocol babel { ... }" block.
type BabelProtocolBlock struct {
    Name             string
    IPv4Table        string
    IPv6Table        string
    InterfacePattern string
    InterfaceType    BabelInterfaceType
    RTTMetrics       bool
    MetricBase       uint
    MetricStaged     uint
    MetricDraining   uint
    ECMP             bool
    ECMPLimit        uint
    Auth             *BabelAuthSpec
}

// FilterBlock is a named BIRD filter function.
type FilterBlock struct {
    Name string
    Body string // raw BIRD filter text, including surrounding braces
}
```

## Observed state

`BirdObservation` is the result of parsing `birdc` text output into
structured Go values. Fields may be partially populated when parsing of a
specific command fails; the client records parse warnings in the returned
error or in an internal parse log.

```go
// BirdObservation is the parsed output of birdc status/commands.
type BirdObservation struct {
    Status     BirdStatus
    Protocols  []BirdProtocol
    Routes     []BirdRoute
    Interfaces []BirdInterface
    Neighbors  []BirdNeighbor

    FetchedAt time.Time
    Stale     bool     // true if the snapshot timed out or used cached data
    Warnings  []string // non-fatal parse warnings
}

type BirdStatus struct {
    RouterID     uint32
    Version      string
    UpSince      time.Time
    LastReconfig time.Time
}

type BirdProtocol struct {
    Name    string
    Proto   string // "Babel", "Kernel", "Device", ...
    Table   string
    State   string // "up", "down", "start", ...
    Info    string
    Since   time.Time
    Uptime  time.Duration
}

type BirdRoute struct {
    Prefix   netip.Prefix
    From     netip.Addr
    Via      netip.Addr
    Iface    string
    Protocol string
    Source   string // e.g. "babel", "static"
    Metric   uint32
    Selected bool
}

type BirdInterface struct {
    Index    int
    Name     string
    Flags    string
    State    string // "up", "down"
    MTU      int
    LinkLocal netip.Addr
    Addresses []netip.Addr
}

type BirdNeighbor struct {
    Interface string
    Address   netip.Addr
    Protocol  string
    Metric    uint32
    Routes    int    // routes learned from this Babel neighbor
    Reach     uint16 // babel reachability bitmap, when available
}
```

## Interfaces

### `ConfigGenerator`

```go
// ConfigGenerator renders a bird.conf from a spec and the current authorized
// import/export prefix sets.
type ConfigGenerator interface {
    Generate(
        spec BirdInstanceSpec,
        importSet []netip.Prefix,
        exportSet []netip.Prefix,
    ) ([]byte, error)
}
```

`importSet` is the set of prefixes this instance should accept from Babel
peers; `exportSet` is the set of local prefixes it should announce.

### `Client`

```go
// Client talks to a running BIRD daemon through birdc over a Unix socket.
type Client interface {
    // Status returns a snapshot of BIRD status, protocols, routes,
    // interfaces and neighbors.
    Status(ctx context.Context) (*BirdObservation, error)

    // Configure performs a full "birdc configure" using the file at path.
    Configure(ctx context.Context, path string) error

    // ConfigureSoft performs "birdc configure soft" using the file at path.
    ConfigureSoft(ctx context.Context, path string) error

    // ReloadIn triggers "birdc reload in <proto>".
    ReloadIn(ctx context.Context, proto string) error

    // ReloadOut triggers "birdc reload out <proto>".
    ReloadOut(ctx context.Context, proto string) error

    // Shutdown performs a graceful shutdown ("birdc down" or SIGTERM).
    Shutdown(ctx context.Context) error
}
```

All methods should respect `ctx` deadlines; `Status` should mark the result
`Stale` rather than fail entirely when individual commands time out.

### `ProcessManager`

```go
// ProcessManager owns the BIRD child process in managed mode.
type ProcessManager interface {
    // Start ensures the target netns exists and starts BIRD inside it.
    // If a compatible BIRD process is already running (matching router id,
    // table, and control socket), Start adopts it instead of spawning a new one.
    Start(ctx context.Context, spec BirdInstanceSpec) error

    // Stop gracefully stops the BIRD process and removes Photon-owned
    // pid/control-socket/config files when ownership checks pass.
    Stop(ctx context.Context, spec BirdInstanceSpec) error

    // IsRunning reports whether the currently managed BIRD process is alive.
    // The implementation is expected to hold the spec it was started with.
    IsRunning(ctx context.Context) bool
}
```

## Helper functions

### `RenderFilter`

```go
// RenderFilter returns a complete BIRD filter function named name.
// Authorized prefixes are accepted; bogon prefixes are rejected first.
// If prefixes is empty the filter rejects everything.
func RenderFilter(
    name string,
    prefixes []netip.Prefix,
    bogons []netip.Prefix,
) string
```

Typical usage:

```go
importFilter := RenderFilter("photon_import", importSet, spec.BogonPrefixes)
exportFilter := RenderFilter("photon_export", exportSet, spec.BogonPrefixes)
```

The returned text includes the surrounding `filter <name> { ... }` block.
Example body for an import filter:

```bird
filter photon_import_100 {
    if net ~ [ 0.0.0.0/0, ::/0 ] then reject;
    if net ~ [ 10.0.0.0/8{18,28}, 2001:db8::/32{48,96} ] then accept;
    reject;
}
```

### `StableRouterID`

```go
// StableRouterID returns a deterministic 32-bit router id for an overlay.
// It hashes the local zone, the trusted root hash, and the overlay id,
// then maps the first four bytes of the digest to a non-zero uint32.
func StableRouterID(
    localZone zone.ZonePath,
    rootTrust []byte,
    overlayID string,
) uint32
```

Implementation sketch (do not commit as production code):

```go
func StableRouterID(localZone zone.ZonePath, rootTrust []byte, overlayID string) uint32 {
    digest := photoncrypto.Hash(
        []byte(localZone),
        rootTrust,
        []byte(overlayID),
    )
    id := binary.BigEndian.Uint32(digest[:4])
    if id == 0 {
        id = 0x80000001 // 128.0.0.1; avoid the all-zero router id
    }
    return id
}
```

The global 32-bit BIRD router id is persisted by the caller (e.g. in Photon
state DB) so it does not change across restarts. The generated Babel protocol
still enables `randomize router id`: BIRD keeps the stable global ID in the low
32 bits and randomizes the high 32 bits of Babel's 64-bit origin ID whenever
the protocol instance starts. This prevents a restarted Babel instance, whose
sequence number starts again at 1, from having its announcements rejected as
stale by peers.

## Example BIRD config snippets

### Minimal managed overlay config

```bird
# Photon-generated BIRD config for overlay ipsec-main
# Do not edit manually.

log syslog all;
router id 1.2.3.4;
# Control socket path is set on the bird command line with -s.
# The optional extra socket inside the config uses the 'cli' directive:
# cli "/run/photon/bird-ipsec-main.ctl";

protocol device {
    scan time 5;
}

ipv4 table photon_ipsec_main;
ipv6 table photon_ipsec_main;

protocol kernel photon_kern_ipsec_main {
    ipv4 { table photon_ipsec_main; export all; };
    ipv6 { table photon_ipsec_main; export all; };
}
```

### Kernel sync for a non-main table

```bird
protocol kernel photon_kern_100 {
    ipv4 { table photon_100; export all; };
    ipv6 { table photon_100; export all; };
    kernel table 100;
}
```

### Babel protocol block

```bird
protocol babel photon_babel_ipsec_main {
    randomize router id;

    ipv4 {
        table photon_ipsec_main;
        import filter photon_import_ipsec_main;
        export filter photon_export_ipsec_main;
    };
    ipv6 {
        table photon_ipsec_main;
        import filter photon_import_ipsec_main;
        export filter photon_export_ipsec_main;
    };

    ecmp on limit 16;

    interface "phx*" {
        type wireless;
        rxcost 100;
        rtt cost 1024;
        rtt min 10 ms;
        rtt max 500 ms;
        rtt decay 12;
        hello interval 4 s;
        update interval 16 s;
    };
}
```

### Import/export filters

```bird
filter photon_import_ipsec_main {
    if net ~ [ 0.0.0.0/0, ::/0 ] then reject;
    if net ~ [ 10.0.0.0/8{18,28}, 2001:db8::/32{48,96} ] then accept;
    reject;
}

filter photon_export_ipsec_main {
    if source ~ [ RTS_STATIC, RTS_INHERIT ] then accept;
    reject;
}
```

## Notes for the implementer

- `BirdInstanceSpec` validation belongs in the implementation package. Key
  invariants: non-zero `RouterID`, non-empty `OverlayID`, valid `Mode`, and
  absolute paths for `ControlSocketPath`, `PIDFilePath`, and `ConfigPath`.
- In `managed` mode, the process manager must run BIRD inside the target
  netns, e.g. `ip netns exec <ns> bird -c <conf> -s <ctl> -P <pid>`.
- The control socket is a filesystem object; the client can connect from
  Photon' netns as long as the socket path is reachable. BIRD's replies
  reflect BIRD's own netns.
- Filter changes are applied with `configure soft` followed by
  `reload in <proto>` / `reload out <proto>`. Structural changes (table
  names, interface pattern, auth) require a normal `configure` and may
  restart protocols.
- `Status` should probably run multiple birdc commands (`show status`,
  `show protocols all`, `show route all`, `show interfaces`) and parse each
  independently so a parse failure in one area does not discard all data.
- All generated config files should carry a header comment identifying them
  as Photon-generated and warn against manual edits.
