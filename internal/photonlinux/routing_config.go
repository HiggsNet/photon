package photonlinux

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// NetNSConfig holds the set of named network namespaces the node declares.
type NetNSConfig struct {
	// Names maps netns name → spec. The name is used as the stable key
	// referenced by overlays and routing instances.
	Names map[string]ipsec.NetNSSpec
	// Forwarding holds the single routing/firewall forwarding policy owned by
	// each network namespace. Alias keys (notably "default" and its target)
	// point at the same value.
	Forwarding map[string]firewall.ForwardingPolicy
	// Default is the preferred default reference key.
	Default string
}

// NetNSConfigYAML is the raw YAML model for the top-level `netns:` section.
type NetNSConfigYAML struct {
	// Default is the optional default netns, equivalent to a named entry.
	Default *netnsSpecYAML `yaml:"default"`
	// Entries is a map of named netns definitions, declared alongside default.
	Entries map[string]netnsSpecYAML `yaml:",inline"`
}

type netnsSpecYAML struct {
	Kind       string          `yaml:"kind"`
	Name       string          `yaml:"name"`
	Path       string          `yaml:"path"`
	Create     *bool           `yaml:"create"`
	Forwarding *forwardingYAML `yaml:"forwarding"`
}

// netNSSpec applies netns-specific YAML defaults. A declared named netns is
// Photon-owned by default; create: false opts into reusing an existing one.
func (raw netnsSpecYAML) netNSSpec() ipsec.NetNSSpec {
	spec := ipsec.NetNSSpec{
		Kind: raw.Kind,
		Name: raw.Name,
		Path: raw.Path,
	}
	if raw.Create != nil {
		spec.Create = *raw.Create
	}
	spec = spec.Normalized()
	if raw.Create == nil && spec.Kind == ipsec.NetNSName {
		spec.Create = true
	}
	return spec
}

// ParseNetNSConfig parses the top-level `netns:` section into NetNSConfig.
func ParseNetNSConfig(yamlCfg *NetNSConfigYAML, fallback ipsec.NetNSSpec) (NetNSConfig, error) {
	cfg := NetNSConfig{Names: make(map[string]ipsec.NetNSSpec), Forwarding: make(map[string]firewall.ForwardingPolicy)}
	if yamlCfg == nil {
		n := fallback.Normalized()
		addNetnsSpec(&cfg, "default", n)
		return cfg, nil
	}
	if yamlCfg.Default != nil {
		n := yamlCfg.Default.netNSSpec()
		if err := n.Validate(); err != nil {
			return cfg, fmt.Errorf("netns.default: %w", err)
		}
		addNetnsSpec(&cfg, "default", n)
		if err := addNetnsForwarding(&cfg, "default", n, yamlCfg.Default.Forwarding); err != nil {
			return cfg, fmt.Errorf("netns.default: %w", err)
		}
	}
	for name, entry := range yamlCfg.Entries {
		n := entry.netNSSpec()
		if err := n.Validate(); err != nil {
			return cfg, fmt.Errorf("netns.%s: %w", name, err)
		}
		if name == "" {
			name = n.Target()
		}
		cfg.Names[name] = n
		if err := addNetnsForwarding(&cfg, name, n, entry.Forwarding); err != nil {
			return cfg, fmt.Errorf("netns.%s: %w", name, err)
		}
		if name == "default" && cfg.Default == "" {
			cfg.Default = name
		}
	}
	if len(cfg.Names) == 0 {
		n := fallback.Normalized()
		addNetnsSpec(&cfg, "default", n)
	}
	if cfg.Default == "" {
		cfg.Default = "default"
	}
	return cfg, nil
}

func addNetnsSpec(cfg *NetNSConfig, name string, spec ipsec.NetNSSpec) {
	if cfg.Names == nil {
		cfg.Names = make(map[string]ipsec.NetNSSpec)
	}
	if name == "" {
		name = spec.Target()
	}
	if name == "" {
		name = ipsec.NetNSHost
	}
	cfg.Names[name] = spec
	if name == "default" {
		cfg.Default = name
		if target := spec.Target(); target != "" {
			cfg.Names[target] = spec
		}
	}
}

// RoutingInstance is a per-netns BIRD instance configuration.
type RoutingInstance struct {
	ID             string
	NetNS          string // references a netns name from NetNSConfig
	Enabled        bool
	Protocol       string
	Mode           string
	ShutdownPolicy string
	ControlSocket  string
	PIDFile        string
	ConfigFile     string
	TableID        string
	MetricBase     uint
	MetricStaged   uint
	MetricDraining uint
	RTTCost        uint
	RTTMin         time.Duration
	RTTMax         time.Duration
	RTTDecay       uint
	HelloInterval  time.Duration
	UpdateInterval time.Duration
	ECMP           bool
	ECMPLimit      uint
	InterfacePat   string
	RouterIDLabel  string   // required for path netns
	Overlays       []string // overlays that share this instance (auto-derived)
	Upstream       *UpstreamConfig
}

// UpstreamConfig holds optional veth upstream configuration that connects
// the mesh netns to the main network (init netns or another ns).
type UpstreamConfig struct {
	Enabled                bool
	Mode                   string // static or external
	CreateVeth             bool   // if true, Photon creates and maintains the veth pair
	InstallSourceAddresses bool   // install non-shared local assignment source identities on the external endpoint
	MeshInterface          string // routing instance netns side of the veth pair
	MeshIPv4LL             string // optional IPv4 link-local for the mesh side
	MeshIPv6LL             string // optional IPv6 link-local for the mesh side
	ExternalInterface      string // host/upstream netns side of the veth pair
	ExternalNetns          string // empty = init/main host netns
	ExternalIPv4LL         string // optional IPv4 link-local for the external side
	ExternalIPv6LL         string // optional IPv6 link-local for the external side
}

// forwardingYAML is the raw forwarding policy nested under a netns entry.
type forwardingYAML struct {
	Transit       *bool    `yaml:"transit"`
	AllowPrefixes []string `yaml:"allow_prefixes"`
	DenyPrefixes  []string `yaml:"deny_prefixes"`
	AllowPeers    []string `yaml:"allow_peers"`
	DenyPeers     []string `yaml:"deny_peers"`
	MetricHint    uint     `yaml:"metric_hint"`
}

func parseForwardingPolicy(raw *forwardingYAML) (firewall.ForwardingPolicy, error) {
	if raw == nil {
		return firewall.ForwardingPolicy{}, nil
	}
	allowPrefixes, err := parsePrefixList(raw.AllowPrefixes)
	if err != nil {
		return firewall.ForwardingPolicy{}, fmt.Errorf("allow_prefixes: %w", err)
	}
	denyPrefixes, err := parsePrefixList(raw.DenyPrefixes)
	if err != nil {
		return firewall.ForwardingPolicy{}, fmt.Errorf("deny_prefixes: %w", err)
	}
	// The forwarding section is an opt-in: declaring it enables transit unless
	// the user explicitly overrides that with transit: false.
	transit := true
	if raw.Transit != nil {
		transit = *raw.Transit
	}
	return firewall.BuildForwardingPolicy(transit, allowPrefixes, denyPrefixes, raw.AllowPeers, raw.DenyPeers, raw.MetricHint), nil
}

// addNetnsForwarding registers a policy under both the configuration key and
// the resolved namespace target, so routing and firewall consumers converge on
// the same policy regardless of which form they use.
func addNetnsForwarding(cfg *NetNSConfig, name string, spec ipsec.NetNSSpec, raw *forwardingYAML) error {
	if raw == nil {
		return nil
	}
	policy, err := parseForwardingPolicy(raw)
	if err != nil {
		return fmt.Errorf("forwarding: %w", err)
	}
	if cfg.Forwarding == nil {
		cfg.Forwarding = make(map[string]firewall.ForwardingPolicy)
	}
	cfg.Forwarding[name] = policy
	if spec.Target() != "" {
		cfg.Forwarding[spec.Target()] = policy
	}
	return nil
}

// ForwardingPolicy returns the policy owned by the named network
// namespace. An absent policy has the safe non-transit zero value.
func (config NetNSConfig) ForwardingPolicy(netnsName string) firewall.ForwardingPolicy {
	if policy, ok := config.Forwarding[netnsName]; ok {
		return policy
	}
	if spec, ok := config.Names[netnsName]; ok {
		return config.Forwarding[spec.Target()]
	}
	return firewall.ForwardingPolicy{}
}

func parsePrefixList(items []string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, s := range items {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			return nil, fmt.Errorf("invalid prefix %q: %w", s, err)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

func (config NetNSConfig) runtimeTarget(name string) string {
	if spec, ok := config.Names[name]; ok {
		if target := spec.Target(); target != "" {
			return target
		}
		return ipsec.NetNSHost
	}
	return name
}
