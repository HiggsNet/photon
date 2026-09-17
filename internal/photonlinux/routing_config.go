package photonlinux

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing/bird"
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
	Enabled        bool
	Protocol       string
	ShutdownPolicy string
	RouterIDLabel  string // required for path netns
	Bird           bird.BirdInstanceSpec
	Upstream       *UpstreamConfig
}

// UpstreamConfig holds optional veth upstream configuration that connects
// the mesh netns to the main network (init netns or another ns).
type UpstreamConfig struct {
	Enabled                bool
	Mode                   string // static or external
	CreateVeth             bool
	InstallSourceAddresses bool
	Veth                   bird.VethSpec
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
		return NetNSTarget(spec)
	}
	return name
}

// RoutingConfig holds top-level routing instance definitions.
type RoutingConfig struct {
	Instances []RoutingInstance
}

// RoutingConfigYAML is the raw YAML model for the top-level `routing:` section.
type RoutingConfigYAML struct {
	Instances []RoutingInstanceYAML `yaml:"instances"`
}

type RoutingInstanceYAML struct {
	ID             string              `yaml:"id"`
	NetNS          string              `yaml:"netns"`
	Enabled        *bool               `yaml:"enabled"`
	Disabled       *bool               `yaml:"disabled"`
	Provider       string              `yaml:"provider"`
	Mode           string              `yaml:"mode"`
	ShutdownPolicy string              `yaml:"shutdown_policy"`
	ControlSocket  string              `yaml:"control_socket"`
	PIDFile        string              `yaml:"pid_file"`
	ConfigFile     string              `yaml:"config_file"`
	TableID        string              `yaml:"table"`
	MetricBase     uint                `yaml:"metric_base"`
	MetricStaged   uint                `yaml:"metric_staged"`
	MetricDraining uint                `yaml:"metric_draining"`
	RTTCost        uint                `yaml:"rtt_cost"`
	RTTMin         string              `yaml:"rtt_min"`
	RTTMax         string              `yaml:"rtt_max"`
	RTTDecay       uint                `yaml:"rtt_decay"`
	HelloInterval  string              `yaml:"hello_interval"`
	UpdateInterval string              `yaml:"update_interval"`
	ECMP           *bool               `yaml:"ecmp"`
	ECMPLimit      uint                `yaml:"ecmp_limit"`
	InterfacePat   string              `yaml:"interface_pattern"`
	RouterIDLabel  string              `yaml:"router_id_label"`
	Upstream       *UpstreamConfigYAML `yaml:"upstream"`
}

// UpstreamConfigYAML is the raw YAML model for routing.instances[].upstream.
type UpstreamConfigYAML struct {
	Enabled                *bool                `yaml:"enabled"`
	Disabled               *bool                `yaml:"disabled"`
	Mode                   string               `yaml:"mode"`
	CreateVeth             *bool                `yaml:"create_veth"`
	InstallSourceAddresses *bool                `yaml:"install_source_addresses"`
	Mesh                   UpstreamEndpointYAML `yaml:"mesh"`
	External               UpstreamEndpointYAML `yaml:"external"`
}

type UpstreamEndpointYAML struct {
	Interface string `yaml:"interface"`
	NetNS     string `yaml:"netns"`
	IPv4LL    string `yaml:"ipv4_ll"`
	IPv6LL    string `yaml:"ipv6_ll"`
}

const (
	RoutingShutdownPolicyPersist = "persist"
	RoutingShutdownPolicyStop    = "stop"

	UpstreamModeStatic   = "static"
	UpstreamModeExternal = "external"

	defaultMeshIPv4LL     = "169.254.254.1/30"
	defaultMeshIPv6LL     = "fe80::a1:1/64"
	defaultExternalIPv4LL = "169.254.254.2/30"
	defaultExternalIPv6LL = "fe80::a1:2/64"
	defaultMeshVeth       = "phv2host"
	defaultExternalVeth   = "phv2mesh"
)

// ParseRoutingConfig parses `routing.instances[]` into RoutingConfig.
func ParseRoutingConfig(yamlInstances []RoutingInstanceYAML, netnsCfg NetNSConfig, dataDir string) (RoutingConfig, error) {
	var instances []RoutingInstance
	for i, yi := range yamlInstances {
		inst, err := parseRoutingInstance(yi, netnsCfg, dataDir)
		if err != nil {
			return RoutingConfig{}, fmt.Errorf("routing.instances[%d]: %w", i, err)
		}
		instances = append(instances, inst)
	}
	return RoutingConfig{Instances: instances}, nil
}

func parseRoutingInstance(yi RoutingInstanceYAML, netnsCfg NetNSConfig, dataDir string) (RoutingInstance, error) {
	if yi.ID == "" {
		return RoutingInstance{}, fmt.Errorf("id is required")
	}
	if yi.NetNS == "" {
		yi.NetNS = "default"
	}
	spec, ok := netnsCfg.Names[yi.NetNS]
	if !ok {
		return RoutingInstance{}, fmt.Errorf("netns %q not found in netns section", yi.NetNS)
	}
	netnsName := netnsCfg.runtimeTarget(yi.NetNS)
	// path netns requires router_id_label
	if spec.Kind == ipsec.NetNSPath && yi.RouterIDLabel == "" {
		return RoutingInstance{}, fmt.Errorf("router_id_label is required when netns uses path mode")
	}

	enabled, err := configEnabled("routing.instances[]", yi.Enabled, yi.Disabled)
	if err != nil {
		return RoutingInstance{}, err
	}

	mode := yi.Mode
	if mode == "" {
		mode = ipsec.RoutingModeManaged
	}
	if !oneOfRoutingMode(mode) {
		return RoutingInstance{}, fmt.Errorf("unsupported routing mode %q", mode)
	}
	shutdownPolicy := strings.TrimSpace(yi.ShutdownPolicy)
	if shutdownPolicy == "" {
		shutdownPolicy = RoutingShutdownPolicyPersist
	}
	if !oneOfRoutingShutdownPolicy(shutdownPolicy) {
		return RoutingInstance{}, fmt.Errorf("unsupported shutdown_policy %q", shutdownPolicy)
	}
	provider := yi.Provider
	if provider == "" {
		provider = "bird"
	}
	if provider != "bird" {
		return RoutingInstance{}, fmt.Errorf("unsupported routing provider %q", provider)
	}
	tableID := yi.TableID
	if tableID == "" {
		tableID = ipsec.DefaultRoutingTable
	}
	metricBase := yi.MetricBase
	if metricBase == 0 {
		metricBase = ipsec.DefaultMetricBase
	}
	metricStaged := yi.MetricStaged
	if metricStaged == 0 {
		metricStaged = ipsec.DefaultMetricStaged
	}
	metricDraining := yi.MetricDraining
	if metricDraining == 0 {
		metricDraining = ipsec.DefaultMetricDrained
	}
	rttCost := yi.RTTCost
	if rttCost == 0 {
		rttCost = bird.DefaultBabelRTTCost
	}
	if rttCost >= 65535 {
		return RoutingInstance{}, fmt.Errorf("rtt_cost must be less than 65535")
	}
	rttMin, err := parseRoutingBabelDuration(yi.RTTMin, bird.DefaultBabelRTTMin, "rtt_min")
	if err != nil {
		return RoutingInstance{}, err
	}
	rttMax, err := parseRoutingBabelDuration(yi.RTTMax, bird.DefaultBabelRTTMax, "rtt_max")
	if err != nil {
		return RoutingInstance{}, err
	}
	if rttMax <= rttMin {
		return RoutingInstance{}, fmt.Errorf("rtt_max must be greater than rtt_min")
	}
	rttDecay := yi.RTTDecay
	if rttDecay == 0 {
		rttDecay = bird.DefaultBabelRTTDecay
	}
	if rttDecay > 256 {
		return RoutingInstance{}, fmt.Errorf("rtt_decay must be between 1 and 256")
	}
	helloInterval, err := parseRoutingBabelDuration(yi.HelloInterval, bird.DefaultBabelHelloInterval, "hello_interval")
	if err != nil {
		return RoutingInstance{}, err
	}
	updateInterval, err := parseRoutingBabelDuration(yi.UpdateInterval, bird.DefaultBabelUpdateInterval, "update_interval")
	if err != nil {
		return RoutingInstance{}, err
	}
	ecmp := true
	if yi.ECMP != nil {
		ecmp = *yi.ECMP
	}
	ecmpLimit := yi.ECMPLimit
	if ecmpLimit == 0 {
		ecmpLimit = 16
	}
	ifacePat := yi.InterfacePat
	if ifacePat == "" {
		ifacePat = "phx*"
	}

	configDir := filepath.Join(dataDir, "bird")
	controlSocket := yi.ControlSocket
	if controlSocket == "" {
		controlSocket, err = defaultBirdControlSocketPath(configDir, netnsName)
		if err != nil {
			return RoutingInstance{}, err
		}
	} else if err := validateBirdControlSocketPath(controlSocket); err != nil {
		return RoutingInstance{}, err
	}
	pidFile := yi.PIDFile
	if pidFile == "" {
		pidFile = filepath.Join(configDir, fmt.Sprintf("bird-%s.pid", netnsName))
	}
	configFile := yi.ConfigFile
	if configFile == "" {
		configFile = filepath.Join(configDir, fmt.Sprintf("bird-%s.conf", netnsName))
	}

	upstream, err := parseUpstreamConfig(yi.Upstream)
	if err != nil {
		return RoutingInstance{}, fmt.Errorf("upstream: %w", err)
	}

	if upstream != nil {
		upstream.Veth.MeshNetns = netnsName
	}
	return RoutingInstance{
		ID:             yi.ID,
		Enabled:        enabled,
		Protocol:       provider,
		ShutdownPolicy: shutdownPolicy,
		RouterIDLabel:  yi.RouterIDLabel,
		Upstream:       upstream,
		Bird: bird.BirdInstanceSpec{
			NetNS:               bird.NetNSSpec{Kind: spec.Kind, Name: spec.Name, Path: spec.Path, Create: spec.Create},
			NetNSName:           netnsName,
			Mode:                bird.BirdMode(mode),
			ControlSocketPath:   controlSocket,
			PIDFilePath:         pidFile,
			ConfigPath:          configFile,
			TableID:             tableID,
			MetricBase:          metricBase,
			MetricStaged:        metricStaged,
			MetricDraining:      metricDraining,
			BabelRTTCost:        rttCost,
			BabelRTTMin:         rttMin,
			BabelRTTMax:         rttMax,
			BabelRTTDecay:       rttDecay,
			BabelHelloInterval:  helloInterval,
			BabelUpdateInterval: updateInterval,
			ECMP:                ecmp,
			ECMPLimit:           ecmpLimit,
			InterfacePatterns:   []string{ifacePat},
		},
	}, nil
}

func parseRoutingBabelDuration(raw string, fallback time.Duration, field string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %q", field, raw)
	}
	if value < time.Millisecond || value%time.Millisecond != 0 {
		return 0, fmt.Errorf("%s must be a positive whole number of milliseconds", field)
	}
	return value, nil
}

func defaultBirdControlSocketPath(configDir, netnsName string) (string, error) {
	path := filepath.Join(configDir, fmt.Sprintf("bird-%s.ctl", netnsName))
	if len(path) <= bird.MaxControlSocketPathBytes {
		return path, nil
	}

	sum := sha256.Sum256([]byte(netnsName))
	path = filepath.Join(configDir, fmt.Sprintf("bird-%x.ctl", sum[:8]))
	if len(path) <= bird.MaxControlSocketPathBytes {
		return path, nil
	}

	// A long data_dir can consume the entire sockaddr_un budget even after the
	// filename is hashed. Managed BIRD already needs a runtime socket, so use a
	// stable path below /run keyed by the complete desired path. Including the
	// data-dir-derived path keeps concurrent isolated smoke runs distinct.
	sum = sha256.Sum256([]byte(path))
	path = filepath.Join("/run/photon/bird", fmt.Sprintf("bird-%x.ctl", sum[:8]))
	return path, validateBirdControlSocketPath(path)
}

func validateBirdControlSocketPath(path string) error {
	if len(path) > bird.MaxControlSocketPathBytes {
		return fmt.Errorf("BIRD control socket path is %d bytes, exceeds Linux limit %d: %s", len(path), bird.MaxControlSocketPathBytes, path)
	}
	return nil
}

func parseUpstreamConfig(yu *UpstreamConfigYAML) (*UpstreamConfig, error) {
	if yu == nil {
		return nil, nil
	}
	enabled, err := configEnabled("routing.instances[].upstream", yu.Enabled, yu.Disabled)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return &UpstreamConfig{Enabled: false}, nil
	}

	uc := &UpstreamConfig{
		Enabled:    true,
		Mode:       strings.TrimSpace(yu.Mode),
		CreateVeth: true,
		Veth: bird.VethSpec{
			MeshInterface: strings.TrimSpace(yu.Mesh.Interface),
			MeshIPv4LL:    strings.TrimSpace(yu.Mesh.IPv4LL),
			MeshIPv6LL:    strings.TrimSpace(yu.Mesh.IPv6LL),
			PeerInterface: strings.TrimSpace(yu.External.Interface),
			PeerNetns:     strings.TrimSpace(yu.External.NetNS),
			PeerIPv4LL:    strings.TrimSpace(yu.External.IPv4LL),
			PeerIPv6LL:    strings.TrimSpace(yu.External.IPv6LL),
		},
	}
	if uc.Mode == "" {
		uc.Mode = UpstreamModeStatic
	}
	// Static mode historically installed an address from each local assignment
	// on the external endpoint. Preserve that default while allowing external
	// routing daemons to opt into address management independently.
	uc.InstallSourceAddresses = uc.Mode == UpstreamModeStatic
	if yu.CreateVeth != nil {
		uc.CreateVeth = *yu.CreateVeth
	}
	if yu.InstallSourceAddresses != nil {
		uc.InstallSourceAddresses = *yu.InstallSourceAddresses
	}

	// Apply default link-local addresses when upstream is enabled and the user
	// did not provide explicit values. These are used both for the veth
	// endpoints and as the next-hop for static routes toward the mesh netns.
	if uc.Veth.MeshIPv4LL == "" {
		uc.Veth.MeshIPv4LL = defaultMeshIPv4LL
	}
	if uc.Veth.MeshIPv6LL == "" {
		uc.Veth.MeshIPv6LL = defaultMeshIPv6LL
	}
	if uc.Veth.PeerIPv4LL == "" {
		uc.Veth.PeerIPv4LL = defaultExternalIPv4LL
	}
	if uc.Veth.PeerIPv6LL == "" {
		uc.Veth.PeerIPv6LL = defaultExternalIPv6LL
	}

	// Default endpoint interface names when upstream is enabled but not specified.
	if uc.Veth.MeshInterface == "" {
		uc.Veth.MeshInterface = defaultMeshVeth
	}
	if uc.Veth.PeerInterface == "" {
		uc.Veth.PeerInterface = defaultExternalVeth
	}
	if !oneOfUpstreamMode(uc.Mode) {
		return nil, fmt.Errorf("unsupported mode %q", uc.Mode)
	}

	// Validate IPv4/IPv6 link-local if provided.
	if err := validateOptionalPrefix("mesh.ipv4_ll", uc.Veth.MeshIPv4LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("mesh.ipv6_ll", uc.Veth.MeshIPv6LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("external.ipv4_ll", uc.Veth.PeerIPv4LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("external.ipv6_ll", uc.Veth.PeerIPv6LL); err != nil {
		return nil, err
	}

	return uc, nil
}

func validateOptionalPrefix(field, value string) error {
	if value == "" {
		return nil
	}
	if _, err := netip.ParsePrefix(value); err != nil {
		return fmt.Errorf("invalid %s %q: %w", field, value, err)
	}
	return nil
}

func oneOfRoutingMode(mode string) bool {
	return mode == ipsec.RoutingModeManaged || mode == ipsec.RoutingModeExternal || mode == ipsec.RoutingModeDisabled
}

func oneOfRoutingShutdownPolicy(policy string) bool {
	return policy == RoutingShutdownPolicyPersist || policy == RoutingShutdownPolicyStop
}

func oneOfUpstreamMode(mode string) bool {
	return mode == UpstreamModeStatic || mode == UpstreamModeExternal
}

// NetNSTarget returns the runtime namespace key: host, a name, or a path.
// Configuration references and defaults must already be resolved.
func NetNSTarget(spec ipsec.NetNSSpec) string {
	if target := spec.Target(); target != "" {
		return target
	}
	return ipsec.NetNSHost
}

// NetNSNames returns sorted unique runtime namespaces declared by routing.
func (config RoutingConfig) NetNSNames() []string {
	var names []string
	for _, inst := range config.Instances {
		names = append(names, inst.Bird.NetNSName)
	}
	slices.Sort(names)
	return slices.Compact(names)
}
