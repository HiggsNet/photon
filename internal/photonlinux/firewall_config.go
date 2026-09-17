package photonlinux

import (
	"fmt"
	"net"
	"net/netip"
	"strings"

	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// FirewallConfig holds top-level firewall instance definitions.
type FirewallConfig struct {
	Instances []firewall.FirewallInstanceSpec
}

// FirewallConfigYAML is the raw YAML model for the top-level `firewall:` section.
type FirewallConfigYAML struct {
	Instances []firewallInstanceYAML `yaml:"instances"`
}

type firewallInstanceYAML struct {
	ID            string `yaml:"id"`
	NetNS         string `yaml:"netns"`
	Host          *bool  `yaml:"host"`
	Enabled       *bool  `yaml:"enabled"`
	Disabled      *bool  `yaml:"disabled"`
	Mode          string `yaml:"mode"`
	Backend       string `yaml:"backend"`
	DefaultPolicy string `yaml:"default_policy"`
	OwnerPrefix   string `yaml:"owner_prefix"`

	XFRMTunnelPattern string `yaml:"xfrm_tunnel_pattern"`

	LocalServices []localServiceYAML `yaml:"local_services"`

	HostPorts     *hostPortsYAML     `yaml:"host_ports"`
	RedirectGrace *redirectGraceYAML `yaml:"redirect_grace"`
	Priority      *priorityYAML      `yaml:"priority"`
	ListenAddrs   []string           `yaml:"listen_addrs"`

	NFTHooks      *inlineHooksYAML   `yaml:"nft_hooks"`
	IPTablesHooks *iptablesHooksYAML `yaml:"iptables_hooks"`
}

type localServiceYAML struct {
	Proto   string   `yaml:"proto"`
	Port    uint16   `yaml:"port"`
	Sources []string `yaml:"sources"`
}

type hostPortsYAML struct {
	IKE  *bool `yaml:"ike"`
	NATT *bool `yaml:"natt"`
}

type redirectGraceYAML struct {
	Enabled  *bool `yaml:"enabled"`
	Disabled *bool `yaml:"disabled"`
}

type priorityYAML struct {
	Filter      string `yaml:"filter"`
	Prerouting  string `yaml:"prerouting"`
	Postrouting string `yaml:"postrouting"`
}

type inlineHooksYAML struct {
	PreInput           []string `yaml:"pre_input"`
	PostInput          []string `yaml:"post_input"`
	PreForward         []string `yaml:"pre_forward"`
	PostForward        []string `yaml:"post_forward"`
	PreOutput          []string `yaml:"pre_output"`
	PostOutput         []string `yaml:"post_output"`
	HostPrePrerouting  []string `yaml:"host_pre_prerouting"`
	HostPostPrerouting []string `yaml:"host_post_prerouting"`
	HostPreInput       []string `yaml:"host_pre_input"`
	HostPostInput      []string `yaml:"host_post_input"`
}

type iptablesHooksYAML struct {
	IPv4 *inlineHooksYAML `yaml:"ipv4"`
	IPv6 *inlineHooksYAML `yaml:"ipv6"`
}

func ParseFirewallConfig(yamlCfg *FirewallConfigYAML, namespaces map[string]ipsec.NetNSSpec, portMode string) (FirewallConfig, error) {
	cfg := FirewallConfig{}
	if yamlCfg == nil {
		return cfg, nil
	}
	for i, yi := range yamlCfg.Instances {
		inst, err := parseFirewallInstance(yi, namespaces, portMode)
		if err != nil {
			return FirewallConfig{}, fmt.Errorf("firewall.instances[%d]: %w", i, err)
		}
		cfg.Instances = append(cfg.Instances, inst)
	}
	return cfg, nil
}

func parseFirewallInstance(yi firewallInstanceYAML, namespaces map[string]ipsec.NetNSSpec, portMode string) (firewall.FirewallInstanceSpec, error) {
	if yi.ID == "" {
		return firewall.FirewallInstanceSpec{}, fmt.Errorf("id is required")
	}

	isHost := false
	if yi.Host != nil {
		isHost = *yi.Host
	}
	if isHost && yi.NetNS != "" {
		return firewall.FirewallInstanceSpec{}, fmt.Errorf("host: true conflicts with netns %q; choose either host: true or netns", yi.NetNS)
	}
	if yi.NetNS == "" && !isHost {
		yi.NetNS = "default"
	}
	if isHost {
		yi.NetNS = "host"
	} else {
		if _, ok := namespaces[yi.NetNS]; !ok {
			return firewall.FirewallInstanceSpec{}, fmt.Errorf("netns %q not found in netns section", yi.NetNS)
		}
	}

	enabled, err := configEnabled("firewall.instances[]", yi.Enabled, yi.Disabled)
	if err != nil {
		return firewall.FirewallInstanceSpec{}, err
	}

	mode := yi.Mode
	if mode == "" {
		mode = firewall.ModeManaged
	}
	if !oneOfFirewallMode(mode) {
		return firewall.FirewallInstanceSpec{}, fmt.Errorf("unsupported firewall mode %q", mode)
	}

	backend := yi.Backend
	if backend == "" {
		backend = firewall.BackendAuto
	}
	if !oneOfFirewallBackend(backend) {
		return firewall.FirewallInstanceSpec{}, fmt.Errorf("unsupported firewall backend %q", backend)
	}

	defaultPolicy := yi.DefaultPolicy
	if defaultPolicy == "" {
		defaultPolicy = firewall.DefaultPolicyDrop
	}
	if defaultPolicy != firewall.DefaultPolicyDrop && defaultPolicy != firewall.DefaultPolicyAccept {
		return firewall.FirewallInstanceSpec{}, fmt.Errorf("invalid default_policy %q", defaultPolicy)
	}

	ownerPrefix := yi.OwnerPrefix
	if ownerPrefix == "" {
		ownerPrefix = "photon"
	}

	xfrmPat := yi.XFRMTunnelPattern
	if xfrmPat == "" && !isHost {
		xfrmPat = "phx*"
	}

	localServices, err := parseLocalServices(yi.LocalServices)
	if err != nil {
		return firewall.FirewallInstanceSpec{}, fmt.Errorf("local_services: %w", err)
	}

	hostPorts := firewall.HostPortConfig{}
	rangeMode := isHost && portMode == ipsec.PortModeRange
	if rangeMode {
		hostPorts.IKE = true
		hostPorts.NATT = true
	}
	if yi.HostPorts != nil {
		if yi.HostPorts.IKE != nil {
			hostPorts.IKE = *yi.HostPorts.IKE
		}
		if yi.HostPorts.NATT != nil {
			hostPorts.NATT = *yi.HostPorts.NATT
		}
	}

	redirectGrace := firewall.RedirectGrace{}
	if rangeMode {
		redirectGrace.Enabled = true
	}
	if yi.RedirectGrace != nil {
		enabled, err := configEnabled("firewall.instances[].redirect_grace", yi.RedirectGrace.Enabled, yi.RedirectGrace.Disabled)
		if err != nil {
			return firewall.FirewallInstanceSpec{}, err
		}
		redirectGrace.Enabled = enabled
	}

	listenAddrs, err := parseFirewallListenAddrs(yi.ListenAddrs)
	if err != nil {
		return firewall.FirewallInstanceSpec{}, fmt.Errorf("listen_addrs: %w", err)
	}
	priorities, err := parseFirewallPriorities(yi.Priority)
	if err != nil {
		return firewall.FirewallInstanceSpec{}, fmt.Errorf("priority: %w", err)
	}

	nativeHooks := firewall.NativeHooks{}
	if yi.NFTHooks != nil {
		nativeHooks.NFT = inlineHooksFromYAML(yi.NFTHooks)
	}
	if yi.IPTablesHooks != nil {
		if yi.IPTablesHooks.IPv4 != nil {
			nativeHooks.IPTables.IPv4 = inlineHooksFromYAML(yi.IPTablesHooks.IPv4)
		}
		if yi.IPTablesHooks.IPv6 != nil {
			nativeHooks.IPTables.IPv6 = inlineHooksFromYAML(yi.IPTablesHooks.IPv6)
		}
	}
	if err := firewall.ValidateNativeHooks(nativeHooks); err != nil {
		return firewall.FirewallInstanceSpec{}, fmt.Errorf("inline hooks: %w", err)
	}

	return firewall.FirewallInstanceSpec{
		ID:                yi.ID,
		NetNS:             yi.NetNS,
		IsHost:            isHost,
		Enabled:           enabled,
		Mode:              mode,
		Backend:           backend,
		DefaultPolicy:     defaultPolicy,
		OwnerPrefix:       ownerPrefix,
		XFRMTunnelPattern: xfrmPat,
		LocalServices:     localServices,
		HostPorts:         hostPorts,
		RedirectGrace:     redirectGrace,
		Priorities:        priorities,
		ListenAddrs:       listenAddrs,
		NativeHooks:       nativeHooks,
		CharonIKEPort:     500,
		CharonNATTPort:    4500,
	}, nil
}

func parseFirewallPriorities(raw *priorityYAML) (firewall.ChainPriorities, error) {
	priorities := firewall.DefaultChainPriorities()
	if raw == nil {
		return priorities, nil
	}
	var err error
	if priorities.Filter, err = firewall.ParseChainPriority(raw.Filter, "filter"); err != nil {
		return firewall.ChainPriorities{}, fmt.Errorf("filter: %w", err)
	}
	if priorities.Prerouting, err = firewall.ParseChainPriority(raw.Prerouting, "dstnat"); err != nil {
		return firewall.ChainPriorities{}, fmt.Errorf("prerouting: %w", err)
	}
	if priorities.Postrouting, err = firewall.ParseChainPriority(raw.Postrouting, "srcnat"); err != nil {
		return firewall.ChainPriorities{}, fmt.Errorf("postrouting: %w", err)
	}
	return priorities, nil
}

func inlineHooksFromYAML(h *inlineHooksYAML) firewall.InlineHookRules {
	if h == nil {
		return firewall.InlineHookRules{}
	}
	return firewall.InlineHookRules{
		PreInput:           append([]string(nil), h.PreInput...),
		PostInput:          append([]string(nil), h.PostInput...),
		PreForward:         append([]string(nil), h.PreForward...),
		PostForward:        append([]string(nil), h.PostForward...),
		PreOutput:          append([]string(nil), h.PreOutput...),
		PostOutput:         append([]string(nil), h.PostOutput...),
		HostPrePrerouting:  append([]string(nil), h.HostPrePrerouting...),
		HostPostPrerouting: append([]string(nil), h.HostPostPrerouting...),
		HostPreInput:       append([]string(nil), h.HostPreInput...),
		HostPostInput:      append([]string(nil), h.HostPostInput...),
	}
}

func parseLocalServices(items []localServiceYAML) ([]firewall.LocalService, error) {
	if len(items) == 0 {
		return nil, nil
	}
	var out []firewall.LocalService
	for i, svc := range items {
		proto := strings.ToLower(strings.TrimSpace(svc.Proto))
		if proto != "tcp" && proto != "udp" {
			return nil, fmt.Errorf("[%d]: proto must be tcp or udp", i)
		}
		if svc.Port == 0 {
			return nil, fmt.Errorf("[%d]: port is required", i)
		}
		var srcs []netip.Prefix
		for _, s := range svc.Sources {
			p, err := netip.ParsePrefix(s)
			if err != nil {
				return nil, fmt.Errorf("[%d]: invalid source %q: %w", i, s, err)
			}
			srcs = append(srcs, p.Masked())
		}
		out = append(out, firewall.LocalService{Proto: proto, Port: svc.Port, Sources: srcs})
	}
	return out, nil
}

// parseFirewallListenAddrs parses a list of listen addresses for host firewall
// rules. Plain IPs are accepted; host:port forms have their host portion
// extracted for use as a destination address match.
func parseFirewallListenAddrs(items []string) ([]netip.Addr, error) {
	if len(items) == 0 {
		return nil, nil
	}
	var out []netip.Addr
	for _, s := range items {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		addr := s
		if host, _, err := net.SplitHostPort(s); err == nil {
			addr = host
		}
		addr = strings.Trim(addr, "[]")
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			return nil, fmt.Errorf("invalid listen address %q: %w", s, err)
		}
		out = append(out, ip)
	}
	return out, nil
}

func oneOfFirewallMode(mode string) bool {
	return mode == firewall.ModeManaged || mode == firewall.ModeExternal || mode == firewall.ModeDisabled
}

func oneOfFirewallBackend(backend string) bool {
	switch backend {
	case firewall.BackendAuto, firewall.BackendNFT, firewall.BackendIptables, firewall.BackendNone:
		return true
	}
	return false
}

// ManagedInstances returns enabled instances Photon may manage.
func (config FirewallConfig) ManagedInstances() []firewall.FirewallInstanceSpec {
	var out []firewall.FirewallInstanceSpec
	for _, inst := range config.Instances {
		if inst.Enabled && inst.Mode == firewall.ModeManaged {
			out = append(out, inst)
		}
	}
	return out
}

// Declared config blocks are enabled unless explicitly disabled.
func configEnabled(path string, enabled, disabled *bool) (bool, error) {
	if enabled != nil && disabled != nil && *enabled == *disabled {
		return false, fmt.Errorf("%s.enabled conflicts with %s.disabled", path, path)
	}
	if disabled != nil {
		return !*disabled, nil
	}
	return enabled == nil || *enabled, nil
}
