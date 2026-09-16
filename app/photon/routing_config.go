package main

import (
	"crypto/sha256"
	"fmt"
	"net/netip"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// routingConfig holds top-level routing instance definitions.
type routingConfig struct {
	Instances []photonlinux.RoutingInstance
}

// routingInstancesYAML is the raw YAML model for the top-level `routing:` section.
type routingInstancesYAML struct {
	Instances []routingInstanceYAML `yaml:"instances"`
}

type routingInstanceYAML struct {
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
	Upstream       *upstreamConfigYAML `yaml:"upstream"`
}

// upstreamConfigYAML is the raw YAML model for routing.instances[].upstream.
type upstreamConfigYAML struct {
	Enabled                *bool                `yaml:"enabled"`
	Disabled               *bool                `yaml:"disabled"`
	Mode                   string               `yaml:"mode"`
	CreateVeth             *bool                `yaml:"create_veth"`
	InstallSourceAddresses *bool                `yaml:"install_source_addresses"`
	Mesh                   upstreamEndpointYAML `yaml:"mesh"`
	External               upstreamEndpointYAML `yaml:"external"`
}

type upstreamEndpointYAML struct {
	Interface string `yaml:"interface"`
	NetNS     string `yaml:"netns"`
	IPv4LL    string `yaml:"ipv4_ll"`
	IPv6LL    string `yaml:"ipv6_ll"`
}

const (
	routingShutdownPolicyPersist = "persist"
	routingShutdownPolicyStop    = "stop"

	upstreamModeStatic   = "static"
	upstreamModeExternal = "external"

	defaultMeshIPv4LL     = "169.254.254.1/30"
	defaultMeshIPv6LL     = "fe80::a1:1/64"
	defaultExternalIPv4LL = "169.254.254.2/30"
	defaultExternalIPv6LL = "fe80::a1:2/64"
	defaultMeshVeth       = "phv2host"
	defaultExternalVeth   = "phv2mesh"
)

// parseRoutingConfigInstances parses `routing.instances[]` into routingConfig.
func parseRoutingConfigInstances(yamlInstances []routingInstanceYAML, netnsCfg photonlinux.NetNSConfig, dataDir string) (routingConfig, error) {
	var instances []photonlinux.RoutingInstance
	for i, yi := range yamlInstances {
		inst, err := parseRoutingInstance(yi, netnsCfg, dataDir)
		if err != nil {
			return routingConfig{}, fmt.Errorf("routing.instances[%d]: %w", i, err)
		}
		instances = append(instances, inst)
	}
	return routingConfig{Instances: instances}, nil
}

func parseRoutingInstance(yi routingInstanceYAML, netnsCfg photonlinux.NetNSConfig, dataDir string) (photonlinux.RoutingInstance, error) {
	if yi.ID == "" {
		return photonlinux.RoutingInstance{}, fmt.Errorf("id is required")
	}
	if yi.NetNS == "" {
		yi.NetNS = "default"
	}
	spec, ok := netnsCfg.Names[yi.NetNS]
	if !ok {
		return photonlinux.RoutingInstance{}, fmt.Errorf("netns %q not found in netns section", yi.NetNS)
	}
	netnsName := routingNetNSTarget(spec)
	// path netns requires router_id_label
	if spec.Kind == ipsec.NetNSPath && yi.RouterIDLabel == "" {
		return photonlinux.RoutingInstance{}, fmt.Errorf("router_id_label is required when netns uses path mode")
	}

	enabled, err := enabledFromPresence("routing.instances[].enabled", "routing.instances[].disabled", true, yi.Enabled, yi.Disabled)
	if err != nil {
		return photonlinux.RoutingInstance{}, err
	}

	mode := yi.Mode
	if mode == "" {
		mode = ipsec.RoutingModeManaged
	}
	if !oneOfRoutingMode(mode) {
		return photonlinux.RoutingInstance{}, fmt.Errorf("unsupported routing mode %q", mode)
	}
	shutdownPolicy := normalizedRoutingShutdownPolicy(strings.TrimSpace(yi.ShutdownPolicy))
	if !oneOfRoutingShutdownPolicy(shutdownPolicy) {
		return photonlinux.RoutingInstance{}, fmt.Errorf("unsupported shutdown_policy %q", shutdownPolicy)
	}
	provider := yi.Provider
	if provider == "" {
		provider = "bird"
	}
	if provider != "bird" {
		return photonlinux.RoutingInstance{}, fmt.Errorf("unsupported routing provider %q", provider)
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
		return photonlinux.RoutingInstance{}, fmt.Errorf("rtt_cost must be less than 65535")
	}
	rttMin, err := parseRoutingBabelDuration(yi.RTTMin, bird.DefaultBabelRTTMin, "rtt_min")
	if err != nil {
		return photonlinux.RoutingInstance{}, err
	}
	rttMax, err := parseRoutingBabelDuration(yi.RTTMax, bird.DefaultBabelRTTMax, "rtt_max")
	if err != nil {
		return photonlinux.RoutingInstance{}, err
	}
	if rttMax <= rttMin {
		return photonlinux.RoutingInstance{}, fmt.Errorf("rtt_max must be greater than rtt_min")
	}
	rttDecay := yi.RTTDecay
	if rttDecay == 0 {
		rttDecay = bird.DefaultBabelRTTDecay
	}
	if rttDecay > 256 {
		return photonlinux.RoutingInstance{}, fmt.Errorf("rtt_decay must be between 1 and 256")
	}
	helloInterval, err := parseRoutingBabelDuration(yi.HelloInterval, bird.DefaultBabelHelloInterval, "hello_interval")
	if err != nil {
		return photonlinux.RoutingInstance{}, err
	}
	updateInterval, err := parseRoutingBabelDuration(yi.UpdateInterval, bird.DefaultBabelUpdateInterval, "update_interval")
	if err != nil {
		return photonlinux.RoutingInstance{}, err
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
			return photonlinux.RoutingInstance{}, err
		}
	} else if err := validateBirdControlSocketPath(controlSocket); err != nil {
		return photonlinux.RoutingInstance{}, err
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
		return photonlinux.RoutingInstance{}, fmt.Errorf("upstream: %w", err)
	}

	return photonlinux.RoutingInstance{
		ID:             yi.ID,
		NetNS:          netnsName,
		Enabled:        enabled,
		Protocol:       provider,
		Mode:           mode,
		ShutdownPolicy: shutdownPolicy,
		ControlSocket:  controlSocket,
		PIDFile:        pidFile,
		ConfigFile:     configFile,
		TableID:        tableID,
		MetricBase:     metricBase,
		MetricStaged:   metricStaged,
		MetricDraining: metricDraining,
		RTTCost:        rttCost,
		RTTMin:         rttMin,
		RTTMax:         rttMax,
		RTTDecay:       rttDecay,
		HelloInterval:  helloInterval,
		UpdateInterval: updateInterval,
		ECMP:           ecmp,
		ECMPLimit:      ecmpLimit,
		InterfacePat:   ifacePat,
		RouterIDLabel:  yi.RouterIDLabel,
		Upstream:       upstream,
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

func routingNetNSTarget(spec ipsec.NetNSSpec) string {
	if target := spec.Target(); target != "" {
		return target
	}
	return ipsec.NetNSHost
}

func parseUpstreamConfig(yu *upstreamConfigYAML) (*photonlinux.UpstreamConfig, error) {
	if yu == nil {
		return nil, nil
	}
	enabled, err := enabledFromPresence("routing.instances[].upstream.enabled", "routing.instances[].upstream.disabled", true, yu.Enabled, yu.Disabled)
	if err != nil {
		return nil, err
	}
	if !enabled {
		return &photonlinux.UpstreamConfig{Enabled: false}, nil
	}

	uc := &photonlinux.UpstreamConfig{
		Enabled:           true,
		Mode:              normalizedUpstreamMode(strings.TrimSpace(yu.Mode)),
		CreateVeth:        true,
		MeshInterface:     strings.TrimSpace(yu.Mesh.Interface),
		MeshIPv4LL:        strings.TrimSpace(yu.Mesh.IPv4LL),
		MeshIPv6LL:        strings.TrimSpace(yu.Mesh.IPv6LL),
		ExternalInterface: strings.TrimSpace(yu.External.Interface),
		ExternalNetns:     strings.TrimSpace(yu.External.NetNS),
		ExternalIPv4LL:    strings.TrimSpace(yu.External.IPv4LL),
		ExternalIPv6LL:    strings.TrimSpace(yu.External.IPv6LL),
	}
	// Static mode historically installed an address from each local assignment
	// on the external endpoint. Preserve that default while allowing external
	// routing daemons to opt into address management independently.
	uc.InstallSourceAddresses = uc.Mode == upstreamModeStatic
	if yu.CreateVeth != nil {
		uc.CreateVeth = *yu.CreateVeth
	}
	if yu.InstallSourceAddresses != nil {
		uc.InstallSourceAddresses = *yu.InstallSourceAddresses
	}

	// Apply default link-local addresses when upstream is enabled and the user
	// did not provide explicit values. These are used both for the veth
	// endpoints and as the next-hop for static routes toward the mesh netns.
	if uc.MeshIPv4LL == "" {
		uc.MeshIPv4LL = defaultMeshIPv4LL
	}
	if uc.MeshIPv6LL == "" {
		uc.MeshIPv6LL = defaultMeshIPv6LL
	}
	if uc.ExternalIPv4LL == "" {
		uc.ExternalIPv4LL = defaultExternalIPv4LL
	}
	if uc.ExternalIPv6LL == "" {
		uc.ExternalIPv6LL = defaultExternalIPv6LL
	}

	// Default endpoint interface names when upstream is enabled but not specified.
	if uc.MeshInterface == "" {
		uc.MeshInterface = defaultMeshVeth
	}
	if uc.ExternalInterface == "" {
		uc.ExternalInterface = defaultExternalVeth
	}
	if !oneOfUpstreamMode(uc.Mode) {
		return nil, fmt.Errorf("unsupported mode %q", uc.Mode)
	}

	// Validate IPv4/IPv6 link-local if provided.
	if err := validateOptionalPrefix("mesh.ipv4_ll", uc.MeshIPv4LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("mesh.ipv6_ll", uc.MeshIPv6LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("external.ipv4_ll", uc.ExternalIPv4LL); err != nil {
		return nil, err
	}
	if err := validateOptionalPrefix("external.ipv6_ll", uc.ExternalIPv6LL); err != nil {
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
	return policy == routingShutdownPolicyPersist || policy == routingShutdownPolicyStop
}

func oneOfUpstreamMode(mode string) bool {
	return mode == upstreamModeStatic || mode == upstreamModeExternal
}

func normalizedUpstreamMode(mode string) string {
	if mode == "" {
		return upstreamModeStatic
	}
	return mode
}

func normalizedRoutingShutdownPolicy(policy string) string {
	if policy == "" {
		return routingShutdownPolicyPersist
	}
	return policy
}

// resolveOverlayNetNSName returns the netns name for an overlay group.
// If the group has a named netns, its Target() is returned.
// Otherwise, the fallback default netns name is used.
func resolveOverlayNetNSName(group ipsec.LinkGroupSpec, defaultNetNS ipsec.NetNSSpec) string {
	netns := group.NetNS.Normalized()
	if netns.Kind == "" || (netns.Kind == ipsec.NetNSName && netns.Name == "") {
		netns = defaultNetNS.Normalized()
	}
	name := netns.Target()
	if name == "" {
		return ipsec.NetNSHost
	}
	return name
}

// routingNetnsNames returns sorted unique netns names used by routing instances.
func routingNetnsNames(cfg routingConfig) []string {
	seen := make(map[string]bool)
	var out []string
	for _, inst := range cfg.Instances {
		if !seen[inst.NetNS] {
			seen[inst.NetNS] = true
			out = append(out, inst.NetNS)
		}
	}
	sort.Strings(out)
	return out
}

// netnsRouterIDLabel returns the stable label used for StableRouterID derivation.
// For host netns → "host"; for named netns → the name; for path netns → router_id_label.
func netnsRouterIDLabel(netnsName string, netnsCfg photonlinux.NetNSConfig, inst photonlinux.RoutingInstance) string {
	if inst.RouterIDLabel != "" {
		return inst.RouterIDLabel
	}
	if spec, ok := netnsCfg.Names[netnsName]; ok {
		if spec.Kind == ipsec.NetNSPath {
			// path netns without label should have been rejected at parse time
			return netnsName
		}
		if spec.Kind == ipsec.NetNSHost {
			return ipsec.NetNSHost
		}
		return spec.Target()
	}
	return netnsName
}

// trim strings.Fields helper to avoid importing in multiple places
var _ = strings.TrimSpace
