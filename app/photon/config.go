package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigPath              = "/etc/photon/config.yaml"
	defaultDataDir                 = "/etc/photon"
	defaultStateFile               = "photon.db"
	defaultIPsecPortPreviousGrace  = 2 * time.Hour
	defaultIPsecRotateRetentionSec = 3600
)

type appConfig struct {
	DataDir              string
	StatePath            string
	ManagedZone          zone.ZonePath
	Identity             identityConfig
	PeerID               string
	ListenAddr           string
	Bootstrap            []syncConfigPeer
	TrustedRootPublicKey ed25519.PublicKey
	MaxMessageBytes      int
	MaxSyncZones         int
	MaxSyncRecords       int
	LogLevel             string
	Log                  logConfig
	AdvertiseAddrs       []string
	Reflectors           []string
	ReflectorInterval    time.Duration
	ReflectorTimeout     time.Duration
	EndpointTTL          time.Duration
	EndpointRefresh      time.Duration
	EndpointGrace        time.Duration
	PublishEndpoints     bool
	EndpointDiscovery    string
	EndpointSourceOrder  []string
	FilterPrivateIPv4    bool
	Overlay              overlayConfig
	IPsec                ipsecConfig
	IPAM                 ipamConfig
	Netns                netnsConfig
	Routing              routingConfig
	Firewall             firewallConfig
	PeerLifecycle        inspect.PeerLifecycleConfig
	Health               healthConfig
	Observer             observerConfig
}

type syncConfigPeer struct {
	ID   string `json:"id" yaml:"id"`
	Addr string `json:"addr" yaml:"addr"`
}

type configYAML struct {
	DataDir string `yaml:"data_dir"`

	StatePath string `yaml:"state_path"`

	TrustedRootPublicKey string `yaml:"trusted_root_public_key"`
	RootPublicKey        string `yaml:"root_public_key"`
	TrustedRootKey       string `yaml:"trusted_root_key"`

	Log logConfigYAML `yaml:"log"`

	Overlay       overlayDefaultsYAML      `yaml:"overlay"`
	IPsec         ipsecConfigYAML          `yaml:"ipsec"`
	IPAM          ipamConfigYAML           `yaml:"ipam"`
	Netns         *netnsConfigYAML         `yaml:"netns"`
	Routing       *routingInstancesYAML    `yaml:"routing"`
	Firewall      *firewallConfigYAML      `yaml:"firewall"`
	PeerLifecycle *peerLifecycleYAML       `yaml:"peer_lifecycle"`
	Health        *healthConfigYAML        `yaml:"health"`
	Observer      *observerConfigYAML      `yaml:"observer"`
	Overlays      []overlayGroupConfigYAML `yaml:"overlays"`
	Gossip        gossipConfigYAML         `yaml:"gossip"`
}

// peerLifecycleYAML is the YAML representation of PeerLifecycleConfig.
type peerLifecycleYAML struct {
	StaleAfter       string `yaml:"stale_after"`
	OfflineAfter     string `yaml:"offline_after"`
	CleanupAfter     string `yaml:"cleanup_after"`
	KeepSAWhileStale *bool  `yaml:"keep_sa_while_stale"`
}

type configStringList []string

type identityConfig struct {
	KeyPath string
}

type identityYAML struct {
	KeyPath string `yaml:"key_path"`
}

type gossipConfigYAML struct {
	Init gossipInitYAML `yaml:"init"`

	PeerID     string `yaml:"peer_id"`
	ListenAddr string `yaml:"listen_addr"`

	Bootstrap []syncConfigPeer `yaml:"bootstrap"`

	MaxDatagramBytes *int `yaml:"max_datagram_bytes"`
	MaxSyncZones     *int `yaml:"max_sync_zones"`
	MaxSyncRecords   *int `yaml:"max_sync_records"`

	AdvertiseAddr  string           `yaml:"advertise_addr"`
	AdvertiseAddrs configStringList `yaml:"advertise_addrs"`
	Reflector      string           `yaml:"reflector"`
	Reflectors     configStringList `yaml:"reflectors"`

	ReflectorInterval   string           `yaml:"reflector_interval"`
	ReflectorTimeout    string           `yaml:"reflector_timeout"`
	EndpointTTL         string           `yaml:"endpoint_ttl"`
	EndpointRefresh     string           `yaml:"endpoint_refresh"`
	EndpointGrace       string           `yaml:"endpoint_grace"`
	EndpointGracePeriod string           `yaml:"endpoint_grace_period"`
	PublishEndpoints    *bool            `yaml:"publish_endpoints"`
	EndpointDiscovery   string           `yaml:"endpoint_discovery"`
	EndpointSourceOrder configStringList `yaml:"endpoint_source_order"`

	FilterPrivateIPv4 *bool `yaml:"filter_private_ipv4"`
}

type gossipInitYAML struct {
	ManagedZone string       `yaml:"managed_zone"`
	KeyPath     string       `yaml:"key_path"`
	Identity    identityYAML `yaml:"identity"`
}

type logConfig struct {
	Level string
	Mode  string
	File  string
}

type logConfigYAML struct {
	Level string `yaml:"level"`
	Mode  string `yaml:"mode"`
	File  string `yaml:"file"`
}

type overlayConfig struct {
	DefaultNetNS ipsec.NetNSSpec
}

type overlayDefaultsYAML struct{}

type ipsecConfig struct {
	DefaultNetNS              ipsec.NetNSSpec
	LinkGroups                []ipsec.LinkGroupSpec
	Role                      string
	Driver                    string
	VICISocket                string
	PortMode                  string
	PortRange                 ipsec.PortRange
	PortRotateInterval        time.Duration
	PortPreviousGrace         time.Duration
	AnnounceAddrs             []string
	AnnounceDNS               []string
	AnnounceDNSReconnectAfter time.Duration
	AnnounceGossipEndpoints   bool
}

type ipsecConfigYAML struct {
	Role                      string           `yaml:"role"`
	DeprecatedAccept          string           `yaml:"accept"`
	Driver                    string           `yaml:"driver"`
	VICISocket                string           `yaml:"vici_socket"`
	PortMode                  string           `yaml:"port_mode"`
	PortRange                 ipsec.PortRange  `yaml:"port_range"`
	PortRotateInterval        string           `yaml:"port_rotate_interval"`
	PortPreviousGrace         string           `yaml:"port_previous_grace"`
	AnnounceAddrs             configStringList `yaml:"announce_addrs"`
	AnnounceDNS               configStringList `yaml:"announce_dns"`
	AnnounceDNSReconnectAfter string           `yaml:"announce_dns_reconnect_after"`
	AnnounceGossipEndpoints   *bool            `yaml:"announce_gossip_endpoints"`
}

type ipamConfig struct {
	AutoAnnounceAssignedIPs bool
	Announce                []string
}

type ipamConfigYAML struct {
	AutoAnnounceAssignedIPs *bool            `yaml:"auto_announce_assigned_ips"`
	Announce                configStringList `yaml:"announce"`
}

type tunnelAddressConfigYAML struct {
	Mode   string `yaml:"mode"`
	Family string `yaml:"family"`
	Pool   string `yaml:"pool"`
}

type overlayGroupConfigYAML struct {
	ID                 string                  `yaml:"id"`
	Name               string                  `yaml:"name"`
	Provider           string                  `yaml:"provider"`
	NetNS              netnsRefYAML            `yaml:"netns"`
	DefaultPathMode    string                  `yaml:"default_path_mode"`
	Direction          string                  `yaml:"direction"`
	AddressSourceOrder configStringList        `yaml:"address_source_order"`
	MaxPeers           *int                    `yaml:"max_peers"`
	MaxLinksPerPeer    *int                    `yaml:"max_links_per_peer"`
	TunnelAddressPool  string                  `yaml:"tunnel_address_pool"`
	TunnelAddress      tunnelAddressConfigYAML `yaml:"tunnel_address"`
	Reconcile          overlayReconcileYAML    `yaml:"reconcile"`
	Connect            configStringList        `yaml:"connect"`
	Deny               configStringList        `yaml:"deny"`
}

type overlayReconcileYAML struct {
	Interval        string             `yaml:"interval"`
	RotateRetention string             `yaml:"rotate_retention"`
	Backoff         overlayBackoffYAML `yaml:"backoff"`
}

type overlayBackoffYAML struct {
	Initial string `yaml:"initial"`
	Max     string `yaml:"max"`
}

type netnsRefYAML struct {
	Ref        string
	Spec       ipsec.NetNSSpec
	InlineSpec bool
}

func (n *netnsRefYAML) UnmarshalYAML(node *yaml.Node) error {
	switch node.Kind {
	case yaml.ScalarNode:
		n.Ref = strings.TrimSpace(node.Value)
		return nil
	case yaml.MappingNode:
		var spec ipsec.NetNSSpec
		if err := node.Decode(&spec); err != nil {
			return err
		}
		n.Spec = spec
		n.InlineSpec = true
		return nil
	default:
		return fmt.Errorf("netns must be a reference string or netns spec object")
	}
}

func loadAppConfig() (*appConfig, error) {
	config := defaultAppConfig()
	path, explicit := selectedConfigPath()
	data, err := os.ReadFile(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) && !explicit {
			normalizeAppConfig(config)
			return config, nil
		}
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := parseConfigYAML(string(data), config); err != nil {
		return nil, err
	}
	normalizeAppConfig(config)
	return config, nil
}

func defaultAppConfig() *appConfig {
	return &appConfig{
		DataDir:             defaultDataDir,
		ListenAddr:          fmt.Sprintf("[::]:%d", gossip.DefaultPort),
		MaxMessageBytes:     gossip.DefaultMaxMessage,
		MaxSyncZones:        corestate.DefaultSyncLimits().MaxZones,
		MaxSyncRecords:      corestate.DefaultSyncLimits().MaxRecords,
		ReflectorInterval:   5 * time.Minute,
		ReflectorTimeout:    3 * time.Second,
		EndpointTTL:         gossip.DefaultEndpointTTL,
		EndpointRefresh:     gossip.DefaultEndpointRefresh,
		EndpointGrace:       gossip.DefaultEndpointGrace,
		PublishEndpoints:    true,
		EndpointSourceOrder: []string{"advertise", "bootstrap", "reflector", "interface"},
		FilterPrivateIPv4:   true,
		Overlay: overlayConfig{
			DefaultNetNS: ipsec.NetNSSpec{}.Normalized(),
		},
		IPsec: ipsecConfig{
			DefaultNetNS:              ipsec.NetNSSpec{}.Normalized(),
			Role:                      ipsec.RoleBoth,
			Driver:                    ipsecDriverStrongSwan,
			PortMode:                  ipsec.PortModeFixed,
			PortRotateInterval:        0,
			PortPreviousGrace:         defaultIPsecPortPreviousGrace,
			AnnounceGossipEndpoints:   true,
			AnnounceDNSReconnectAfter: 5 * time.Minute,
		},
		IPAM: ipamConfig{
			AutoAnnounceAssignedIPs: false,
		},
		Health:   defaultHealthConfig(),
		Observer: defaultObserverConfig(),
	}
}

func normalizeAppConfig(config *appConfig) {
	if config.DataDir == "" {
		config.DataDir = defaultDataDir
	}
	if config.StatePath == "" {
		config.StatePath = filepath.Join(config.DataDir, defaultStateFile)
	}
	if config.ListenAddr == "" {
		config.ListenAddr = fmt.Sprintf("[::]:%d", gossip.DefaultPort)
	}
	if config.MaxMessageBytes <= 0 {
		config.MaxMessageBytes = gossip.DefaultMaxMessage
	}
	if config.MaxSyncZones <= 0 {
		config.MaxSyncZones = corestate.DefaultSyncLimits().MaxZones
	}
	if config.MaxSyncRecords <= 0 {
		config.MaxSyncRecords = corestate.DefaultSyncLimits().MaxRecords
	}
	if config.Log.Level == "" {
		config.Log.Level = config.LogLevel
	}
	if config.LogLevel == "" {
		config.LogLevel = config.Log.Level
	}
	if config.Log.Mode == "" {
		config.Log.Mode = string(logModeStderr)
	}
	config.Overlay.DefaultNetNS = config.Overlay.DefaultNetNS.Normalized()
	config.IPsec.DefaultNetNS = config.Overlay.DefaultNetNS
	if config.IPsec.Role == "" {
		config.IPsec.Role = ipsec.RoleBoth
	}
	if config.IPsec.Driver == "" {
		config.IPsec.Driver = ipsecDriverStrongSwan
	}
	if config.IPsec.PortMode == "" {
		config.IPsec.PortMode = ipsec.PortModeFixed
	}
	if config.IPsec.PortPreviousGrace <= 0 {
		config.IPsec.PortPreviousGrace = defaultIPsecPortPreviousGrace
	}
	if config.EndpointTTL <= 0 {
		config.EndpointTTL = gossip.DefaultEndpointTTL
	}
	if config.EndpointRefresh <= 0 {
		config.EndpointRefresh = gossip.DefaultEndpointRefresh
	}
	if config.EndpointGrace <= 0 {
		config.EndpointGrace = gossip.DefaultEndpointGrace
	}
}

func parseConfigYAML(input string, config *appConfig) error {
	if strings.TrimSpace(input) == "" {
		return nil
	}
	topLevelKeys, err := yamlTopLevelKeys(input)
	if err != nil {
		return fmt.Errorf("config.yaml: %w", err)
	}
	var file configYAML
	decoder := yaml.NewDecoder(strings.NewReader(input))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		return fmt.Errorf("config.yaml: %w", err)
	}
	return applyConfigYAML(config, file, topLevelKeys)
}

func yamlTopLevelKeys(input string) (map[string]bool, error) {
	var root yaml.Node
	if err := yaml.Unmarshal([]byte(input), &root); err != nil {
		return nil, err
	}
	keys := make(map[string]bool)
	if len(root.Content) == 0 || root.Content[0].Kind != yaml.MappingNode {
		return keys, nil
	}
	for i := 0; i+1 < len(root.Content[0].Content); i += 2 {
		keys[root.Content[0].Content[i].Value] = true
	}
	return keys, nil
}

func applyGossipConfigYAML(config *appConfig, file gossipConfigYAML, prefix string) error {
	if file.Init.ManagedZone != "" {
		path := zone.ZonePath(strings.TrimSpace(file.Init.ManagedZone))
		if !path.Valid() || path == zone.RootZone {
			return fmt.Errorf("invalid %sinit.managed_zone: %s", prefix, file.Init.ManagedZone)
		}
		config.ManagedZone = path
	}
	if value := firstNonEmpty(file.Init.KeyPath, file.Init.Identity.KeyPath); value != "" {
		config.Identity.KeyPath = value
	}
	config.PeerID = firstNonEmpty(file.PeerID, config.PeerID)
	config.ListenAddr = firstNonEmpty(file.ListenAddr, config.ListenAddr)
	config.Bootstrap = append(config.Bootstrap, file.Bootstrap...)
	if err := applyPositiveInt(&config.MaxMessageBytes, file.MaxDatagramBytes, prefix+"max_datagram_bytes"); err != nil {
		return err
	}
	if err := applyPositiveInt(&config.MaxSyncZones, file.MaxSyncZones, prefix+"max_sync_zones"); err != nil {
		return err
	}
	if err := applyPositiveInt(&config.MaxSyncRecords, file.MaxSyncRecords, prefix+"max_sync_records"); err != nil {
		return err
	}
	if file.AdvertiseAddr != "" {
		config.AdvertiseAddrs = append(config.AdvertiseAddrs, file.AdvertiseAddr)
	}
	config.AdvertiseAddrs = append(config.AdvertiseAddrs, file.AdvertiseAddrs...)
	if file.Reflector != "" {
		config.Reflectors = append(config.Reflectors, file.Reflector)
	}
	config.Reflectors = append(config.Reflectors, file.Reflectors...)
	if file.ReflectorInterval != "" {
		d, err := parseConfigDuration(file.ReflectorInterval, prefix+"reflector_interval")
		if err != nil {
			return err
		}
		config.ReflectorInterval = d
	}
	if file.ReflectorTimeout != "" {
		d, err := parseConfigDuration(file.ReflectorTimeout, prefix+"reflector_timeout")
		if err != nil {
			return err
		}
		config.ReflectorTimeout = d
	}
	if file.EndpointTTL != "" {
		d, err := parseConfigDuration(file.EndpointTTL, prefix+"endpoint_ttl")
		if err != nil {
			return err
		}
		config.EndpointTTL = d
	}
	if file.EndpointRefresh != "" {
		d, err := parseConfigDuration(file.EndpointRefresh, prefix+"endpoint_refresh")
		if err != nil {
			return err
		}
		config.EndpointRefresh = d
	}
	if value := firstNonEmpty(file.EndpointGrace, file.EndpointGracePeriod); value != "" {
		d, err := parseConfigDuration(value, prefix+"endpoint_grace")
		if err != nil {
			return err
		}
		config.EndpointGrace = d
	}
	if file.PublishEndpoints != nil {
		config.PublishEndpoints = *file.PublishEndpoints
	}
	if file.EndpointDiscovery != "" {
		config.EndpointDiscovery = file.EndpointDiscovery
	}
	if len(file.EndpointSourceOrder) > 0 {
		config.EndpointSourceOrder = normalizeEndpointSourceOrder([]string(file.EndpointSourceOrder))
	}
	if file.FilterPrivateIPv4 != nil {
		config.FilterPrivateIPv4 = *file.FilterPrivateIPv4
	}
	return nil
}

func applyConfigYAML(config *appConfig, file configYAML, topLevelKeys map[string]bool) error {
	if file.DataDir != "" {
		config.DataDir = file.DataDir
		config.StatePath = ""
	}
	if file.StatePath != "" {
		config.StatePath = file.StatePath
	}
	if value := firstNonEmpty(file.TrustedRootPublicKey, file.RootPublicKey, file.TrustedRootKey); value != "" {
		key, err := decodePublicKey(value)
		if err != nil {
			return err
		}
		config.TrustedRootPublicKey = key
	}
	if file.Log.Level != "" {
		config.Log.Level = strings.ToLower(file.Log.Level)
		config.LogLevel = config.Log.Level
	}
	if file.Log.Mode != "" {
		mode := parseLogMode(file.Log.Mode)
		if !isValidLogMode(file.Log.Mode) {
			return fmt.Errorf("invalid log.mode: %s", file.Log.Mode)
		}
		config.Log.Mode = string(mode)
	}
	if file.Log.File != "" {
		config.Log.File = file.Log.File
	}
	if topLevelKeys["gossip"] {
		if err := applyGossipConfigYAML(config, file.Gossip, "gossip."); err != nil {
			return err
		}
	}
	config.Reflectors = gossip.ResolvePublicIPReflectors(config.Reflectors)
	if file.IPsec.Driver != "" {
		driver, err := parseIPsecDriver(file.IPsec.Driver)
		if err != nil {
			return err
		}
		config.IPsec.Driver = driver
	}
	if file.IPsec.Role != "" {
		role := strings.ToLower(strings.TrimSpace(file.IPsec.Role))
		switch role {
		case ipsec.RoleOut, ipsec.RoleIn, ipsec.RoleBoth:
			config.IPsec.Role = role
		default:
			return fmt.Errorf("invalid ipsec.role %q", file.IPsec.Role)
		}
	}
	if file.IPsec.DeprecatedAccept != "" {
		return fmt.Errorf("ipsec.accept is deprecated; use ipsec.role")
	}
	if file.IPsec.VICISocket != "" {
		config.IPsec.VICISocket = file.IPsec.VICISocket
	}
	if file.IPsec.PortMode != "" {
		mode := strings.ToLower(strings.TrimSpace(file.IPsec.PortMode))
		if !ipsec.ValidPortMode(mode) {
			return fmt.Errorf("invalid ipsec.port_mode %q", file.IPsec.PortMode)
		}
		config.IPsec.PortMode = mode
	}
	if config.IPsec.PortMode == ipsec.PortModeRange {
		if file.IPsec.PortRange.From == 0 || file.IPsec.PortRange.To == 0 || file.IPsec.PortRange.From > file.IPsec.PortRange.To {
			return fmt.Errorf("invalid ipsec.port_range %d-%d", file.IPsec.PortRange.From, file.IPsec.PortRange.To)
		}
		if uint32(file.IPsec.PortRange.To)-uint32(file.IPsec.PortRange.From)+1 < 4 {
			return fmt.Errorf("ipsec.port_range %d-%d must contain at least two IKE/NAT-T port pairs", file.IPsec.PortRange.From, file.IPsec.PortRange.To)
		}
		config.IPsec.PortRange = file.IPsec.PortRange
	}
	if file.IPsec.PortRotateInterval != "" {
		d, err := parseConfigDuration(file.IPsec.PortRotateInterval, "ipsec.port_rotate_interval")
		if err != nil {
			return err
		}
		config.IPsec.PortRotateInterval = d
	}
	if file.IPsec.PortPreviousGrace != "" {
		d, err := parseConfigDuration(file.IPsec.PortPreviousGrace, "ipsec.port_previous_grace")
		if err != nil {
			return err
		}
		config.IPsec.PortPreviousGrace = d
	}
	for _, raw := range file.IPsec.AnnounceAddrs {
		candidate := strings.TrimSpace(raw)
		addr, err := netip.ParseAddr(candidate)
		if err != nil {
			return fmt.Errorf("invalid ipsec.announce_addrs entry %q: expected an IP address without a port", raw)
		}
		config.IPsec.AnnounceAddrs = append(config.IPsec.AnnounceAddrs, addr.String())
	}
	config.IPsec.AnnounceDNS = append(config.IPsec.AnnounceDNS, file.IPsec.AnnounceDNS...)
	if file.IPsec.AnnounceDNSReconnectAfter != "" {
		d, err := parseConfigDuration(file.IPsec.AnnounceDNSReconnectAfter, "ipsec.announce_dns_reconnect_after")
		if err != nil {
			return err
		}
		if d < 0 {
			return fmt.Errorf("ipsec.announce_dns_reconnect_after must not be negative")
		}
		config.IPsec.AnnounceDNSReconnectAfter = d
	}
	if file.IPsec.AnnounceGossipEndpoints != nil {
		config.IPsec.AnnounceGossipEndpoints = *file.IPsec.AnnounceGossipEndpoints
	}
	config.IPsec.DefaultNetNS = config.Overlay.DefaultNetNS
	var err error
	config.Netns, err = parseNetnsConfig(file.Netns, config.Overlay.DefaultNetNS)
	if err != nil {
		return err
	}
	// Parse routing.instances[], if any.
	if file.Routing != nil {
		config.Routing, err = parseRoutingConfigInstances(file.Routing.Instances, config.Netns, config.DataDir)
		if err != nil {
			return err
		}
	}
	// Parse firewall.instances[], if any.
	if file.Firewall != nil {
		var err error
		config.Firewall, err = parseFirewallConfig(file.Firewall, config.Netns, config.IPsec, config.DataDir)
		if err != nil {
			return err
		}
	}
	if len(file.Overlays) > 0 {
		groups, err := parseOverlayConfigs(file.Overlays, config.Netns, config.Overlay.DefaultNetNS)
		if err != nil {
			return err
		}
		config.IPsec.LinkGroups = groups
	}
	if err := validateRotateWindows(config); err != nil {
		return err
	}
	if file.IPAM.AutoAnnounceAssignedIPs != nil {
		config.IPAM.AutoAnnounceAssignedIPs = *file.IPAM.AutoAnnounceAssignedIPs
	}
	if len(file.IPAM.Announce) > 0 {
		if file.IPAM.AutoAnnounceAssignedIPs != nil {
			return fmt.Errorf("ipam.announce cannot be combined with legacy ipam.auto_announce_assigned_ips")
		}
		selectors, err := parseIPAMAnnounceSelectors(file.IPAM.Announce)
		if err != nil {
			return err
		}
		config.IPAM.Announce = selectors
	}
	if file.PeerLifecycle != nil {
		pl, err := parsePeerLifecycleConfig(file.PeerLifecycle)
		if err != nil {
			return err
		}
		config.PeerLifecycle = pl
	}
	if topLevelKeys["health"] {
		health := file.Health
		if health == nil {
			health = &healthConfigYAML{}
		}
		hc, err := parseHealthConfig(health)
		if err != nil {
			return err
		}
		config.Health = hc
	}
	if topLevelKeys["observer"] {
		observer := file.Observer
		if observer == nil {
			observer = &observerConfigYAML{}
		}
		oc, err := parseObserverConfig(observer)
		if err != nil {
			return err
		}
		config.Observer = oc
	}
	return nil
}

// parsePeerLifecycleConfig parses the peer_lifecycle YAML section with validation.
func parsePeerLifecycleConfig(y *peerLifecycleYAML) (inspect.PeerLifecycleConfig, error) {
	def := inspect.DefaultPeerLifecycleConfig()
	out := inspect.PeerLifecycleConfig{
		StaleAfter:       def.StaleAfter,
		OfflineAfter:     def.OfflineAfter,
		CleanupAfter:     def.CleanupAfter,
		KeepSAWhileStale: def.KeepSAWhileStale,
	}
	if y.StaleAfter != "" {
		d, err := parseConfigDuration(y.StaleAfter, "peer_lifecycle.stale_after")
		if err != nil {
			return inspect.PeerLifecycleConfig{}, err
		}
		if d <= 0 {
			return inspect.PeerLifecycleConfig{}, fmt.Errorf("peer_lifecycle.stale_after must be positive, got %s", d)
		}
		out.StaleAfter = d
	}
	if y.OfflineAfter != "" {
		d, err := parseConfigDuration(y.OfflineAfter, "peer_lifecycle.offline_after")
		if err != nil {
			return inspect.PeerLifecycleConfig{}, err
		}
		if d <= 0 {
			return inspect.PeerLifecycleConfig{}, fmt.Errorf("peer_lifecycle.offline_after must be positive, got %s", d)
		}
		out.OfflineAfter = d
	}
	if y.CleanupAfter != "" {
		d, err := parseConfigDuration(y.CleanupAfter, "peer_lifecycle.cleanup_after")
		if err != nil {
			return inspect.PeerLifecycleConfig{}, err
		}
		if d <= 0 {
			return inspect.PeerLifecycleConfig{}, fmt.Errorf("peer_lifecycle.cleanup_after must be positive, got %s", d)
		}
		out.CleanupAfter = d
	}
	if y.KeepSAWhileStale != nil {
		out.KeepSAWhileStale = *y.KeepSAWhileStale
	}
	// Validate threshold ordering: stale < offline < cleanup.
	if out.StaleAfter >= out.OfflineAfter {
		return inspect.PeerLifecycleConfig{}, fmt.Errorf("peer_lifecycle.stale_after %s must be less than offline_after %s", out.StaleAfter, out.OfflineAfter)
	}
	if out.OfflineAfter >= out.CleanupAfter {
		return inspect.PeerLifecycleConfig{}, fmt.Errorf("peer_lifecycle.offline_after %s must be less than cleanup_after %s", out.OfflineAfter, out.CleanupAfter)
	}
	return out, nil
}

func validateRotateWindows(config *appConfig) error {
	maxRetention := time.Duration(0)
	for _, group := range config.IPsec.LinkGroups {
		retention := group.Normalized().Reconcile.RotateRetentionSeconds
		if retention == 0 {
			retention = defaultIPsecRotateRetentionSec
		}
		if d := time.Duration(retention) * time.Second; d > maxRetention {
			maxRetention = d
		}
	}
	if maxRetention > 0 && config.IPsec.PortPreviousGrace < maxRetention {
		return fmt.Errorf("ipsec.port_previous_grace %s must be at least overlays[].reconcile.rotate_retention %s", config.IPsec.PortPreviousGrace, maxRetention)
	}
	return nil
}

const (
	ipsecDriverDryRun     = "dry-run"
	ipsecDriverStrongSwan = "strongswan"
)

func parseIPsecDriver(value string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", ipsecDriverDryRun:
		return ipsecDriverDryRun, nil
	case ipsecDriverStrongSwan, "system", "vici":
		return ipsecDriverStrongSwan, nil
	default:
		return "", fmt.Errorf("invalid ipsec.driver %q: expected dry-run or strongswan", value)
	}
}

func parseTunnelAddressConfig(cfg tunnelAddressConfigYAML) (ipsec.TunnelAddressSpec, error) {
	mode := ipsec.TunnelAddressMode(strings.ToLower(strings.TrimSpace(cfg.Mode)))
	switch mode {
	case "", ipsec.TunnelAddressDerivedLinkLocal, ipsec.TunnelAddressDerivedPool, ipsec.TunnelAddressSequentialPool, ipsec.TunnelAddressDisabled:
		// ok
	default:
		return ipsec.TunnelAddressSpec{}, fmt.Errorf("invalid tunnel_address.mode %q", cfg.Mode)
	}
	family := strings.ToLower(strings.TrimSpace(cfg.Family))
	switch family {
	case "", ipsec.FamilyIPv4, ipsec.FamilyIPv6:
		// ok
	default:
		return ipsec.TunnelAddressSpec{}, fmt.Errorf("invalid tunnel_address.family %q", cfg.Family)
	}
	var prefix netip.Prefix
	if cfg.Pool != "" {
		var err error
		prefix, err = netip.ParsePrefix(cfg.Pool)
		if err != nil {
			return ipsec.TunnelAddressSpec{}, fmt.Errorf("invalid tunnel_address.pool %q: %w", cfg.Pool, err)
		}
		if family == "" {
			if prefix.Addr().Is4() {
				family = ipsec.FamilyIPv4
			} else {
				family = ipsec.FamilyIPv6
			}
		}
		if prefix.Addr().Is4() && family != ipsec.FamilyIPv4 {
			return ipsec.TunnelAddressSpec{}, fmt.Errorf("tunnel_address.family %q does not match pool %q", cfg.Family, cfg.Pool)
		}
		if prefix.Addr().Is6() && family != ipsec.FamilyIPv6 {
			return ipsec.TunnelAddressSpec{}, fmt.Errorf("tunnel_address.family %q does not match pool %q", cfg.Family, cfg.Pool)
		}
	}
	if mode == "" {
		if family == ipsec.FamilyIPv4 {
			mode = ipsec.TunnelAddressDisabled
		} else {
			mode = ipsec.TunnelAddressDerivedLinkLocal
		}
	}
	if (mode == ipsec.TunnelAddressDerivedPool || mode == ipsec.TunnelAddressSequentialPool) && !prefix.IsValid() {
		return ipsec.TunnelAddressSpec{}, fmt.Errorf("tunnel_address.mode %q requires a pool", mode)
	}
	return ipsec.TunnelAddressSpec{
		Mode:   mode,
		Family: family,
		Pool:   prefix,
	}, nil
}

func parseOverlayConfigs(overlays []overlayGroupConfigYAML, netnsCfg netnsConfig, defaultNetNS ipsec.NetNSSpec) ([]ipsec.LinkGroupSpec, error) {
	groups := make([]ipsec.LinkGroupSpec, 0, len(overlays))
	for i, overlay := range overlays {
		group, err := parseOverlayConfig(overlay, netnsCfg, defaultNetNS)
		if err != nil {
			return nil, fmt.Errorf("overlays[%d]: %w", i, err)
		}
		groups = append(groups, group)
	}
	return groups, nil
}

func parseOverlayConfig(overlay overlayGroupConfigYAML, netnsCfg netnsConfig, defaultNetNS ipsec.NetNSSpec) (ipsec.LinkGroupSpec, error) {
	netns, err := resolveNetNSRef(overlay.NetNS, netnsCfg, defaultNetNS)
	if err != nil {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("netns: %w", err)
	}
	if overlay.Direction != "" {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("overlays[].direction is deprecated; use ipsec.role instead")
	}
	group := ipsec.LinkGroupSpec{
		ID:                 overlay.ID,
		Name:               overlay.Name,
		Provider:           overlay.Provider,
		NetNS:              netns,
		DefaultPathMode:    overlay.DefaultPathMode,
		AddressSourceOrder: append([]string(nil), overlay.AddressSourceOrder...),
		ConnectRules:       append([]string(nil), overlay.Connect...),
		DenyRules:          append([]string(nil), overlay.Deny...),
	}
	if group.ID == "" {
		group.ID = group.Name
	}
	if overlay.MaxPeers != nil {
		group.MaxPeers = *overlay.MaxPeers
	}
	if overlay.MaxLinksPerPeer != nil {
		group.MaxLinksPerPeer = *overlay.MaxLinksPerPeer
	}
	legacyPoolSet := overlay.TunnelAddressPool != ""
	newBlockSet := overlay.TunnelAddress.Mode != "" || overlay.TunnelAddress.Family != "" || overlay.TunnelAddress.Pool != ""
	if legacyPoolSet && newBlockSet {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("cannot mix tunnel_address_pool with tunnel_address")
	}
	if legacyPoolSet {
		prefix, err := netip.ParsePrefix(overlay.TunnelAddressPool)
		if err != nil {
			return ipsec.LinkGroupSpec{}, fmt.Errorf("invalid tunnel_address_pool %q: %w", overlay.TunnelAddressPool, err)
		}
		group.TunnelAddressPool = prefix
	}
	if newBlockSet {
		spec, err := parseTunnelAddressConfig(overlay.TunnelAddress)
		if err != nil {
			return ipsec.LinkGroupSpec{}, err
		}
		group.TunnelAddressSpec = spec
	}
	if overlay.Reconcile.Interval != "" {
		d, err := parseConfigDuration(overlay.Reconcile.Interval, "reconcile.interval")
		if err != nil {
			return ipsec.LinkGroupSpec{}, err
		}
		group.Reconcile.IntervalSeconds = durationSeconds(d)
	}
	if overlay.Reconcile.RotateRetention != "" {
		d, err := parseConfigDuration(overlay.Reconcile.RotateRetention, "reconcile.rotate_retention")
		if err != nil {
			return ipsec.LinkGroupSpec{}, err
		}
		group.Reconcile.RotateRetentionSeconds = durationSeconds(d)
	}
	if overlay.Reconcile.Backoff.Initial != "" {
		d, err := parseConfigDuration(overlay.Reconcile.Backoff.Initial, "reconcile.backoff.initial")
		if err != nil {
			return ipsec.LinkGroupSpec{}, err
		}
		group.Reconcile.Backoff.InitialSeconds = durationSeconds(d)
	}
	if overlay.Reconcile.Backoff.Max != "" {
		d, err := parseConfigDuration(overlay.Reconcile.Backoff.Max, "reconcile.backoff.max")
		if err != nil {
			return ipsec.LinkGroupSpec{}, err
		}
		group.Reconcile.Backoff.MaxSeconds = durationSeconds(d)
	}
	if err := group.Validate(); err != nil {
		return ipsec.LinkGroupSpec{}, err
	}
	if _, err := ipsec.ParseMeshPolicyRules(group.ConnectRules); err != nil {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("connect: %w", err)
	}
	if _, err := ipsec.ParseMeshPolicyRules(group.DenyRules); err != nil {
		return ipsec.LinkGroupSpec{}, fmt.Errorf("deny: %w", err)
	}
	return group.Normalized(), nil
}

func resolveNetNSRef(ref netnsRefYAML, netnsCfg netnsConfig, fallback ipsec.NetNSSpec) (ipsec.NetNSSpec, error) {
	if ref.Ref != "" {
		spec, ok := netnsCfg.Names[ref.Ref]
		if !ok {
			return ipsec.NetNSSpec{}, fmt.Errorf("unknown netns %q", ref.Ref)
		}
		return spec, nil
	}
	if ref.InlineSpec {
		spec := ref.Spec.Normalized()
		if err := spec.Validate(); err != nil {
			return ipsec.NetNSSpec{}, err
		}
		return spec, nil
	}
	key := netnsCfg.Default
	if key == "" {
		key = "default"
	}
	if spec, ok := netnsCfg.Names[key]; ok {
		return spec, nil
	}
	spec := fallback.Normalized()
	if err := spec.Validate(); err != nil {
		return ipsec.NetNSSpec{}, err
	}
	return spec, nil
}

func (list *configStringList) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind == yaml.SequenceNode {
		var values []string
		if err := node.Decode(&values); err != nil {
			return err
		}
		*list = append((*list)[:0], values...)
		return nil
	}
	var value string
	if err := node.Decode(&value); err != nil {
		return err
	}
	*list = (*list)[:0]
	for v := range strings.SplitSeq(value, ",") {
		if v = strings.TrimSpace(v); v != "" {
			*list = append(*list, v)
		}
	}
	return nil
}

func parseIPAMAnnounceSelectors(values []string) ([]string, error) {
	seen := make(map[string]bool, len(values))
	out := make([]string, 0, len(values))
	for _, raw := range values {
		selector := strings.TrimSpace(raw)
		switch {
		case selector == "all", selector == "non-shared", selector == "shared":
		case strings.HasPrefix(selector, "tag:"):
			tag := strings.TrimPrefix(selector, "tag:")
			if err := routing.ValidateAssignmentTag(tag); err != nil {
				return nil, fmt.Errorf("ipam.announce selector %q: %w", raw, err)
			}
		case strings.HasPrefix(selector, "assignment:"):
			prefix, err := routing.CanonicalizePrefix(strings.TrimPrefix(selector, "assignment:"))
			if err != nil {
				return nil, fmt.Errorf("ipam.announce selector %q: invalid assignment prefix: %w", raw, err)
			}
			selector = "assignment:" + prefix
		default:
			return nil, fmt.Errorf("unsupported ipam.announce selector %q", raw)
		}
		if !seen[selector] {
			seen[selector] = true
			out = append(out, selector)
		}
	}
	return out, nil
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func applyPositiveInt(target *int, value *int, name string) error {
	if value == nil {
		return nil
	}
	if *value <= 0 {
		return fmt.Errorf("invalid %s: %d", name, *value)
	}
	*target = *value
	return nil
}

func parseConfigDuration(value, name string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %q", name, value)
	}
	return d, nil
}

func normalizeEndpointSourceOrder(order []string) []string {
	valid := map[string]bool{"bootstrap": true, "advertise": true, "reflector": true, "interface": true}
	seen := make(map[string]bool)
	var out []string
	for _, s := range order {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "" || !valid[s] || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	if len(out) == 0 {
		return []string{"advertise", "bootstrap", "reflector", "interface"}
	}
	return out
}

func durationSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int(d.Round(time.Second) / time.Second)
}

func decodePublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	if decoded, err := hex.DecodeString(value); err == nil {
		if len(decoded) != ed25519.PublicKeySize {
			return nil, fmt.Errorf("trusted root public key must be %d bytes", ed25519.PublicKeySize)
		}
		return ed25519.PublicKey(decoded), nil
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
	} {
		decoded, err := encoding.DecodeString(value)
		if err == nil {
			if len(decoded) != ed25519.PublicKeySize {
				return nil, fmt.Errorf("trusted root public key must be %d bytes", ed25519.PublicKeySize)
			}
			return ed25519.PublicKey(decoded), nil
		}
	}
	return nil, fmt.Errorf("trusted root public key must be hex or base64")
}

func configPath() string {
	path, _ := selectedConfigPath()
	return path
}

func selectedConfigPath() (string, bool) {
	if path := os.Getenv("PHOTON_CONFIG"); path != "" {
		return path, true
	}
	return defaultConfigPath, false
}

func configuredStatePath() (string, error) {
	if path := statePathOverride(); path != "" {
		return path, nil
	}
	config, err := loadAppConfig()
	if err != nil {
		return "", err
	}
	return config.StatePath, nil
}

func statePathOverride() string {
	return os.Getenv("PHOTON_STATE")
}

func configuredPeerID(config *appConfig, verified *corestate.VerifiedState) string {
	if config != nil && config.PeerID != "" {
		return config.PeerID
	}
	if verified == nil {
		return "local"
	}
	if verified.ManagedZone != "" && verified.ManagedZone != zone.RootZone {
		return string(verified.ManagedZone)
	}
	if len(verified.IdentityPrivateKey) == 0 {
		return "local"
	}
	pub := verified.IdentityPrivateKey.Public().(ed25519.PublicKey)
	return hex.EncodeToString(photoncrypto.KeyID(pub))[:16]
}

func configuredKnownPeers(config *appConfig) map[string]*net.UDPAddr {
	if config == nil {
		return nil
	}
	peers := make(map[string]*net.UDPAddr, len(config.Bootstrap))
	for _, peer := range config.Bootstrap {
		if peer.ID == "" || peer.Addr == "" {
			continue
		}
		addr, err := net.ResolveUDPAddr("udp", peer.Addr)
		if err != nil {
			continue
		}
		peers[peer.ID] = addr
	}
	return peers
}

func enabledFromPresence(enabledName, disabledName string, presentDefault bool, enabled, disabled *bool) (bool, error) {
	out := presentDefault
	if enabled != nil {
		out = *enabled
	}
	if disabled != nil {
		disabledValue := *disabled
		if enabled != nil && *enabled == disabledValue {
			return false, fmt.Errorf("%s conflicts with %s", enabledName, disabledName)
		}
		out = !disabledValue
	}
	return out, nil
}
