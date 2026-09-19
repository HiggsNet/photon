package main

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"gopkg.in/yaml.v3"
)

const (
	defaultConfigPath = "/etc/photon/config.yaml"
	defaultDataDir    = "/etc/photon"
	defaultStateFile  = "photon.db"
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
	IPsec                photonlinux.IPsecConfig
	IPAM                 ipamConfig
	Netns                photonlinux.NetNSConfig
	Routing              photonlinux.RoutingConfig
	Firewall             photonlinux.FirewallConfig
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

	Overlay       overlayDefaultsYAML             `yaml:"overlay"`
	IPsec         photonlinux.IPsecConfigYAML     `yaml:"ipsec"`
	IPAM          ipamConfigYAML                  `yaml:"ipam"`
	Netns         *photonlinux.NetNSConfigYAML    `yaml:"netns"`
	Routing       *photonlinux.RoutingConfigYAML  `yaml:"routing"`
	Firewall      *photonlinux.FirewallConfigYAML `yaml:"firewall"`
	PeerLifecycle *peerLifecycleYAML              `yaml:"peer_lifecycle"`
	Health        *healthConfigYAML               `yaml:"health"`
	Observer      *observerConfigYAML             `yaml:"observer"`
	Overlays      []photonlinux.OverlayConfigYAML `yaml:"overlays"`
	Gossip        gossipConfigYAML                `yaml:"gossip"`
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

type ipamConfig struct {
	AutoAnnounceAssignedIPs bool
	Announce                []string
}

type ipamConfigYAML struct {
	AutoAnnounceAssignedIPs *bool            `yaml:"auto_announce_assigned_ips"`
	Announce                configStringList `yaml:"announce"`
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
		IPsec: photonlinux.DefaultIPsecConfig(),
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
	config.IPsec.Normalize()
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
	if err := file.IPsec.Apply(&config.IPsec); err != nil {
		return err
	}
	config.IPsec.DefaultNetNS = config.Overlay.DefaultNetNS
	var err error
	config.Netns, err = photonlinux.ParseNetNSConfig(file.Netns, config.Overlay.DefaultNetNS)
	if err != nil {
		return err
	}
	// Parse routing.instances[], if any.
	if file.Routing != nil {
		config.Routing, err = photonlinux.ParseRoutingConfig(file.Routing.Instances, config.Netns, config.DataDir)
		if err != nil {
			return err
		}
	}
	// Parse firewall.instances[], if any.
	if file.Firewall != nil {
		var err error
		config.Firewall, err = photonlinux.ParseFirewallConfig(file.Firewall, config.Netns.Names, config.IPsec.PortMode)
		if err != nil {
			return err
		}
	}
	if len(file.Overlays) > 0 {
		groups, err := photonlinux.ParseOverlayConfigs(file.Overlays, config.Netns, config.Overlay.DefaultNetNS)
		if err != nil {
			return err
		}
		config.IPsec.LinkGroups = groups
	}
	if err := photonlinux.ValidateIPsecRotateWindows(config.IPsec.LinkGroups, config.IPsec.PortPreviousGrace); err != nil {
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
