// Package photonwindows contains Windows product composition and platform
// adapters. Files without Windows build tags must remain portable so config
// validation and unit tests can run on development hosts.
package photonwindows

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"gopkg.in/yaml.v3"
)

const ConfigSchemaVersion = 1

type Config struct {
	SchemaVersion        int
	TrustedRootPublicKey ed25519.PublicKey
	ManagedZone          zone.ZonePath
	State                StateConfig
	Overlay              OverlayConfig
	Gateway              GatewayConfig
	Wintun               WintunConfig
	Log                  LogConfig
	Reconnect            ReconnectConfig
	GossipListen         string
}

type StateConfig struct {
	Path string
}

type OverlayConfig struct {
	ID          string
	SplitRoutes []netip.Prefix
}

type GatewayConfig struct {
	AllowedZones   []zone.ZonePath
	BootstrapHints []BootstrapHint
}

// BootstrapHint only locates an initial peer. It never authorizes the peer;
// identity, transport and route authorization still come from verified Photon
// records.
type BootstrapHint struct {
	Peer    zone.ZonePath
	Address string
}

type WintunConfig struct {
	AdapterName string
	MTU         int
}

type LogConfig struct {
	Level string
}

type ReconnectConfig struct {
	InitialBackoff time.Duration
	MaxBackoff     time.Duration
}

type rawConfig struct {
	GossipListen         string `yaml:"gossip_listen"`
	SchemaVersion        int    `yaml:"schema_version"`
	TrustedRootPublicKey string `yaml:"trusted_root_public_key"`
	ManagedZone          string `yaml:"managed_zone"`
	State                struct {
		Path string `yaml:"path"`
	} `yaml:"state"`
	Overlay struct {
		ID          string   `yaml:"id"`
		SplitRoutes []string `yaml:"split_routes"`
	} `yaml:"overlay"`
	Gateway struct {
		AllowedZones   []string           `yaml:"allowed_zones"`
		BootstrapHints []rawBootstrapHint `yaml:"bootstrap_hints"`
	} `yaml:"gateway"`
	Wintun struct {
		AdapterName string `yaml:"adapter_name"`
		MTU         int    `yaml:"mtu"`
	} `yaml:"wintun"`
	Log struct {
		Level string `yaml:"level"`
	} `yaml:"log"`
	Reconnect struct {
		InitialBackoff string `yaml:"initial_backoff"`
		MaxBackoff     string `yaml:"max_backoff"`
	} `yaml:"reconnect"`
}

type rawBootstrapHint struct {
	Peer    string `yaml:"peer"`
	Address string `yaml:"address"`
}

func LoadConfig(path string) (*Config, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("config path is empty")
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open Photon Windows config %s: %w", path, err)
	}
	defer f.Close()
	config, err := ParseConfig(f)
	if err != nil {
		return nil, fmt.Errorf("Photon Windows config %s: %w", path, err)
	}
	return config, nil
}

func ParseConfig(r io.Reader) (*Config, error) {
	if r == nil {
		return nil, errors.New("config input is nil")
	}
	var raw rawConfig
	decoder := yaml.NewDecoder(r)
	decoder.KnownFields(true)
	if err := decoder.Decode(&raw); err != nil {
		return nil, err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return nil, errors.New("multiple YAML documents are not allowed")
		}
		return nil, err
	}
	return normalizeConfig(raw)
}

func normalizeConfig(raw rawConfig) (*Config, error) {
	if raw.SchemaVersion != ConfigSchemaVersion {
		return nil, fmt.Errorf("schema_version must be %d", ConfigSchemaVersion)
	}
	root, err := parseRootPublicKey(raw.TrustedRootPublicKey)
	if err != nil {
		return nil, fmt.Errorf("trusted_root_public_key: %w", err)
	}
	managed := zone.ZonePath(strings.TrimSpace(raw.ManagedZone))
	if !managed.Valid() || managed.IsRoot() {
		return nil, errors.New("managed_zone must be a non-root fully-qualified Photon zone ending in '.'")
	}

	config := &Config{
		GossipListen:         strings.TrimSpace(raw.GossipListen),
		SchemaVersion:        raw.SchemaVersion,
		TrustedRootPublicKey: root,
		ManagedZone:          managed,
		State: StateConfig{
			Path: strings.TrimSpace(raw.State.Path),
		},
		Overlay: OverlayConfig{
			ID: strings.TrimSpace(raw.Overlay.ID),
		},
		Wintun: WintunConfig{
			AdapterName: strings.TrimSpace(raw.Wintun.AdapterName),
			MTU:         raw.Wintun.MTU,
		},
		Log: LogConfig{
			Level: strings.ToLower(strings.TrimSpace(raw.Log.Level)),
		},
	}
	if config.State.Path == "" {
		return nil, errors.New("state.path is required")
	}
	if config.GossipListen == "" {
		config.GossipListen = "0.0.0.0:33434"
	}
	if _, err := netip.ParseAddrPort(config.GossipListen); err != nil {
		return nil, fmt.Errorf("gossip_listen must be an IP:port: %w", err)
	}
	if config.Overlay.ID == "" {
		return nil, errors.New("overlay.id is required")
	}

	config.Overlay.SplitRoutes, err = parseSplitRoutes(raw.Overlay.SplitRoutes)
	if err != nil {
		return nil, err
	}
	config.Gateway.AllowedZones, err = parseAllowedZones(raw.Gateway.AllowedZones)
	if err != nil {
		return nil, err
	}
	config.Gateway.BootstrapHints, err = parseBootstrapHints(raw.Gateway.BootstrapHints, config.Gateway.AllowedZones)
	if err != nil {
		return nil, err
	}

	if config.Wintun.AdapterName == "" {
		config.Wintun.AdapterName = "Photon Windows"
	}
	if len(config.Wintun.AdapterName) > 128 {
		return nil, errors.New("wintun.adapter_name is longer than 128 characters")
	}
	if config.Wintun.MTU == 0 {
		config.Wintun.MTU = 1400
	}
	if config.Wintun.MTU < 1280 || config.Wintun.MTU > 65535 {
		return nil, fmt.Errorf("wintun.mtu %d is outside [1280, 65535]", config.Wintun.MTU)
	}
	if config.Log.Level == "" {
		config.Log.Level = "info"
	}
	switch config.Log.Level {
	case "debug", "info", "warn", "error":
	default:
		return nil, fmt.Errorf("log.level %q is not one of debug, info, warn, error", config.Log.Level)
	}
	config.Reconnect.InitialBackoff, err = parseDurationDefault(raw.Reconnect.InitialBackoff, time.Second, "reconnect.initial_backoff")
	if err != nil {
		return nil, err
	}
	config.Reconnect.MaxBackoff, err = parseDurationDefault(raw.Reconnect.MaxBackoff, time.Minute, "reconnect.max_backoff")
	if err != nil {
		return nil, err
	}
	if config.Reconnect.MaxBackoff < config.Reconnect.InitialBackoff {
		return nil, errors.New("reconnect.max_backoff must be greater than or equal to reconnect.initial_backoff")
	}
	return config, nil
}

func parseRootPublicKey(value string) (ed25519.PublicKey, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, errors.New("is required; Photon Windows does not use trust-on-first-use")
	}
	if decoded, err := hex.DecodeString(value); err == nil && len(decoded) == ed25519.PublicKeySize {
		return ed25519.PublicKey(decoded), nil
	}
	for _, encoding := range []*base64.Encoding{
		base64.StdEncoding,
		base64.RawStdEncoding,
		base64.URLEncoding,
		base64.RawURLEncoding,
	} {
		decoded, err := encoding.DecodeString(value)
		if err == nil && len(decoded) == ed25519.PublicKeySize {
			return ed25519.PublicKey(decoded), nil
		}
	}
	return nil, fmt.Errorf("must encode exactly %d Ed25519 public-key bytes as base64 or hex", ed25519.PublicKeySize)
}

func parseSplitRoutes(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, errors.New("overlay.split_routes must contain at least one split-tunnel aggregate")
	}
	out := make([]netip.Prefix, 0, len(values))
	seen := make(map[netip.Prefix]struct{}, len(values))
	for i, value := range values {
		prefix, err := netip.ParsePrefix(strings.TrimSpace(value))
		if err != nil {
			return nil, fmt.Errorf("overlay.split_routes[%d]: %w", i, err)
		}
		if prefix != prefix.Masked() {
			return nil, fmt.Errorf("overlay.split_routes[%d] %q is not a canonical network prefix", i, value)
		}
		if prefix.Bits() == 0 {
			return nil, fmt.Errorf("overlay.split_routes[%d] is a default route; Photon Windows v1 is split-tunnel only", i)
		}
		if _, ok := seen[prefix]; ok {
			return nil, fmt.Errorf("overlay.split_routes[%d] duplicates %s", i, prefix)
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	return out, nil
}

func parseAllowedZones(values []string) ([]zone.ZonePath, error) {
	if len(values) == 0 {
		return nil, errors.New("gateway.allowed_zones must contain at least one verified gateway zone")
	}
	out := make([]zone.ZonePath, 0, len(values))
	seen := make(map[zone.ZonePath]struct{}, len(values))
	for i, value := range values {
		path := zone.ZonePath(strings.TrimSpace(value))
		if !path.Valid() || path.IsRoot() {
			return nil, fmt.Errorf("gateway.allowed_zones[%d] must be a non-root fully-qualified Photon zone", i)
		}
		if _, ok := seen[path]; ok {
			return nil, fmt.Errorf("gateway.allowed_zones[%d] duplicates %s", i, path)
		}
		seen[path] = struct{}{}
		out = append(out, path)
	}
	return out, nil
}

func parseBootstrapHints(values []rawBootstrapHint, allowed []zone.ZonePath) ([]BootstrapHint, error) {
	allowedSet := make(map[zone.ZonePath]struct{}, len(allowed))
	for _, path := range allowed {
		allowedSet[path] = struct{}{}
	}
	out := make([]BootstrapHint, 0, len(values))
	for i, raw := range values {
		peer := zone.ZonePath(strings.TrimSpace(raw.Peer))
		if _, ok := allowedSet[peer]; !ok {
			return nil, fmt.Errorf("gateway.bootstrap_hints[%d].peer must appear in gateway.allowed_zones", i)
		}
		address := strings.TrimSpace(raw.Address)
		host, port, err := net.SplitHostPort(address)
		if err != nil || strings.TrimSpace(host) == "" || strings.TrimSpace(port) == "" {
			return nil, fmt.Errorf("gateway.bootstrap_hints[%d].address must be host:port: %q", i, raw.Address)
		}
		portNumber, err := strconv.Atoi(port)
		if err != nil || portNumber < 1 || portNumber > 65535 {
			return nil, fmt.Errorf("gateway.bootstrap_hints[%d].address has an invalid UDP port: %q", i, raw.Address)
		}
		out = append(out, BootstrapHint{Peer: peer, Address: address})
	}
	return out, nil
}

func parseDurationDefault(value string, fallback time.Duration, field string) (time.Duration, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return fallback, nil
	}
	duration, err := time.ParseDuration(value)
	if err != nil || duration <= 0 {
		return 0, fmt.Errorf("%s must be a positive duration: %q", field, value)
	}
	return duration, nil
}
