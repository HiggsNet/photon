package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestParseConfigYAML(t *testing.T) {
	pub := make(ed25519.PublicKey, ed25519.PublicKeySize)
	for i := range pub {
		pub[i] = byte(i)
	}
	config := defaultAppConfig()
	input := `
data_dir: /tmp/photon-a
trusted_root_public_key: ` + hex.EncodeToString(pub)
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.StatePath != "/tmp/photon-a/photon.db" {
		t.Fatalf("StatePath = %q, want /tmp/photon-a/photon.db", config.StatePath)
	}
	if !bytes.Equal(config.TrustedRootPublicKey, pub) {
		t.Fatalf("TrustedRootPublicKey mismatch")
	}
	if config.IPsec.DefaultNetNS.Name != ipsec.DefaultNetNSName || !config.IPsec.DefaultNetNS.Create {
		t.Fatalf("IPsec.DefaultNetNS = %+v", config.IPsec.DefaultNetNS)
	}
}

func TestParseConfigExampleYAML(t *testing.T) {
	data, err := os.ReadFile("../../config.example.yaml")
	if err != nil {
		t.Fatalf("read config.example.yaml: %v", err)
	}
	config := defaultAppConfig()
	if err := parseConfigYAML(string(data), config); err != nil {
		t.Fatalf("parse config.example.yaml: %v", err)
	}
	if config.PeerID == "" {
		t.Fatal("config.example.yaml should set peer_id")
	}
	if len(config.IPsec.LinkGroups) != 0 {
		t.Fatal("config.example.yaml should not enable overlay link groups by default")
	}
	if len(config.Routing.Instances) == 0 {
		t.Fatal("config.example.yaml should include a routing instance example")
	}
}

func TestLoadAppConfigRejectsMissingExplicitConfig(t *testing.T) {
	missingPath := filepath.Join(t.TempDir(), "missing.yaml")
	t.Setenv("PHOTON_CONFIG", missingPath)

	config, err := loadAppConfig()
	if err == nil {
		t.Fatalf("loadAppConfig returned nil error and config %#v for missing explicit config", config)
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("loadAppConfig error = %v, want not-exist error", err)
	}
	if !strings.Contains(err.Error(), missingPath) {
		t.Fatalf("loadAppConfig error = %q, want path %q", err.Error(), missingPath)
	}
}

func TestConfigDefaultsForListenAndPrivateIPv4Filter(t *testing.T) {
	config := defaultAppConfig()
	normalizeAppConfig(config)
	if config.ListenAddr != "[::]:33434" {
		t.Fatalf("ListenAddr = %q, want [::]:33434", config.ListenAddr)
	}
	if !config.FilterPrivateIPv4 {
		t.Fatal("FilterPrivateIPv4 = false, want true")
	}
	if config.IPsec.Driver != photonlinux.IPsecDriverStrongSwan {
		t.Fatalf("IPsec.Driver = %q, want strongswan", config.IPsec.Driver)
	}
}

func TestParseConfigYAMLRejectsUnknownFields(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML("unknown: true\n", config); err == nil {
		t.Fatalf("parseConfigYAML should reject unknown config fields")
	}
}

func TestParseConfigYAMLRejectsLegacyDefaultNetNS(t *testing.T) {
	for _, input := range []string{`
ipsec:
  default_netns:
    kind: name
    name: legacytesth2
    create: true
`, `
overlay:
  default_netns:
    kind: name
    name: legacytesth2
    create: true
`} {
		config := defaultAppConfig()
		if err := parseConfigYAML(input, config); err == nil || !strings.Contains(err.Error(), "field default_netns not found") {
			t.Fatalf("expected unknown default_netns field error, got %v for %s", err, input)
		}
	}
}

func TestParseConfigYAMLRejectsFirewallForwarding(t *testing.T) {
	config := defaultAppConfig()
	err := parseConfigYAML(`
firewall:
  instances:
    - id: mesh
      forwarding:
        transit: true
`, config)
	if err == nil || !strings.Contains(err.Error(), "field forwarding not found") {
		t.Fatalf("expected unknown forwarding field error, got %v", err)
	}
}

func TestParseConfigYAMLRoutingInstancesRejectsLegacyProtocolAlias(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
routing:
  instances:
    - id: main
      netns: photontesth2
      protocol: bird
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatal("parseConfigYAML should reject routing.instances[].protocol")
	}
}

func TestNormalizeConfigPreservesOverridesAndFallsBack(t *testing.T) {
	for _, value := range []string{"0s", "-1s"} {
		t.Run(value, func(t *testing.T) {
			config := defaultAppConfig()
			input := "data_dir: /tmp/photon-normalized\ngossip:\n  endpoint_ttl: " + value + "\n  endpoint_refresh: " + value + "\n  endpoint_grace: " + value + "\n  reflector_interval: 0s\n  reflector_timeout: 0s\n  publish_endpoints: false\n  filter_private_ipv4: false\n"
			if err := parseConfigYAML(input, config); err != nil {
				t.Fatal(err)
			}
			normalizeAppConfig(config)
			defaults := defaultAppConfig()
			if config.EndpointTTL != defaults.EndpointTTL || config.EndpointRefresh != defaults.EndpointRefresh || config.EndpointGrace != defaults.EndpointGrace {
				t.Fatalf("endpoint fallback failed: %+v", config)
			}
			if config.PublishEndpoints || config.FilterPrivateIPv4 || config.ReflectorInterval != 0 || config.ReflectorTimeout != 0 {
				t.Fatal("normalization overwrote explicit false/zero values")
			}
			if config.StatePath != "/tmp/photon-normalized/photon.db" {
				t.Fatalf("derived state path = %q", config.StatePath)
			}
			config.StatePath = "/tmp/explicit-state.db"
			normalizeAppConfig(config)
			if config.StatePath != "/tmp/explicit-state.db" {
				t.Fatal("normalization overwrote explicit state path")
			}
		})
	}
}
