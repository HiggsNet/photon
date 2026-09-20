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
trusted_root_public_key: ` + hex.EncodeToString(pub) + `
gossip:
  peer_id: node-a
  listen_addr: 0.0.0.0:33434
  max_datagram_bytes: 32768
  max_sync_zones: 8
  max_sync_records: 512
  endpoint_grace: 2m
  reflector_timeout: 1500ms
  publish_endpoints: false
  bootstrap:
    - id: node-b
      addr: 127.0.0.1:33435
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.StatePath != "/tmp/photon-a/photon.db" {
		t.Fatalf("StatePath = %q, want /tmp/photon-a/photon.db", config.StatePath)
	}
	if config.PeerID != "node-a" || config.ListenAddr != "0.0.0.0:33434" {
		t.Fatalf("peer/listen = %q/%q", config.PeerID, config.ListenAddr)
	}
	if len(config.Bootstrap) != 1 || config.Bootstrap[0].ID != "node-b" || config.Bootstrap[0].Addr != "127.0.0.1:33435" {
		t.Fatalf("Bootstrap = %#v", config.Bootstrap)
	}
	if !bytes.Equal(config.TrustedRootPublicKey, pub) {
		t.Fatalf("TrustedRootPublicKey mismatch")
	}
	if config.MaxMessageBytes != 32768 || config.MaxSyncZones != 8 || config.MaxSyncRecords != 512 {
		t.Fatalf("sync limits = %d/%d/%d", config.MaxMessageBytes, config.MaxSyncZones, config.MaxSyncRecords)
	}
	if config.EndpointGrace.String() != "2m0s" {
		t.Fatalf("EndpointGrace = %s, want 2m0s", config.EndpointGrace)
	}
	if config.ReflectorTimeout.String() != "1.5s" {
		t.Fatalf("ReflectorTimeout = %s, want 1.5s", config.ReflectorTimeout)
	}
	if config.PublishEndpoints {
		t.Fatalf("PublishEndpoints = true, want false")
	}
	if config.IPsec.DefaultNetNS.Name != ipsec.DefaultNetNSName || !config.IPsec.DefaultNetNS.Create {
		t.Fatalf("IPsec.DefaultNetNS = %+v", config.IPsec.DefaultNetNS)
	}
	if config.Overlay.DefaultNetNS.Name != ipsec.DefaultNetNSName || !config.Overlay.DefaultNetNS.Create {
		t.Fatalf("Overlay.DefaultNetNS = %+v", config.Overlay.DefaultNetNS)
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

func TestParseConfigYAMLCanDisablePrivateIPv4Filter(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML("gossip:\n  filter_private_ipv4: false\n", config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if config.FilterPrivateIPv4 {
		t.Fatal("FilterPrivateIPv4 = true, want false")
	}
}

func TestParseConfigYAMLLists(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  advertise_addrs:
    - 127.0.0.1:33434
    - 10.0.0.2:33434
  reflectors:
    - 198.51.100.10:33434
    - 198.51.100.11:33434
  bootstrap:
    - id: node-b
      addr: 127.0.0.1:33435
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if got := strings.Join(config.AdvertiseAddrs, ","); got != "127.0.0.1:33434,10.0.0.2:33434" {
		t.Fatalf("AdvertiseAddrs = %q", got)
	}
	if got := strings.Join(config.Reflectors, ","); got != "198.51.100.10:33434,198.51.100.11:33434" {
		t.Fatalf("Reflectors = %q", got)
	}
	if len(config.Bootstrap) != 1 || config.Bootstrap[0].ID != "node-b" {
		t.Fatalf("Bootstrap = %#v", config.Bootstrap)
	}
}

func TestParseConfigYAMLRejectsUnknownFields(t *testing.T) {
	config := defaultAppConfig()
	if err := parseConfigYAML("unknown: true\n", config); err == nil {
		t.Fatalf("parseConfigYAML should reject unknown config fields")
	}
}
