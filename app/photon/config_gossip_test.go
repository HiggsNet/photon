package main

import (
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestParseConfigYAMLGossipSection(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  init:
    managed_zone: node-a.catofes.
    key_path: /var/lib/photon/identity.key.json
  peer_id: node-a.catofes.
  listen_addr: 0.0.0.0:33434
  max_datagram_bytes: 1200
  max_sync_zones: 16
  max_sync_records: 1024
  advertise_addrs:
    - 203.0.113.10:33434
  endpoint_discovery: all
  publish_endpoints: false
  reflectors: auto
  reflector_interval: 5m
  reflector_timeout: 3s
  endpoint_ttl: 3h
  endpoint_refresh: 30m
  endpoint_grace: 10m
  endpoint_source_order:
    - bootstrap
    - advertise
  filter_private_ipv4: false
  bootstrap:
    - id: node-b.catofes.
      addr: 203.0.113.20:33434
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.ManagedZone.String() != "node-a.catofes." {
		t.Fatalf("ManagedZone = %q", config.ManagedZone)
	}
	if config.Identity.KeyPath != "/var/lib/photon/identity.key.json" {
		t.Fatalf("Identity.KeyPath = %q", config.Identity.KeyPath)
	}
	if config.PeerID != "node-a.catofes." || config.ListenAddr != "0.0.0.0:33434" {
		t.Fatalf("peer/listen = %q/%q", config.PeerID, config.ListenAddr)
	}
	if len(config.Bootstrap) != 1 || config.Bootstrap[0].ID != "node-b.catofes." || config.Bootstrap[0].Addr != "203.0.113.20:33434" {
		t.Fatalf("Bootstrap = %#v", config.Bootstrap)
	}
	if config.MaxMessageBytes != 1200 || config.MaxSyncZones != 16 || config.MaxSyncRecords != 1024 {
		t.Fatalf("sync limits = %d/%d/%d", config.MaxMessageBytes, config.MaxSyncZones, config.MaxSyncRecords)
	}
	if got := strings.Join(config.AdvertiseAddrs, ","); got != "203.0.113.10:33434" {
		t.Fatalf("AdvertiseAddrs = %q", got)
	}
	if len(config.Reflectors) != len(gossip.ResolvePublicIPReflectors([]string{"auto"})) {
		t.Fatalf("Reflectors = %d, want auto preset", len(config.Reflectors))
	}
	if config.ReflectorInterval != 5*time.Minute || config.ReflectorTimeout != 3*time.Second {
		t.Fatalf("reflector timers = %s/%s", config.ReflectorInterval, config.ReflectorTimeout)
	}
	if config.EndpointTTL != 3*time.Hour || config.EndpointRefresh != 30*time.Minute || config.EndpointGrace != 10*time.Minute {
		t.Fatalf("endpoint timers = %s/%s/%s", config.EndpointTTL, config.EndpointRefresh, config.EndpointGrace)
	}
	if config.EndpointDiscovery != "all" || config.PublishEndpoints || config.FilterPrivateIPv4 {
		t.Fatalf("endpoint flags = discovery:%q publish:%t filter:%t", config.EndpointDiscovery, config.PublishEndpoints, config.FilterPrivateIPv4)
	}
	if got := strings.Join(config.EndpointSourceOrder, ","); got != "bootstrap,advertise" {
		t.Fatalf("EndpointSourceOrder = %q", got)
	}
}

func TestParseConfigYAMLKeepsCommaSeparatedAdvertiseAddrs(t *testing.T) {
	config := defaultAppConfig()
	input := `gossip:
  advertise_addrs: 127.0.0.1:33434, 10.0.0.2:33434`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if got := strings.Join(config.AdvertiseAddrs, ","); got != "127.0.0.1:33434,10.0.0.2:33434" {
		t.Fatalf("AdvertiseAddrs = %q", got)
	}
}

func TestParseConfigYAMLExpandsAutoReflectors(t *testing.T) {
	config := defaultAppConfig()
	input := `gossip:
  reflectors: auto, https://custom.example/ip`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	if len(config.Reflectors) != len(gossip.ResolvePublicIPReflectors([]string{"auto"}))+1 {
		t.Fatalf("Reflectors = %d, want custom plus defaults", len(config.Reflectors))
	}
	if config.Reflectors[len(config.Reflectors)-1] != "https://custom.example/ip" {
		t.Fatalf("last reflector = %q, want custom", config.Reflectors[len(config.Reflectors)-1])
	}
}

func TestParseConfigYAMLRejectsLegacyTopLevelGossipFields(t *testing.T) {
	for _, input := range []string{
		"managed_zone: node-a.catofes.\n",
		"identity:\n  key_path: keys/node-a.json\n",
		"peer_id: node-a\n",
		"listen_addr: 127.0.0.1:0\n",
		"gossip:\n  listen_port: 33434\n",
		"bootstrap:\n  - id: node-b\n    addr: 127.0.0.1:33435\n",
		"max_datagram_bytes: 1200\n",
		"advertise_addrs:\n  - 203.0.113.10:33434\n",
		"endpoint_discovery: all\n",
		"publish_endpoints: false\n",
		"filter_private_ipv4: false\n",
	} {
		config := defaultAppConfig()
		if err := parseConfigYAML(input, config); err == nil {
			t.Fatalf("parseConfigYAML(%q) should reject legacy top-level gossip field", input)
		}
	}
}

func TestParseConfigYAMLRejectsExplicitZeroLimits(t *testing.T) {
	for _, input := range []string{
		"gossip:\n  max_datagram_bytes: 0\n",
		"gossip:\n  max_sync_zones: 0\n",
		"gossip:\n  max_sync_records: 0\n",
	} {
		config := defaultAppConfig()
		if err := parseConfigYAML(input, config); err == nil {
			t.Fatalf("parseConfigYAML(%q) should reject explicit zero", input)
		}
	}
}

func TestParseConfigYAMLEndpointDiscovery(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  endpoint_discovery: loopback_only
  endpoint_source_order:
    - bootstrap
    - advertise
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if config.EndpointDiscovery != "loopback_only" {
		t.Fatalf("EndpointDiscovery = %q, want loopback_only", config.EndpointDiscovery)
	}
	if len(config.EndpointSourceOrder) != 2 || config.EndpointSourceOrder[0] != "bootstrap" || config.EndpointSourceOrder[1] != "advertise" {
		t.Fatalf("EndpointSourceOrder = %v, want [bootstrap advertise]", config.EndpointSourceOrder)
	}
}

func TestParseConfigYAMLInvalidEndpointSourceOrderIgnored(t *testing.T) {
	config := defaultAppConfig()
	input := `
gossip:
  endpoint_source_order:
    - bootstrap
    - unknown
    - advertise
    - bootstrap
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.EndpointSourceOrder) != 2 || config.EndpointSourceOrder[0] != "bootstrap" || config.EndpointSourceOrder[1] != "advertise" {
		t.Fatalf("EndpointSourceOrder = %v, want [bootstrap advertise]", config.EndpointSourceOrder)
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
