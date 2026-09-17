package main

import (
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"strings"
	"testing"
)

func TestParseConfigYAMLOverlays(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
overlays:
  - name: ipsec-main
    provider: strongswan
    netns: default
    default_path_mode: family-redundant
    address_source_order: manual-dns, discovery
    max_peers: 64
    max_links_per_peer: 2
    tunnel_address_pool: fd00:1234::/64
    reconcile:
      interval: 30s
      rotate_retention: 1h
      backoff:
        initial: 1s
        max: 1m
    connect:
      - "strongswan://*.catofes.?role=in&family=dual"
    deny:
      - "strongswan://*.lab.catofes."
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.IPsec.LinkGroups) != 1 {
		t.Fatalf("LinkGroups len = %d, want 1", len(config.IPsec.LinkGroups))
	}
	group := config.IPsec.LinkGroups[0]
	if group.ID != "ipsec-main" || group.Name != "ipsec-main" || group.Provider != ipsec.ProviderStrongSwan {
		t.Fatalf("group identity = %+v", group)
	}
	if group.NetNS.Kind != ipsec.NetNSName || group.NetNS.Name != "photontesth2" || !group.NetNS.Create {
		t.Fatalf("group netns = %+v", group.NetNS)
	}
	if group.TunnelAddressPool.String() != "fd00:1234::/64" {
		t.Fatalf("tunnel pool = %s", group.TunnelAddressPool)
	}
	if group.Reconcile.IntervalSeconds != 30 || group.Reconcile.RotateRetentionSeconds != 3600 || group.Reconcile.Backoff.InitialSeconds != 1 || group.Reconcile.Backoff.MaxSeconds != 60 {
		t.Fatalf("reconcile = %+v", group.Reconcile)
	}
	if got := strings.Join(group.AddressSourceOrder, ","); got != "manual-dns,discovery" {
		t.Fatalf("AddressSourceOrder = %q", got)
	}
	if len(group.ConnectRules) != 1 || len(group.DenyRules) != 1 {
		t.Fatalf("rules = connect:%v deny:%v", group.ConnectRules, group.DenyRules)
	}
	if config.IPsec.Role != ipsec.RoleBoth {
		t.Fatalf("IPsec.Role = %q, want default bidirectional", config.IPsec.Role)
	}
}

func TestParseConfigYAMLOverlayDirectionDeprecated(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    direction: outbound
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("expected error for deprecated overlays[].direction")
	}
}

func TestParseConfigYAMLOverlayUsesDefaultNetNSReference(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
overlays:
  - name: ipsec-main
    provider: strongswan
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	group := config.IPsec.LinkGroups[0]
	if group.NetNS.Kind != ipsec.NetNSName || group.NetNS.Name != "photontesth2" || !group.NetNS.Create {
		t.Fatalf("group netns = %+v, want netns.default photontesth2", group.NetNS)
	}
}

func TestParseConfigYAMLOverlayAcceptsLegacyInlineNetNS(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    netns:
      kind: name
      name: legacytesth2
      create: true
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	group := config.IPsec.LinkGroups[0]
	if group.NetNS.Kind != ipsec.NetNSName || group.NetNS.Name != "legacytesth2" || !group.NetNS.Create {
		t.Fatalf("group netns = %+v, want inline legacytesth2", group.NetNS)
	}
}

func TestParseConfigYAMLOverlayRejectsUnknownNetNSReference(t *testing.T) {
	config := defaultAppConfig()
	input := `
netns:
  default:
    kind: name
    name: photontesth2
    create: true
overlays:
  - name: ipsec-main
    provider: strongswan
    netns: missing
`
	err := parseConfigYAML(input, config)
	if err == nil {
		t.Fatal("expected unknown overlay netns reference error")
	}
	if !strings.Contains(err.Error(), `unknown netns "missing"`) {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseConfigYAMLRejectsInvalidOverlay(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: broken
    provider: strongswan
    tunnel_address_pool: not-a-prefix
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject invalid overlay tunnel pool")
	}
}

func TestParseConfigYAMLRejectsInvalidOverlayRule(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    connect:
      - "strongswan://*.catofes.?source=magic"
`
	if err := parseConfigYAML(input, config); err == nil {
		t.Fatalf("parseConfigYAML should reject invalid overlay rule")
	}
}
