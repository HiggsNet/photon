package photonlinux

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"gopkg.in/yaml.v3"
)

func parseOverlayYAML(input string) ([]ipsec.LinkGroupSpec, error) {
	var file struct {
		Overlays []OverlayConfigYAML `yaml:"overlays"`
	}
	decoder := yaml.NewDecoder(strings.NewReader(input))
	decoder.KnownFields(true)
	if err := decoder.Decode(&file); err != nil {
		return nil, err
	}
	return ParseOverlayConfigs(file.Overlays, NetNSConfig{}, ipsec.NetNSSpec{})
}

func TestOverlayPeerOverrides(t *testing.T) {
	const prefix = "overlays:\n  - id: ipsec-main\n    peer_overrides:\n"
	groups, err := parseOverlayYAML(prefix + `      - peer: edge.example.
        role: out
        endpoints:
          ipv4: {address: 192.0.2.40, natt_port: 44500}
          ipv6: {address: "2001:db8::40"}
`)
	if err != nil {
		t.Fatal(err)
	}
	override := groups[0].PeerOverrides[0]
	ipv4, ipv6 := override.Endpoints[ipsec.FamilyIPv4], override.Endpoints[ipsec.FamilyIPv6]
	if override.Peer != "edge.example." || override.Role != ipsec.RoleOut ||
		ipv4.Address != netip.MustParseAddr("192.0.2.40") || ipv4.NATTPort == nil || *ipv4.NATTPort != 44500 ||
		ipv6.Address != netip.MustParseAddr("2001:db8::40") || ipv6.NATTPort != nil {
		t.Fatalf("unexpected peer override: %+v", override)
	}
	groups, err = parseOverlayYAML(prefix + "      - {peer: edge.example., mtu: 1420, mtu_by_family: {ipv4: 1400}}\n")
	if err != nil {
		t.Fatal(err)
	}
	override = groups[0].PeerOverrides[0]
	if override.MTU == nil || *override.MTU != 1420 || override.MTUByFamily[ipsec.FamilyIPv4] != 1400 {
		t.Fatalf("unexpected MTU override: %+v", override)
	}
	for _, input := range []string{
		"      - {peer: '*.example.', role: out}\n",
		"      - {peer: edge.example, role: out}\n",
		"      - {peer: edge.example., role: server}\n",
		"      - {peer: edge.example.}\n",
		"      - {peer: edge.example., role: out}\n      - {peer: edge.example., role: in}\n",
		"      - {peer: edge.example., endpoints: {ipv4: {address: '2001:db8::40'}}}\n",
		"      - {peer: edge.example., endpoints: {ipv6: {address: 'fe80::40'}}}\n",
		"      - {peer: edge.example., endpoints: {ipv4: {address: 192.0.2.40, natt_port: 500}}}\n",
		"      - {peer: edge.example., endpoints: {ipv4: {address: 192.0.2.40, natt_port: 0}}}\n",
		"      - {peer: edge.example., mtu: 0}\n",
		"      - {peer: edge.example., mtu: 1279}\n",
		"      - {peer: edge.example., mtu: 65536}\n",
		"      - {peer: edge.example., mtu_by_family: {dual: 1400}}\n",
		"      - {peer: edge.example., mtu_by_family: {ipv6: 0}}\n",
	} {
		if _, err := parseOverlayYAML(prefix + input); err == nil {
			t.Errorf("accepted invalid override %s", input)
		}
	}
}

func TestOverlayConfigOverlayDirectionDeprecated(t *testing.T) {
	input := `
overlays:
  - name: ipsec-main
    direction: outbound
`
	if _, err := parseOverlayYAML(input); err == nil {
		t.Fatalf("expected error for deprecated overlays[].direction")
	}
}

func TestOverlayConfigOverlayAcceptsLegacyInlineNetNS(t *testing.T) {
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    netns:
      kind: name
      name: legacytesth2
      create: true
`
	groups, err := parseOverlayYAML(input)
	if err != nil {
		t.Fatalf("ParseOverlayConfigs: %v", err)
	}
	group := groups[0]
	if group.NetNS.Kind != ipsec.NetNSName || group.NetNS.Name != "legacytesth2" || !group.NetNS.Create {
		t.Fatalf("group netns = %+v, want inline legacytesth2", group.NetNS)
	}
}

func TestOverlayConfigRejectsInvalidOverlay(t *testing.T) {
	input := `
overlays:
  - name: broken
    provider: strongswan
    tunnel_address_pool: not-a-prefix
`
	if _, err := parseOverlayYAML(input); err == nil {
		t.Fatalf("ParseOverlayConfigs should reject invalid overlay tunnel pool")
	}
}

func TestOverlayConfigRejectsInvalidOverlayRule(t *testing.T) {
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    connect:
      - "strongswan://*.catofes.?source=magic"
`
	if _, err := parseOverlayYAML(input); err == nil {
		t.Fatalf("ParseOverlayConfigs should reject invalid overlay rule")
	}
}

func TestOverlayConfigLegacyTunnelAddressPoolStillWorks(t *testing.T) {
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    tunnel_address_pool: fd00:1234::/64
`
	groups, err := parseOverlayYAML(input)
	if err != nil {
		t.Fatalf("ParseOverlayConfigs: %v", err)
	}
	group := groups[0]
	if group.TunnelAddressPool.String() != "fd00:1234::/64" {
		t.Fatalf("legacy pool = %s", group.TunnelAddressPool)
	}
	normalized := group.Normalized()
	if normalized.TunnelAddressSpec.Mode != ipsec.TunnelAddressSequentialPool {
		t.Fatalf("legacy did not map to sequential-pool: %+v", normalized.TunnelAddressSpec)
	}
	if normalized.TunnelAddressSpec.Pool != netip.MustParsePrefix("fd00:1234::/64") {
		t.Fatalf("sequential pool = %s", normalized.TunnelAddressSpec.Pool)
	}
}

func TestOverlayConfigRejectsMixedTunnelAddressConfig(t *testing.T) {
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    tunnel_address_pool: fd00:1234::/64
    tunnel_address:
      mode: derived-link-local
`
	if _, err := parseOverlayYAML(input); err == nil {
		t.Fatalf("ParseOverlayConfigs should reject mixed tunnel address config")
	}
}

func TestOverlayConfigFields(t *testing.T) {
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
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
	groups, err := parseOverlayYAML(input)
	if err != nil {
		t.Fatalf("parseOverlayYAML: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("LinkGroups len = %d, want 1", len(groups))
	}
	group := groups[0]
	if group.ID != "ipsec-main" || group.Name != "ipsec-main" || group.Provider != ipsec.ProviderStrongSwan {
		t.Fatalf("group identity = %+v", group)
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
}

func TestOverlayConfigTunnelAddressBlock(t *testing.T) {
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    tunnel_address:
      mode: derived-link-local
      family: ipv6
`
	groups, err := parseOverlayYAML(input)
	if err != nil {
		t.Fatalf("parseOverlayYAML: %v", err)
	}
	if len(groups) != 1 {
		t.Fatalf("LinkGroups len = %d, want 1", len(groups))
	}
	group := groups[0]
	if group.TunnelAddressSpec.Mode != ipsec.TunnelAddressDerivedLinkLocal || group.TunnelAddressSpec.Family != ipsec.FamilyIPv6 {
		t.Fatalf("tunnel address spec = %+v", group.TunnelAddressSpec)
	}
}
