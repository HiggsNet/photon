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
