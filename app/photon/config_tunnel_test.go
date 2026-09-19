package main

import (
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"testing"
)

func TestParseConfigYAMLTunnelAddressBlock(t *testing.T) {
	config := defaultAppConfig()
	input := `
overlays:
  - name: ipsec-main
    provider: strongswan
    tunnel_address:
      mode: derived-link-local
      family: ipv6
`
	if err := parseConfigYAML(input, config); err != nil {
		t.Fatalf("parseConfigYAML: %v", err)
	}
	normalizeAppConfig(config)
	if len(config.IPsec.LinkGroups) != 1 {
		t.Fatalf("LinkGroups len = %d, want 1", len(config.IPsec.LinkGroups))
	}
	group := config.IPsec.LinkGroups[0]
	if group.TunnelAddressSpec.Mode != ipsec.TunnelAddressDerivedLinkLocal || group.TunnelAddressSpec.Family != ipsec.FamilyIPv6 {
		t.Fatalf("tunnel address spec = %+v", group.TunnelAddressSpec)
	}
}
