package photonlinux

import (
	"net/netip"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestTunnelAddressConfig(t *testing.T) {
	for _, tc := range []struct {
		name      string
		raw       tunnelAddressConfigYAML
		want      ipsec.TunnelAddressSpec
		wantError string
	}{
		{name: "derived pool", raw: tunnelAddressConfigYAML{Mode: "derived-pool", Family: "ipv4", Pool: "10.44.0.0/24"}, want: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedPool, Family: ipsec.FamilyIPv4, Pool: netip.MustParsePrefix("10.44.0.0/24")}},
		{name: "invalid mode", raw: tunnelAddressConfigYAML{Mode: "magic"}, wantError: "invalid tunnel_address.mode"},
		{name: "invalid family", raw: tunnelAddressConfigYAML{Family: "ipx"}, wantError: "invalid tunnel_address.family"},
		{name: "mismatched pool", raw: tunnelAddressConfigYAML{Mode: "derived-pool", Family: "ipv4", Pool: "fd00:1234::/64"}, wantError: "does not match pool"},
		{name: "missing pool", raw: tunnelAddressConfigYAML{Mode: "derived-pool"}, wantError: "requires a pool"},
		{name: "inferred family", raw: tunnelAddressConfigYAML{Mode: " DERIVED-POOL ", Pool: "10.44.0.0/24"}, want: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedPool, Family: ipsec.FamilyIPv4, Pool: netip.MustParsePrefix("10.44.0.0/24")}},
		{name: "ipv4 default", raw: tunnelAddressConfigYAML{Family: "ipv4"}, want: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDisabled, Family: ipsec.FamilyIPv4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.raw.parse()
			if tc.wantError != "" {
				if err == nil || !strings.Contains(err.Error(), tc.wantError) {
					t.Fatalf("Parse() = %v, want %q", err, tc.wantError)
				}
			} else if err != nil || got != tc.want {
				t.Fatalf("Parse() = %+v, %v; want %+v", got, err, tc.want)
			}
		})
	}
}

func TestIPsecConfigRejectsInvalidOptions(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  IPsecConfigYAML
		want string
	}{
		{"driver", IPsecConfigYAML{Driver: "magic"}, "invalid ipsec.driver"},
		{"role", IPsecConfigYAML{Role: "invalid"}, "invalid ipsec.role"},
		{"deprecated accept", IPsecConfigYAML{DeprecatedAccept: "inbound"}, "ipsec.accept is deprecated"},
		{"port mode", IPsecConfigYAML{PortMode: "dynamic"}, "invalid ipsec.port_mode"},
		{"port range", IPsecConfigYAML{PortMode: "range", PortRange: ipsec.PortRange{From: 40000, To: 30000}}, "invalid ipsec.port_range"},
		{"port pairs", IPsecConfigYAML{PortMode: "range", PortRange: ipsec.PortRange{From: 30000, To: 30002}}, "two IKE/NAT-T port pairs"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			config := DefaultIPsecConfig()
			if err := tc.raw.Apply(&config); err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("Apply() = %v, want %q", err, tc.want)
			}
		})
	}
}
