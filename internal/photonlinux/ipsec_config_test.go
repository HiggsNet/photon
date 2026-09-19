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
		raw       TunnelAddressConfigYAML
		want      ipsec.TunnelAddressSpec
		wantError string
	}{
		{name: "derived pool", raw: TunnelAddressConfigYAML{Mode: "derived-pool", Family: "ipv4", Pool: "10.44.0.0/24"}, want: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedPool, Family: ipsec.FamilyIPv4, Pool: netip.MustParsePrefix("10.44.0.0/24")}},
		{name: "invalid mode", raw: TunnelAddressConfigYAML{Mode: "magic"}, wantError: "invalid tunnel_address.mode"},
		{name: "invalid family", raw: TunnelAddressConfigYAML{Family: "ipx"}, wantError: "invalid tunnel_address.family"},
		{name: "mismatched pool", raw: TunnelAddressConfigYAML{Mode: "derived-pool", Family: "ipv4", Pool: "fd00:1234::/64"}, wantError: "does not match pool"},
		{name: "missing pool", raw: TunnelAddressConfigYAML{Mode: "derived-pool"}, wantError: "requires a pool"},
		{name: "inferred family", raw: TunnelAddressConfigYAML{Mode: " DERIVED-POOL ", Pool: "10.44.0.0/24"}, want: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedPool, Family: ipsec.FamilyIPv4, Pool: netip.MustParsePrefix("10.44.0.0/24")}},
		{name: "ipv4 default", raw: TunnelAddressConfigYAML{Family: "ipv4"}, want: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDisabled, Family: ipsec.FamilyIPv4}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := tc.raw.Parse()
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
