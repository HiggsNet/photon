package main

import (
	"context"
	"net/netip"
	"testing"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDiagnosticAddressForPrefixUsesReservedSuffix(t *testing.T) {
	prefix := netip.MustParsePrefix("fd00:1234:5678:9abc::/64")
	addr, ok := photonlinux.DiagnosticAddressForPrefix(prefix, 0xfff4)
	if !ok {
		t.Fatal("diagnosticAddressForPrefix returned ok=false")
	}
	if got := addr.String(); got != "fd00:1234:5678:9abc::fff4" {
		t.Fatalf("diagnostic address = %s, want fd00:1234:5678:9abc::fff4", got)
	}
}

func TestDiagnosticAddressForPrefixRejectsNonNodePrefix(t *testing.T) {
	for _, raw := range []string{"fd00:1234::/80", "10.0.0.0/24"} {
		if addr, ok := photonlinux.DiagnosticAddressForPrefix(netip.MustParsePrefix(raw), 0xfff4); ok {
			t.Fatalf("diagnosticAddressForPrefix(%s) = %s, want rejected", raw, addr)
		}
	}
}

func TestIPsecDiagnosticSuffixFromPathKeyOrLocalAddress(t *testing.T) {
	tests := []struct {
		name string
		spec ipsec.TransportLinkSpec
		want uint16
	}{
		{
			name: "family ipv4 path",
			spec: ipsec.TransportLinkSpec{PathKey: "family:ipv4"},
			want: 0xfff4,
		},
		{
			name: "family ipv6 path",
			spec: ipsec.TransportLinkSpec{PathKey: "family:ipv6"},
			want: 0xfff6,
		},
		{
			name: "ipv4 local address fallback",
			spec: ipsec.TransportLinkSpec{LocalAddress: "192.0.2.10"},
			want: 0xfff4,
		},
		{
			name: "ipv6 local address fallback",
			spec: ipsec.TransportLinkSpec{LocalAddress: "2001:db8::10"},
			want: 0xfff6,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, ok := photonlinux.IPsecDiagnosticSuffix(tt.spec)
			if !ok || got != tt.want {
				t.Fatalf("ipsecDiagnosticSuffix = %#x/%v, want %#x/true", got, ok, tt.want)
			}
		})
	}
}

func TestAssignIPsecDiagnosticAddressesAllowsSameFamilyAddressOnMultipleInterfaces(t *testing.T) {
	driver := &ipsec.DryRunDriver{}
	platformDriver := newTestLinuxDriver(driver, driver)
	prefixes := []netip.Prefix{netip.MustParsePrefix("fd00:1234:5678:9abc::/64")}

	specs := []ipsec.TransportLinkSpec{
		{InterfaceName: "phx4a", PathKey: "family:ipv4"},
		{InterfaceName: "phx4b", PathKey: "family:ipv4"},
		{InterfaceName: "phx6a", PathKey: "family:ipv6"},
	}
	for _, spec := range specs {
		if err := platformDriver.AssignDiagnosticAddresses(context.Background(), spec, prefixes); err != nil {
			t.Fatalf("assignIPsecDiagnosticAddresses(%s): %v", spec.InterfaceName, err)
		}
	}

	want := []string{
		"phx4a=fd00:1234:5678:9abc::fff4/128",
		"phx4b=fd00:1234:5678:9abc::fff4/128",
		"phx6a=fd00:1234:5678:9abc::fff6/128",
	}
	if len(driver.Addresses) != len(want) {
		t.Fatalf("addresses = %+v, want %+v", driver.Addresses, want)
	}
	for i := range want {
		if driver.Addresses[i] != want[i] {
			t.Fatalf("addresses = %+v, want %+v", driver.Addresses, want)
		}
	}
}
