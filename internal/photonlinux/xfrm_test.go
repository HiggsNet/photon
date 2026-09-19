package photonlinux

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDiagnosticAddressForPrefixUsesReservedSuffix(t *testing.T) {
	prefix := netip.MustParsePrefix("fd00:1234:5678:9abc::/64")
	addr, ok := diagnosticAddressForPrefix(prefix, 0xfff4)
	if !ok {
		t.Fatal("diagnosticAddressForPrefix returned ok=false")
	}
	if got := addr.String(); got != "fd00:1234:5678:9abc::fff4" {
		t.Fatalf("diagnostic address = %s, want fd00:1234:5678:9abc::fff4", got)
	}
}

func TestDiagnosticAddressForPrefixRejectsNonNodePrefix(t *testing.T) {
	for _, raw := range []string{"fd00:1234::/80", "10.0.0.0/24"} {
		if addr, ok := diagnosticAddressForPrefix(netip.MustParsePrefix(raw), 0xfff4); ok {
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
			got, ok := ipsecDiagnosticSuffix(tt.spec)
			if !ok || got != tt.want {
				t.Fatalf("ipsecDiagnosticSuffix = %#x/%v, want %#x/true", got, ok, tt.want)
			}
		})
	}
}

func TestAssignIPsecDiagnosticAddressesAllowsSameFamilyAddressOnMultipleInterfaces(t *testing.T) {
	driver := &ipsec.DryRunDriver{}
	platformDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})
	prefixes := []netip.Prefix{netip.MustParsePrefix("fd00:1234:5678:9abc::/64")}

	specs := []ipsec.TransportLinkSpec{
		{InterfaceName: "phx4a", PathKey: "family:ipv4"},
		{InterfaceName: "phx4b", PathKey: "family:ipv4"},
		{InterfaceName: "phx6a", PathKey: "family:ipv6"},
	}
	for _, spec := range specs {
		if err := platformDriver.assignDiagnosticAddresses(context.Background(), spec, prefixes, nil); err != nil {
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

type diagnosticActionDriver struct {
	ipsec.DryRunDriver
	interfaceErr, addressErr error
	interfaceReady           bool
	addressCalls             int
}

func (d *diagnosticActionDriver) EnsureInterface(context.Context, ipsec.TransportLinkSpec) error {
	d.interfaceReady = d.interfaceErr == nil
	return d.interfaceErr
}

func (d *diagnosticActionDriver) AssignExtraAddress(context.Context, ipsec.TransportLinkSpec, string) error {
	d.addressCalls++
	if !d.interfaceReady {
		return errors.New("diagnostic address assigned before interface")
	}
	return d.addressErr
}

func TestIPsecActionIncludesDiagnosticAddressFailure(t *testing.T) {
	failure := errors.New("injected failure")
	for _, tc := range []struct {
		name                     string
		interfaceErr, addressErr error
		calls                    int
	}{
		{"success", nil, nil, 1},
		{"interface failure", failure, nil, 0},
		{"address failure", nil, failure, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			driver := &diagnosticActionDriver{interfaceErr: tc.interfaceErr, addressErr: tc.addressErr}
			platform := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})
			t.Cleanup(func() { _ = platform.Close() })
			spec := ipsec.TransportLinkSpec{TransportID: "ipsec-main", InterfaceName: "phx4", PathKey: "family:ipv4"}
			_, err := platform.ApplyIPsecAction(context.Background(), ipsec.ReconcileAction{Action: ipsec.ReconcileActionCreate, Spec: &spec}, ipsec.NetNSSpec{}, []netip.Prefix{netip.MustParsePrefix("fd00:1234::/64")})
			wantFailure := tc.interfaceErr != nil || tc.addressErr != nil
			if (err != nil) != wantFailure || wantFailure && !errors.Is(err, failure) || driver.addressCalls != tc.calls {
				t.Fatalf("apply error=%v, address calls=%d; want failure=%v, calls=%d", err, driver.addressCalls, wantFailure, tc.calls)
			}
		})
	}
}

func TestXFRMLinkStateMatchesCandidateRequiresLocalTunnelAddress(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		InterfaceName:   "phx1",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1234"),
	}
	state := ipsec.XFRMLinkState{
		NamespaceExists: true,
		InterfaceExists: true,
		Addresses:       []netip.Prefix{netip.MustParsePrefix("fe80::9999/64")},
	}
	if matches, _ := XFRMLinkStateMatchReason(state, spec); matches {
		t.Fatalf("candidate matched with wrong interface address")
	}
	state.Addresses = []netip.Prefix{netip.MustParsePrefix("fe80::1234/64")}
	if matches, _ := XFRMLinkStateMatchReason(state, spec); !matches {
		t.Fatalf("candidate did not match expected interface address")
	}
}

func TestXFRMLinkStateMatchesCandidateRequiresKnownInterfaceFlags(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		InterfaceName:   "phx1",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1234"),
	}
	state := ipsec.XFRMLinkState{
		NamespaceExists: true,
		InterfaceExists: true,
		FlagsKnown:      true,
		InterfaceUp:     true,
		Multicast:       false,
		Addresses:       []netip.Prefix{netip.MustParsePrefix("fe80::1234/64")},
	}
	if matches, _ := XFRMLinkStateMatchReason(state, spec); matches {
		t.Fatalf("candidate matched without multicast enabled")
	}
	state.Multicast = true
	if matches, _ := XFRMLinkStateMatchReason(state, spec); !matches {
		t.Fatalf("candidate did not match with expected flags and address")
	}
	state.InterfaceUp = false
	if matches, _ := XFRMLinkStateMatchReason(state, spec); matches {
		t.Fatalf("candidate matched while interface was not up")
	}
}
