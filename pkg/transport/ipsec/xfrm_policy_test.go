package ipsec

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

func TestNormalizeXFRMBackend(t *testing.T) {
	cases := []struct {
		value string
		want  XFRMBackend
	}{
		{"", XFRMBackendInterface},
		{"interface", XFRMBackendInterface},
		{"policy", XFRMBackendPolicy},
		{" POLICY ", XFRMBackendPolicy},
	}
	for _, tc := range cases {
		got, err := NormalizeXFRMBackend(tc.value)
		if err != nil {
			t.Fatalf("NormalizeXFRMBackend(%q): %v", tc.value, err)
		}
		if got != tc.want {
			t.Fatalf("NormalizeXFRMBackend(%q) = %q, want %q", tc.value, got, tc.want)
		}
	}
	if _, err := NormalizeXFRMBackend("vti"); err == nil {
		t.Fatalf("NormalizeXFRMBackend(vti) expected error")
	}
	if _, err := NormalizeXFRMBackend("ranet"); err == nil {
		t.Fatalf("NormalizeXFRMBackend(ranet) expected error")
	}
}

func TestParseRouteDev(t *testing.T) {
	cases := []struct {
		out  string
		want string
	}{
		{"10.60.0.0/16 via 172.20.0.1 dev eth0 src 172.20.0.5", "eth0"},
		{"default dev eth0 scope link", "eth0"},
		{"default via 172.20.0.1 dev eth0", "eth0"},
		{"unreachable", ""},
	}
	for _, tc := range cases {
		if got := parseRouteDev(tc.out); got != tc.want {
			t.Fatalf("parseRouteDev(%q) = %q, want %q", tc.out, got, tc.want)
		}
	}
}

func TestPolicyChildSAOmitsIfID(t *testing.T) {
	spec := TransportLinkSpec{
		TransportID:     "ipsec-abc",
		LocalZone:       "a.zone",
		PeerZone:        "b.zone",
		XFRMIfID:        42,
		ContactPoints:   []ContactPoint{{Address: "203.0.113.10", NATTPort: 4500}},
		InitiatorRole:   InitiatorRolePrimary,
		InterfaceName:   "lo",
		LocalTunnelAddr: netip.MustParseAddr("10.99.0.1"),
		PeerTunnelAddr:  netip.MustParseAddr("10.99.0.2"),
	}

	driver := &StrongSwanDriver{XFRMBackend: XFRMBackendPolicy}
	msg, err := driver.buildLoadConnMessage(spec)
	if err != nil {
		t.Fatalf("buildLoadConnMessage: %v", err)
	}
	child := msg[spec.TransportID].(map[string]any)["children"].(map[string]any)[ChildSAName(spec)].(map[string]any)
	if _, ok := child["if_id_in"]; ok {
		t.Fatalf("policy child must not carry if_id_in: %#v", child)
	}
	if _, ok := child["if_id_out"]; ok {
		t.Fatalf("policy child must not carry if_id_out: %#v", child)
	}
	if _, ok := child["mark_out"]; ok {
		t.Fatalf("policy child must not carry marks: %#v", child)
	}

	defaultDriver := &StrongSwanDriver{}
	msg, err = defaultDriver.buildLoadConnMessage(spec)
	if err != nil {
		t.Fatalf("default buildLoadConnMessage: %v", err)
	}
	child = msg[spec.TransportID].(map[string]any)["children"].(map[string]any)[ChildSAName(spec)].(map[string]any)
	if child["if_id_in"] != "42" || child["if_id_out"] != "42" {
		t.Fatalf("default child if_id = %v/%v, want 42/42", child["if_id_in"], child["if_id_out"])
	}
}

func TestPolicyEnsureInterfaceInstallsUnderlayRouteWithoutCreatingDevice(t *testing.T) {
	var commands []recordedCommand
	driver := SystemXFRMDriver{
		Backend:      XFRMBackendPolicy,
		DefaultNetNS: NetNSSpec{Kind: NetNSHost},
		IPPath:       "ip",
		SysctlPath:   "sysctl",
		TruePath:     "true",
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, recordedCommand{name: name, args: append([]string(nil), args...)})
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "route get 203.0.113.10"):
				return []byte("203.0.113.10 via 172.20.0.1 dev eth0 src 172.20.0.5\n"), nil
			case strings.HasPrefix(joined, "-w net."):
				return []byte("1\n"), nil
			default:
				return nil, nil
			}
		},
	}
	spec := TransportLinkSpec{
		LinkID:          "link-policy",
		InterfaceName:   "phx2a",
		XFRMIfID:        42,
		LocalTunnelAddr: netip.MustParseAddr("10.99.0.1"),
		PeerTunnelAddr:  netip.MustParseAddr("10.99.0.2"),
		ContactPoints:   []ContactPoint{{Address: "203.0.113.10"}},
	}
	if err := driver.EnsureInterface(context.Background(), spec); err != nil {
		t.Fatalf("EnsureInterface: %v", err)
	}
	got := commandStrings(commands)
	for _, cmd := range got {
		if strings.Contains(cmd, "link add") {
			t.Fatalf("policy EnsureInterface created a device: %v", got)
		}
	}
	wantRoute := "ip -4 route replace 10.99.0.2/32 dev eth0 src 10.99.0.1"
	found := false
	for _, cmd := range got {
		if cmd == wantRoute {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("missing underlay peer route %q in %v", wantRoute, got)
	}
}

func TestPolicyEnsureInterfaceReturnsRouteReplaceError(t *testing.T) {
	driver := SystemXFRMDriver{
		Backend:      XFRMBackendPolicy,
		DefaultNetNS: NetNSSpec{Kind: NetNSHost},
		IPPath:       "ip",
		SysctlPath:   "sysctl",
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "route get") {
				return []byte("203.0.113.10 dev eth0\n"), nil
			}
			if strings.Contains(joined, "route replace") {
				return []byte("RTNETLINK answers: No such device\n"), errors.New("exit status 2")
			}
			return nil, nil
		},
	}
	spec := TransportLinkSpec{
		LinkID:          "link-policy",
		InterfaceName:   "phx2a",
		XFRMIfID:        42,
		LocalTunnelAddr: netip.MustParseAddr("10.99.0.1"),
		PeerTunnelAddr:  netip.MustParseAddr("10.99.0.2"),
		ContactPoints:   []ContactPoint{{Address: "203.0.113.10"}},
	}
	if err := driver.EnsureInterface(context.Background(), spec); err == nil {
		t.Fatal("EnsureInterface should surface route replace failure")
	}
}

func TestPolicyAssignAddressAccumulatesOnLoopback(t *testing.T) {
	var commands []recordedCommand
	driver := SystemXFRMDriver{
		Backend:      XFRMBackendPolicy,
		DefaultNetNS: NetNSSpec{Kind: NetNSHost},
		IPPath:       "ip",
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, recordedCommand{name: name, args: append([]string(nil), args...)})
			return nil, nil
		},
	}
	spec := TransportLinkSpec{InterfaceName: "phx2a", XFRMIfID: 42}
	if err := driver.AssignAddress(context.Background(), spec, "10.99.0.1/32"); err != nil {
		t.Fatalf("AssignAddress: %v", err)
	}
	got := commandStrings(commands)
	for _, cmd := range got {
		if strings.Contains(cmd, "addr del") {
			t.Fatalf("policy AssignAddress pruned sibling addresses: %v", got)
		}
		if strings.Contains(cmd, "dev phx2a") {
			t.Fatalf("policy AssignAddress used resource name as device: %v", got)
		}
	}
	want := "ip addr replace 10.99.0.1/32 dev lo"
	found := false
	for _, cmd := range got {
		if cmd == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("missing lo assignment %q in %v", want, got)
	}
}

func TestPolicyDeleteInterfaceDoesNotDeleteLoopbackOrResourceName(t *testing.T) {
	var commands []recordedCommand
	driver := SystemXFRMDriver{
		Backend:      XFRMBackendPolicy,
		DefaultNetNS: NetNSSpec{Kind: NetNSHost},
		IPPath:       "ip",
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, recordedCommand{name: name, args: append([]string(nil), args...)})
			return nil, nil
		},
	}
	if err := driver.DeleteInterface(context.Background(), "phx2a"); err != nil {
		t.Fatalf("DeleteInterface: %v", err)
	}
	if err := driver.DeleteInterface(context.Background(), "lo"); err != nil {
		t.Fatalf("DeleteInterface(lo): %v", err)
	}
	for _, cmd := range commandStrings(commands) {
		if strings.Contains(cmd, "link delete") {
			t.Fatalf("policy DeleteInterface issued link delete: %v", commandStrings(commands))
		}
	}
}

func TestPolicyInspectLinkObservesLoopbackAttachment(t *testing.T) {
	driver := SystemXFRMDriver{
		Backend:      XFRMBackendPolicy,
		DefaultNetNS: NetNSSpec{Kind: NetNSHost},
		IPPath:       "ip",
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			joined := strings.Join(args, " ")
			switch {
			case strings.Contains(joined, "link show dev lo"):
				return []byte("1: lo: <LOOPBACK,UP,LOWER_UP> mtu 65536\n"), nil
			case strings.Contains(joined, "link show dev phx2a"):
				return nil, errors.New("Device does not exist")
			case strings.Contains(joined, "-4 -o addr show dev lo"):
				return []byte("inet 127.0.0.1/8 scope host lo\ninet 10.99.0.1/32 scope global lo\n"), nil
			case strings.Contains(joined, "-6 -o addr show dev lo"):
				return []byte("inet6 ::1/128 scope host\n"), nil
			default:
				return nil, fmt.Errorf("unexpected command: %s %s", name, joined)
			}
		},
	}
	spec := TransportLinkSpec{
		InterfaceName:   "phx2a",
		XFRMIfID:        42,
		LocalTunnelAddr: netip.MustParseAddr("10.99.0.1"),
	}
	state, err := driver.InspectLink(context.Background(), spec)
	if err != nil {
		t.Fatalf("InspectLink: %v", err)
	}
	if !state.InterfaceExists || !state.InterfaceUp {
		t.Fatalf("state = %+v, want lo present and up", state)
	}
	if !driver.linkStateMatchesSpec(state, spec) {
		t.Fatalf("policy attachment should match without MULTICAST: %+v", state)
	}
}

func TestPolicyEnsureInterfaceInstallsIPv6UnderlayRoute(t *testing.T) {
	var commands []recordedCommand
	driver := SystemXFRMDriver{
		Backend:      XFRMBackendPolicy,
		DefaultNetNS: NetNSSpec{Kind: NetNSHost},
		IPPath:       "ip",
		SysctlPath:   "sysctl",
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, recordedCommand{name: name, args: append([]string(nil), args...)})
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "route get 2001:db8::10") {
				return []byte("2001:db8::10 from :: dev eth0\n"), nil
			}
			return nil, nil
		},
	}
	spec := TransportLinkSpec{
		LinkID:          "link-policy6",
		InterfaceName:   "phx2a",
		XFRMIfID:        42,
		LocalTunnelAddr: netip.MustParseAddr("fd00:99::1"),
		PeerTunnelAddr:  netip.MustParseAddr("fd00:99::2"),
		ContactPoints:   []ContactPoint{{Address: "2001:db8::10"}},
	}
	if err := driver.EnsureInterface(context.Background(), spec); err != nil {
		t.Fatalf("EnsureInterface: %v", err)
	}
	got := commandStrings(commands)
	wantGet := "ip -6 route get 2001:db8::10"
	wantReplace := "ip -6 route replace fd00:99::2/128 dev eth0 src fd00:99::1"
	hasGet, hasReplace := false, false
	for _, cmd := range got {
		if cmd == wantGet {
			hasGet = true
		}
		if cmd == wantReplace {
			hasReplace = true
		}
		if strings.Contains(cmd, "-4 route") {
			t.Fatalf("IPv6 policy route used IPv4 ip route: %v", got)
		}
	}
	if !hasGet || !hasReplace {
		t.Fatalf("IPv6 policy route missing get/replace (get=%v replace=%v) in %v", hasGet, hasReplace, got)
	}
}

func TestPolicyEnsureObservedInterfacesReinstallsPeerRoute(t *testing.T) {
	var commands []recordedCommand
	driver := SystemXFRMDriver{
		Backend:      XFRMBackendPolicy,
		DefaultNetNS: NetNSSpec{Kind: NetNSHost},
		IPPath:       "ip",
		SysctlPath:   "sysctl",
		Command: func(_ context.Context, name string, args ...string) ([]byte, error) {
			commands = append(commands, recordedCommand{name: name, args: append([]string(nil), args...)})
			joined := strings.Join(args, " ")
			if strings.Contains(joined, "route get") {
				return []byte("203.0.113.10 dev eth0\n"), nil
			}
			return nil, nil
		},
	}
	spec := TransportLinkSpec{
		LinkID:          "link-policy",
		InterfaceName:   "phx2a",
		XFRMIfID:        42,
		LocalTunnelAddr: netip.MustParseAddr("10.99.0.1"),
		PeerTunnelAddr:  netip.MustParseAddr("10.99.0.2"),
		ContactPoints:   []ContactPoint{{Address: "203.0.113.10"}},
	}
	state := XFRMLinkState{
		NetNS:                    NetNSSpec{Kind: NetNSHost},
		NamespaceExists:          true,
		InterfaceExists:          true,
		FlagsKnown:               true,
		InterfaceUp:              true,
		SharedAttachment:         true,
		NamespaceForwardingKnown: true,
		NamespaceForwarding:      true,
		Addresses:                []netip.Prefix{netip.MustParsePrefix("10.99.0.1/32")},
	}
	if err := driver.EnsureObservedInterfaces(context.Background(), []XFRMObservedInterface{{Spec: spec, State: state}}); err != nil {
		t.Fatalf("EnsureObservedInterfaces: %v", err)
	}
	wantRoute := "ip -4 route replace 10.99.0.2/32 dev eth0 src 10.99.0.1"
	found := false
	for _, cmd := range commandStrings(commands) {
		if cmd == wantRoute {
			found = true
		}
		if strings.Contains(cmd, "link add") || strings.Contains(cmd, "multicast") {
			t.Fatalf("shared ensure mutated the loopback device: %v", commandStrings(commands))
		}
	}
	if !found {
		t.Fatalf("shared EnsureObservedInterfaces must reinstall peer route, commands=%v", commandStrings(commands))
	}
}
