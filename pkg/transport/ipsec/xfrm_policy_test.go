package ipsec

import (
	"net/netip"
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
