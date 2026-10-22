package ipsec

import (
	"net/netip"
	"slices"
	"testing"
)

func TestLinkLocalControlAddressesPermitDualStackBusinessSelectors(t *testing.T) {
	for _, tc := range []struct {
		name, local, peer string
		want              []string
	}{
		{"derived IPv6 link local", "fe80::1", "fe80::2", []string{"0.0.0.0/0", "::/0"}},
		{"IPv4 link local", "169.254.1.1", "169.254.1.2", []string{"0.0.0.0/0", "::/0"}},
		{"legacy IPv4 tunnel", "10.0.0.1", "10.0.0.2", []string{"0.0.0.0/0"}},
		{"legacy IPv6 tunnel", "fd00::1", "fd00::2", []string{"::/0"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spec := TransportLinkSpec{TransportID: "selector-test", LocalZone: "node-a.catofes.", PeerZone: "node-b.catofes.", XFRMIfID: 524250, LocalTunnelAddr: netip.MustParseAddr(tc.local), PeerTunnelAddr: netip.MustParseAddr(tc.peer)}
			msg, err := BuildStrongSwanConnection(spec)
			if err != nil {
				t.Fatal(err)
			}
			conn := msg
			child := conn["children"].(map[string]any)[ChildSAName(spec)].(map[string]any)
			for _, key := range []string{"local_ts", "remote_ts"} {
				if got := child[key].([]string); !slices.Equal(got, tc.want) {
					t.Fatalf("%s=%v want %v", key, got, tc.want)
				}
			}
			if child["if_id_in"] != "524250" || child["if_id_out"] != "524250" || child["start_action"] != "none" {
				t.Fatal("lost XFRM/passive ownership", child)
			}
		})
	}
}
