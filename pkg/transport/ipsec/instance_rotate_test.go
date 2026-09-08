package ipsec

import (
	"testing"
	"time"
)

func TestRotateConnectionNameStable(t *testing.T) {
	base := "ipsec-deadbeef"
	if got := RotateConnectionName(base, 3); got != "ipsec-deadbeef-r3" {
		t.Fatalf("RotateConnectionName = %q", got)
	}
	if got := RotateChildSAName(base, 3); got != "ipsec-deadbeef-r3-child" {
		t.Fatalf("RotateChildSAName = %q", got)
	}
}

func TestRotateSpecUsesIndependentXFRMInterface(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		TransportID:   "ipsec-main-ab",
		InterfaceName: "phx1",
		XFRMIfID:      77,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	staged := mustRuntimeSpecForPortGeneration(spec, 2)
	if staged.TransportID != RotateConnectionName(spec.TransportID, 2) {
		t.Fatalf("staged transport id = %q", staged.TransportID)
	}
	if staged.XFRMIfID == 0 || staged.XFRMIfID == spec.XFRMIfID {
		t.Fatalf("staged if_id = %d, want independent from %d", staged.XFRMIfID, spec.XFRMIfID)
	}
	if staged.InterfaceName == "" || staged.InterfaceName == spec.InterfaceName {
		t.Fatalf("staged interface = %q, want independent from %q", staged.InterfaceName, spec.InterfaceName)
	}
}

func TestTransportLinkSpecHashIgnoresRuntimeQuality(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		TransportID:   "ipsec-main-ab",
		InterfaceName: "phx1",
		XFRMIfID:      77,
		ContactPoints: []ContactPoint{{
			Address:      "198.51.100.20",
			Family:       FamilyIPv4,
			Generation:   2,
			IKEPort:      DefaultIKEPort,
			NATTPort:     DefaultNATTPort,
			Successes:    5,
			Failures:     2,
			BackoffUntil: now.Add(time.Minute),
			LastError:    "timeout",
			RankReason:   "recent success",
		}},
	}
	base := TransportLinkSpecHash(spec)

	spec.ContactPoints[0].Successes = 10
	spec.ContactPoints[0].Failures = 0
	spec.ContactPoints[0].BackoffUntil = now.Add(2 * time.Minute)
	spec.ContactPoints[0].LastError = ""
	spec.ContactPoints[0].RankReason = "best"
	if got := TransportLinkSpecHash(spec); got != base {
		t.Fatalf("hash changed after quality updates: %q != %q", got, base)
	}

	spec.ContactPoints[0].Address = "198.51.100.21"
	if got := TransportLinkSpecHash(spec); got == base {
		t.Fatalf("hash unchanged after address change")
	}
}

func TestRotateSpecForSecondaryStandbyUsesInboundTrap(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:     "node-b.catofes.",
		PeerZone:      "node-a.catofes.",
		InitiatorRole: InitiatorRolePrimary,
		TransportID:   "ipsec-main-ba",
		InterfaceName: "phx1",
		XFRMIfID:      77,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.10",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}

	staged := rotateSpecForRole(spec, 2, InitiatorRoleSecondaryStandby)
	if len(staged.ContactPoints) != 0 {
		t.Fatalf("standby staged contacts = %+v, want responder-only config", staged.ContactPoints)
	}

	active := rotateSpecForRole(spec, 2, InitiatorRolePrimary)
	if len(active.ContactPoints) != 1 {
		t.Fatalf("active staged contacts = %+v, want preserved contact point", active.ContactPoints)
	}
}
