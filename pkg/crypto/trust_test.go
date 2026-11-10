package crypto

import (
	"crypto/ed25519"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestVerifyPinnedRoot(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{
		Zone: zone.RootZone, Epoch: 1, Threshold: 1,
		Keys: []zone.AuthorizedKey{{Key: pub}},
	})
	if err := VerifyPinnedRoot(ns, pub); err != nil {
		t.Fatalf("VerifyPinnedRoot: %v", err)
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := VerifyPinnedRoot(ns, other); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("wrong-root error = %v", err)
	}
}

func TestPinnedRootRequiresImmutableAuthority(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	other, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*zone.ZoneAuthority)
	}{
		{"legacy capabilities", func(a *zone.ZoneAuthority) {
			a.Keys[0].Capabilities = []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}}
		}},
		{"extra key", func(a *zone.ZoneAuthority) { a.Keys = append(a.Keys, zone.AuthorizedKey{Key: other}) }},
		{"other key", func(a *zone.ZoneAuthority) { a.Keys[0].Key = other }},
		{"epoch", func(a *zone.ZoneAuthority) { a.Epoch++ }},
		{"threshold", func(a *zone.ZoneAuthority) { a.Threshold++ }},
		{"zone", func(a *zone.ZoneAuthority) { a.Zone = "other." }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns := zone.NewNetworkState()
			a := ConfiguredRootAuthority(pub)
			tc.mutate(a)
			ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, a)
			if err := VerifyPinnedRoot(ns, pub); err == nil {
				t.Fatal("noncanonical root accepted")
			}
		})
	}
}
