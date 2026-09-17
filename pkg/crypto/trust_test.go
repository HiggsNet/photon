package crypto

import (
	"bytes"
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
		name       string
		mutate     func(*zone.ZoneAuthority)
		repairable bool
	}{
		{"legacy capabilities", func(a *zone.ZoneAuthority) {
			a.Keys[0].Capabilities = []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}}
		}, true},
		{"extra key", func(a *zone.ZoneAuthority) { a.Keys = append(a.Keys, zone.AuthorizedKey{Key: other}) }, false},
		{"other key", func(a *zone.ZoneAuthority) { a.Keys[0].Key = other }, false},
		{"epoch", func(a *zone.ZoneAuthority) { a.Epoch++ }, false},
		{"threshold", func(a *zone.ZoneAuthority) { a.Threshold++ }, false},
		{"zone", func(a *zone.ZoneAuthority) { a.Zone = "other." }, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns := zone.NewNetworkState()
			a := ConfiguredRootAuthority(pub)
			tc.mutate(a)
			ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, a)
			if err := VerifyPinnedRoot(ns, pub); err == nil {
				t.Fatal("noncanonical root accepted")
			}
			before := AuthorityHash(a)
			RepairLegacyRootAuthority(ns, pub)
			if err := VerifyPinnedRoot(ns, pub); (err == nil) != tc.repairable {
				t.Fatalf("repair result: %v", err)
			}
			if !tc.repairable && !bytes.Equal(before, AuthorityHash(ns.Zones[zone.RootZone].Authority)) {
				t.Fatal("repair changed incompatible root")
			}
		})
	}
}
