package photonwindows

import (
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestLeafAttachmentMathMemoRetainsCurrentLifecycleChecks(t *testing.T) {
	for _, scenario := range []string{"unchanged", "route withdrawal", "host withdrawal", "overlay change", "overlay mismatch", "overlay tamper", "split routes", "gateway withdrawn", "generation", "CHILD retired", "DNS hint expired", "exact delegation expiry"} {
		t.Run(scenario, func(t *testing.T) {
			f := runtimeFixture(t)
			at := f.now
			var expiry time.Time
			if scenario == "exact delegation expiry" {
				expiry = f.now.Add(350 * time.Millisecond)
				delegation := f.view.State.Network.Zones[zone.RootZone].Delegations[f.config.ManagedZone]
				delegation.ExpiresAt = &expiry
				if err := photoncrypto.SignDelegation(delegation, zone.RootZone, packetFixtureRootSigner(t, f)); err != nil {
					t.Fatal(err)
				}
			}
			verifier := new(photoncrypto.Verifier)
			_, err := desiredLeafAttachmentWithVerifier(f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, at, verifier)
			if err != nil {
				t.Fatal("initial signed attachment rejected", err)
			}
			// Warm the exact signature payloads before changing authorization or
			// time. The mutable View intentionally keeps its revision and pointer.
			if _, err := desiredLeafAttachmentWithVerifier(f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, at, verifier); err != nil {
				t.Fatal(err)
			}
			prefix := "10.9.0.1/32"
			switch scenario {
			case "route withdrawal":
				key, _ := routing.NormalizeRouteAnnouncementKey(prefix)
				f.put(f.config.ManagedZone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix, Active: false})
			case "host withdrawal":
				key, _ := routing.NormalizeIPAMAssignmentKey(prefix)
				f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: f.config.ManagedZone, Active: false})
			case "overlay change", "overlay mismatch":
				overlay := ipsec.OverlayIntentRecord{Version: 1, OverlayID: f.config.Overlay.ID, Provider: ipsec.ProviderStrongSwan, PathKeys: []string{"family:ipv4"}, TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}}
				f.put(f.plan.Selected.Zone, ipsec.OverlayIntentRecordKey(f.config.Overlay.ID), ipsec.RecordTypeOverlayIntent, overlay)
				if scenario == "overlay change" {
					f.put(f.config.ManagedZone, ipsec.OverlayIntentRecordKey(f.config.Overlay.ID), ipsec.RecordTypeOverlayIntent, overlay)
				}
			case "overlay tamper":
				record := f.view.State.Network.Zones[f.config.ManagedZone].Records[ipsec.OverlayIntentRecordKey(f.config.Overlay.ID)]
				record.Value[0] ^= 1
			case "split routes":
				f.config.Overlay.SplitRoutes = []netip.Prefix{netip.MustParsePrefix("10.8.0.0/16")}
			case "gateway withdrawn":
				f.config.Gateway.AllowedZones = nil
			case "generation":
				f.p.tunnel.generation++
			case "CHILD retired":
				f.p.tunnel.data.retire(f.p.tunnel.data.active.spi)
			case "DNS hint expired":
				at = f.now.Add(10*time.Second + time.Nanosecond)
			case "exact delegation expiry":
				at = expiry
			}
			want, wantErr := desiredLeafAttachment(f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, at)
			got, gotErr := desiredLeafAttachmentWithVerifier(f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, at, verifier)
			valid := scenario == "unchanged"
			if (wantErr == nil) != valid || (gotErr == nil) != valid || !got.equal(want) {
				t.Fatal("warm signature memo changed lifecycle intent", gotErr, wantErr)
			}
		})
	}
}

func TestLeafLinkLocalMathMemoRecomputesSignedPath(t *testing.T) {
	f := runtimeFixture(t)
	verifier := new(photoncrypto.Verifier)
	oldLocal, oldPeer, err := leafLinkLocalAddressesWithVerifier(f.config, f.view, f.plan, f.now, verifier)
	if err != nil {
		t.Fatal(err)
	}
	overlay := ipsec.OverlayIntentRecord{Version: 1, OverlayID: f.config.Overlay.ID, Provider: ipsec.ProviderStrongSwan, PathKeys: []string{"family:ipv4"}, TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}}
	for _, path := range []zone.ZonePath{f.config.ManagedZone, f.plan.Selected.Zone} {
		f.put(path, ipsec.OverlayIntentRecordKey(f.config.Overlay.ID), ipsec.RecordTypeOverlayIntent, overlay)
	}
	wantLocal, wantPeer, wantErr := leafLinkLocalAddresses(f.config, f.view, f.plan, f.now)
	gotLocal, gotPeer, gotErr := leafLinkLocalAddressesWithVerifier(f.config, f.view, f.plan, f.now, verifier)
	if wantErr != nil || gotErr != nil || gotLocal != wantLocal || gotPeer != wantPeer || gotLocal == oldLocal || gotPeer == oldPeer {
		t.Fatal("warm signature memo retained the old signed path addresses", gotErr, wantErr)
	}
}

func BenchmarkDesiredLeafAttachmentSignatureMath(b *testing.B) {
	for _, memo := range []bool{false, true} {
		name := "fresh"
		if memo {
			name = "bounded math memo"
		}
		b.Run(name, func(b *testing.B) {
			f := runtimeFixture(b)
			var verifier *photoncrypto.Verifier
			if memo {
				verifier = new(photoncrypto.Verifier)
			}
			if _, err := desiredLeafAttachmentWithVerifier(f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now, verifier); err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if _, err := desiredLeafAttachmentWithVerifier(f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now, verifier); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
