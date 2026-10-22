package photonwindows

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func detachedPacketPolicyView(view corestate.View) corestate.View {
	copy := *view.State
	copy.Network = zone.CloneNetworkState(view.State.Network)
	return corestate.View{Revision: view.Revision, State: &copy}
}

// Compare successful static policy and route decisions with the ordinary
// current verifier, using the same genuinely signed input and exact time.
func compareSnapshotPolicy(t *testing.T, f *pipelineFixture, view corestate.View, now time.Time) (*packetAuthorization, bool) {
	t.Helper()
	reference := *f.p
	want, valid := reference.prepare(f.config, view, f.plan, now)
	got, ok := f.p.prepareSnapshot(f.config, view, f.plan, now)
	if ok != valid || (got == nil) != (want == nil) {
		t.Fatalf("snapshot/current decision differs at %s: got %v, want %v", now, ok, valid)
	}
	if !ok {
		return nil, false
	}
	if !got.now.Equal(now) || !reflect.DeepEqual(got.plan, want.plan) ||
		!reflect.DeepEqual(got.hosts, want.hosts) || !reflect.DeepEqual(got.localOrigins, want.localOrigins) {
		t.Fatal("snapshot projection differs from current policy", now)
	}
	for _, route := range []sadr.Route{
		{Destination: netip.MustParsePrefix("10.1.2.0/24"), RouterID: f.remoteID},
		{Destination: netip.MustParsePrefix("10.1.2.0/24"), Source: netip.MustParsePrefix("10.9.0.1/32"), RouterID: f.remoteID},
		{Destination: netip.MustParsePrefix("10.1.2.0/24"), Source: netip.MustParsePrefix("10.8.0.1/32"), RouterID: f.remoteID},
	} {
		if got.authorizeRoute(route) != want.authorizeRoute(route) {
			t.Fatal("snapshot route decision differs from current policy", now, route)
		}
	}
	return got, true
}

func TestPacketPolicySignedExactDeadlineDifferential(t *testing.T) {
	for _, parentProof := range []bool{false, true} {
		t.Run(map[bool]string{false: "delegation", true: "parent proof"}[parentProof], func(t *testing.T) {
			f := newPipelineFixture(t)
			private := packetFixtureRootSigner(t, f)
			expiry := f.now.Add(500 * time.Millisecond)
			root := f.view.State.Network.Zones[zone.RootZone]
			delegation := root.Delegations[f.config.ManagedZone]
			delegation.ExpiresAt = &expiry
			if err := photoncrypto.SignDelegation(delegation, zone.RootZone, private); err != nil {
				t.Fatal(err)
			}
			if parentProof {
				f.view.State.Network.Zones[f.config.ManagedZone].ParentProof = []*zone.Delegation{delegation}
				delete(root.Delegations, f.config.ManagedZone)
			}
			f.learn(t)
			view := detachedPacketPolicyView(f.view)
			for _, at := range []time.Time{f.now, f.now.Add(100 * time.Millisecond), expiry.Add(-time.Nanosecond), expiry} {
				_, ok := compareSnapshotPolicy(t, f, view, at)
				if ok != at.Before(expiry) {
					t.Fatal("signed exact deadline was extended", at, ok)
				}
			}
		})
	}
}

func TestPacketPolicySignedSecondTransitionsDifferential(t *testing.T) {
	for _, scenario := range []string{"authority key", "transport key", "future identity collision", "identity collision expires"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			private := packetFixtureRootSigner(t, f)
			deadline := f.now.Add(time.Second)
			switch scenario {
			case "authority key":
				local := f.view.State.Network.Zones[f.config.ManagedZone]
				local.Authority.Keys[0].NotAfter = f.now.Unix()
				delegation := f.view.State.Network.Zones[zone.RootZone].Delegations[f.config.ManagedZone]
				delegation.Authority = *local.Authority
				if err := photoncrypto.SignDelegation(delegation, zone.RootZone, private); err != nil {
					t.Fatal(err)
				}
			case "transport key":
				record := f.view.State.Network.Zones[f.config.ManagedZone].Records[ipsec.RecordKeyTransportKey]
				key, err := ipsec.ParseTransportKeyRecord(record)
				if err != nil {
					t.Fatal(err)
				}
				key.NotAfter = deadline.Unix()
				f.put(f.config.ManagedZone, record.Key, record.Type, key)
				f.p.tunnel.localAuthorization, err = localTransportAuthorization(f.config, f.view, f.now)
				if err != nil {
					t.Fatal(err)
				}
			default:
				timestamp, expiry := deadline.Unix(), f.now.Add(time.Hour).Unix()
				if scenario == "identity collision expires" {
					timestamp, expiry = f.now.Add(-time.Second).Unix(), deadline.Unix()
				}
				value, err := json.Marshal(routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{hex.EncodeToString(f.remoteID[:])}, ExpiresAt: expiry})
				if err != nil {
					t.Fatal(err)
				}
				record := &zone.Record{Zone: zone.RootZone, Key: routing.RecordKeyBabelIdentity, Type: routing.RecordTypeBabelIdentity, Value: value, Version: 1, Timestamp: timestamp}
				if err := photoncrypto.SignRecord(record, private); err != nil {
					t.Fatal(err)
				}
				f.view.State.Network.Zones[zone.RootZone].Records[record.Key] = record
			}
			f.learn(t)
			view := detachedPacketPolicyView(f.view)
			for _, at := range []time.Time{f.now, f.now.Add(100 * time.Millisecond), deadline.Add(-time.Nanosecond), deadline} {
				facts, ok := compareSnapshotPolicy(t, f, view, at)
				if scenario == "authority key" || scenario == "transport key" {
					if ok != at.Before(deadline) {
						t.Fatal("signed key deadline extended", at, ok)
					}
				} else {
					if !ok {
						t.Fatal("remote identity collision invalidated local attachment")
					}
					validRoute := facts.authorizeRoute(sadr.Route{Destination: netip.MustParsePrefix("10.1.2.0/24"), RouterID: f.remoteID})
					want := at.Before(deadline)
					if scenario == "identity collision expires" {
						want = !want
					}
					if validRoute != want {
						t.Fatal("signed identity transition missed", at, validRoute)
					}
				}
			}
		})
	}
}

func TestPacketPolicySignedContactDifferential(t *testing.T) {
	for _, scenario := range []string{"overflowed TTL", "port equality"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			peer := f.config.Gateway.AllowedZones[0]
			deadline := f.now.Add(time.Second)
			if scenario == "overflowed TTL" {
				f.put(peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{Version: 1, Addresses: []ipsec.AddressAdvertisement{{ID: "wrap", Source: ipsec.SourceManualAddress, Address: f.plan.Selected.Contact.Address, Family: ipsec.FamilyIPv4, TTLSeconds: 18446744074, LastObserved: f.now.Unix()}}})
				addresses, err := ipsec.ParseAddressRecord(f.view.State.Network.Zones[peer].Records[ipsec.RecordKeyAddresses])
				if err != nil {
					t.Fatal(err)
				}
				candidates, err := ipsec.ResolveAddressCandidates(t.Context(), addresses, f.now, ipsec.AddressCandidateOptions{AllowPrivateLocal: true})
				if err != nil || len(candidates) != 1 {
					t.Fatal("overflow candidate absent", candidates, err)
				}
				deadline = candidates[0].ExpiresAt
			} else {
				ports, err := ipsec.ParsePortRecord(f.view.State.Network.Zones[peer].Records[ipsec.RecordKeyPorts])
				if err != nil {
					t.Fatal(err)
				}
				ports.Current.ValidUntil = deadline.Unix()
				f.put(peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ports)
			}
			f.learn(t)
			view := detachedPacketPolicyView(f.view)
			for _, at := range []time.Time{f.now, f.now.Add(100 * time.Millisecond), deadline.Add(-time.Nanosecond), deadline, deadline.Add(time.Nanosecond)} {
				_, ok := compareSnapshotPolicy(t, f, view, at)
				if ok != !at.After(deadline) {
					t.Fatal("signed contact equality changed", at, ok)
				}
			}
		})
	}
}

func TestPacketPolicyNewSnapshotWithdrawsQueuedCompletion(t *testing.T) {
	for _, scenario := range []string{"route withdrawal", "revocation"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			private := packetFixtureRootSigner(t, f)
			f.learn(t)
			view := detachedPacketPolicyView(f.view)
			if !f.p.submitSnapshotPacket(f.config, view, f.plan, f.now, f.packet(true)) {
				t.Fatal("warm outbound rejected")
			}
			completion := f.businessCompletion(t)
			if scenario == "route withdrawal" {
				key, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
				f.put(f.config.Gateway.AllowedZones[0], key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: false})
			} else {
				delegation := f.view.State.Network.Zones[zone.RootZone].Delegations[f.config.ManagedZone]
				revocation := &zone.DelegationRevocation{ChildZone: f.config.ManagedZone, ParentZone: zone.RootZone, RevokedAuthorityEpoch: delegation.AuthorityEpoch, RevokedAuthorityHash: delegation.AuthorityHash, RevokedAt: f.now.Unix()}
				if err := photoncrypto.SignDelegationRevocation(revocation, zone.RootZone, private); err != nil {
					t.Fatal(err)
				}
				f.view.State.Network.Zones[zone.RootZone].Revocations[f.config.ManagedZone] = revocation
			}
			// Even an equal external revision cannot retain a prior snapshot's
			// projection. Real Store publication also increments its revision.
			updated := detachedPacketPolicyView(f.view)
			facts, ok := compareSnapshotPolicy(t, f, updated, f.now.Add(time.Nanosecond))
			if ok {
				if accepted, err := f.p.acceptPrepared(facts, completion); accepted || err != nil {
					t.Fatal("withdrawn snapshot delivered a queued packet", err)
				}
			}
		})
	}
}

func TestPacketPolicyMutableInputsDoNotRetainGrant(t *testing.T) {
	for _, scenario := range []string{"ordinary mutable view", "config split", "config allowlist", "planner contact"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			f.learn(t)
			view := detachedPacketPolicyView(f.view)
			if _, ok := f.p.prepareSnapshot(f.config, view, f.plan, f.now); !ok {
				t.Fatal("warm policy rejected")
			}
			switch scenario {
			case "ordinary mutable view":
				view.State.Network.Zones[f.config.ManagedZone].Records[ipsec.RecordKeyProfile].Signature[0] ^= 1
				if _, ok := f.p.prepare(f.config, view, f.plan, f.now); ok {
					t.Fatal("ordinary mutable view reused trusted snapshot policy")
				}
				return
			case "config split":
				f.config.Overlay.SplitRoutes[0] = netip.MustParsePrefix("10.2.0.0/16")
			case "config allowlist":
				f.config.Gateway.AllowedZones[0] = "absent.catofes."
			case "planner contact":
				f.plan.Candidates[0].Contacts[0].Address = "192.0.2.55"
			}
			facts, ok := compareSnapshotPolicy(t, f, view, f.now.Add(time.Nanosecond))
			if ok && f.p.authorize(facts, f.packet(true), true) {
				t.Fatal("mutable config/planner content retained traffic authorization")
			}
		})
	}
}

func TestPacketPolicyClockAndDNSLifetime(t *testing.T) {
	t.Run("precise rollback", func(t *testing.T) {
		f := newPipelineFixture(t)
		f.learn(t)
		view := detachedPacketPolicyView(f.view)
		_, ok := compareSnapshotPolicy(t, f, view, f.now.Add(100*time.Millisecond))
		if !ok {
			t.Fatal("initial policy rejected")
		}
		before := f.p.policy
		if _, ok := compareSnapshotPolicy(t, f, view, f.now.Add(100*time.Millisecond-time.Nanosecond)); !ok || f.p.policy == before {
			t.Fatal("sub-second wall rollback retained a policy interval")
		}
		if _, ok := f.p.prepareSnapshot(f.config, view, f.plan, f.now.Add(-time.Nanosecond)); ok {
			t.Fatal("original planner wall timestamp bypassed")
		}
	})
	t.Run("original DNS lease", func(t *testing.T) {
		f := newPipelineFixture(t)
		view := detachedPacketPolicyView(f.view)
		for _, at := range []time.Time{f.now, f.now.Add(9 * time.Second), f.now.Add(10 * time.Second), f.now.Add(10*time.Second + time.Nanosecond)} {
			_, ok := compareSnapshotPolicy(t, f, view, at)
			if ok != (at.Sub(f.plan.EvaluatedAt) <= 10*time.Second) {
				t.Fatal("traffic renewed the original DNS hint", at, ok)
			}
		}
	})
	t.Run("monotonic delegation", func(t *testing.T) {
		f := newPipelineFixture(t)
		private := packetFixtureRootSigner(t, f)
		expires := time.Now().Add(time.Hour)
		delegation := f.view.State.Network.Zones[zone.RootZone].Delegations[f.config.ManagedZone]
		delegation.ExpiresAt = &expires
		if err := photoncrypto.SignDelegation(delegation, zone.RootZone, ed25519.PrivateKey(private)); err != nil {
			t.Fatal(err)
		}
		view := detachedPacketPolicyView(f.view)
		for range 2 {
			if _, ok := compareSnapshotPolicy(t, f, view, f.now); !ok || f.p.policy != nil {
				t.Fatal("monotonic expiry retained a wall policy interval")
			}
		}
	})
}
