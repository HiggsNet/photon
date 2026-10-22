package photonwindows

import (
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"slices"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
)

func packetAuditCollisionZone(t *testing.T, f *pipelineFixture, notBefore int64, expires *time.Time) {
	t.Helper()
	private := packetFixtureRootSigner(t, f)
	path := zone.ZonePath("collision.")
	authority := &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1,
		Keys: []zone.AuthorizedKey{{Key: slices.Clone(f.view.State.Network.Zones[f.config.Gateway.AllowedZones[0]].Authority.Keys[0].Key),
			NotBefore: notBefore, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}}}}}
	delegation := &zone.Delegation{ZoneName: path, Authority: *authority, ExpiresAt: expires}
	if err := photoncrypto.SignDelegation(delegation, zone.RootZone, private); err != nil {
		t.Fatal(err)
	}
	f.view.State.Network.Zones[path] = zone.NewZoneState(path, authority)
	f.view.State.Network.Zones[zone.RootZone].Delegations[path] = delegation
	// The existing fixture signer owns this copied public authority too. The
	// collision is a valid independently signed claim, not corrupted input.
	f.put(path, routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity,
		routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{hex.EncodeToString(f.remoteID[:])}, ExpiresAt: f.now.Add(time.Hour).Unix()})
}

func TestPacketPolicyAuditAuthorityCollisionTransitions(t *testing.T) {
	for _, scenario := range []string{"future authority key", "exact delegation expiry"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			f.learn(t)
			deadline := f.now.Add(time.Second)
			if scenario == "future authority key" {
				packetAuditCollisionZone(t, f, deadline.Unix(), nil)
			} else {
				deadline = f.now.Add(500 * time.Millisecond)
				packetAuditCollisionZone(t, f, 0, &deadline)
			}
			view := detachedPacketPolicyView(f.view)
			route := sadr.Route{Destination: netip.MustParsePrefix("10.1.2.0/24"), RouterID: f.remoteID}
			var before *packetPolicy
			for _, at := range []time.Time{f.now, f.now.Add(100 * time.Millisecond), deadline.Add(-time.Nanosecond), deadline} {
				facts, ok := compareSnapshotPolicy(t, f, view, at)
				if !ok || f.p.policy == nil {
					t.Fatal("unrelated claimant invalidated the local attachment", at)
				}
				want := at.Before(deadline)
				if scenario == "exact delegation expiry" {
					want = !want
				}
				if facts.authorizeRoute(route) != want {
					t.Fatal("signed claimant transition retained the wrong route grant", at)
				}
				if before == nil {
					before = f.p.policy
				} else if at.Before(deadline) && f.p.policy != before {
					t.Fatal("fixture did not exercise a warm policy hit", at)
				} else if at.Equal(deadline) && f.p.policy == before {
					t.Fatal("claimant transition retained the previous policy epoch")
				}
			}
		})
	}
}

func TestPacketPolicyAuditLiveChildAndSelectors(t *testing.T) {
	for _, scenario := range []string{"CHILD activation", "selector withdrawal"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			f.learn(t)
			view := detachedPacketPolicyView(f.view)
			facts, ok := f.p.prepareSnapshot(f.config, view, f.plan, f.now)
			if !ok || f.p.policy == nil {
				t.Fatal("warm snapshot preparation rejected")
			}
			before := f.p.policy
			// The two workers may finish setup controls after business crypto.
			// Generate pending deliveries through the shared synchronous core:
			// consuming controls with f.accept would deliberately clear policy.
			outbound, ok := f.p.tunnel.data.processOutbound(f.p.generation, facts.plan, f.packet(true),
				func(packet []byte, out bool) bool { return f.p.authorize(facts, packet, out) })
			if !ok || outbound.err != nil {
				t.Fatal("warm outbound crypto rejected", outbound.err)
			}
			wire, err := f.sender.Seal(f.packet(false))
			if err != nil {
				t.Fatal(err)
			}
			inbound, ok := f.p.tunnel.data.processInbound(f.p.generation, facts.plan, outbound.job.sa.endpoint, wire)
			if !ok || inbound.err != nil {
				t.Fatal("warm inbound crypto rejected", inbound.err)
			}
			if f.p.policy != before {
				t.Fatal("fixture lost its warm cache before the live SA change")
			}
			if scenario == "CHILD activation" {
				next := dataplaneChild(513)
				next.LocalSelectors, next.RemoteSelectors = f.child.LocalSelectors, f.child.RemoteSelectors
				if err := f.p.tunnel.data.install(f.p.generation, f.plan, outbound.job.sa.endpoint, next); err != nil {
					t.Fatal(err)
				}
				if err := f.p.tunnel.data.activate(next.InitiatorSPI); err != nil {
					t.Fatal(err)
				}
			} else {
				address := netip.MustParseAddr("10.99.0.2")
				inbound.job.sa.local = []ike.TrafficSelector{{StartAddr: address, EndAddr: address, EndPort: 65535}}
			}
			facts, ok = f.p.prepareSnapshot(f.config, view, f.plan, f.now.Add(time.Nanosecond))
			if !ok || f.p.policy != before {
				t.Fatal("live SA change must still exercise the signed-policy cache hit")
			}
			if accepted, err := f.p.acceptPrepared(facts, outbound); accepted || err != nil {
				t.Fatal("old outbound completion bypassed the live CHILD/selector gate", err)
			}
			accepted, err := f.p.acceptPrepared(facts, inbound)
			want := scenario == "CHILD activation"
			if accepted != want || err != nil || (len(f.device.written) == 1) != want {
				t.Fatal("warm policy changed old inbound overlap/selector behavior", accepted, err)
			}
		})
	}
}

func TestPacketPolicyAuditPublishedWithdrawalRejectsQueuedPacket(t *testing.T) {
	f := newPipelineFixture(t)
	private := packetFixtureRootSigner(t, f)
	f.learn(t)
	if !f.submitFromDevice(t, f.packet(true)) || !f.accept(t, f.businessCompletion(t)) {
		t.Fatal("setup business exchange failed")
	}
	f.receiveBusiness(t)
	verified := &corestate.VerifiedState{ManagedZone: f.config.ManagedZone,
		TrustedRootPublicKey: f.config.TrustedRootPublicKey, Network: f.view.State.Network}
	store, err := corestate.RestoreStore(&corestate.CommitCandidate{Verified: verified}, f.view.Revision, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(store.Close)
	var reader packetStateView
	view := reader.read(store)
	facts, ok := f.p.prepareSnapshot(f.config, view, f.plan, f.now)
	if !ok || f.p.policy == nil {
		t.Fatal("initial snapshot preparation rejected")
	}
	before := f.p.policy
	// Retain a completed business job before delivery, as in the adjacent SA
	// audit. Draining async setup controls through businessCompletion would
	// deliberately clear policy, depending on worker scheduling.
	completion, processed := f.p.tunnel.data.processOutbound(f.p.generation, facts.plan, f.packet(true),
		func(packet []byte, outbound bool) bool { return f.p.authorize(facts, packet, outbound) })
	if !processed || completion.err != nil {
		t.Fatal("initial business crypto rejected", completion.err)
	}
	if f.p.policy != before {
		t.Fatal("fixture did not retain a policy before the queued completion")
	}
	key, _ := routing.NormalizeIPAMAssignmentKey("10.1.0.0/16")
	previous := f.view.State.Network.Zones[zone.RootZone].Records[key]
	value, err := json.Marshal(routing.IPAMAssignmentRecord{Version: 1, Prefix: "10.1.0.0/16",
		AssignedTo: f.config.Gateway.AllowedZones[0], Active: false})
	if err != nil {
		t.Fatal(err)
	}
	withdrawal := &zone.Record{Zone: zone.RootZone, Key: key, Type: routing.RecordTypeIPAMAssignment,
		Value: value, Version: previous.Version + 1, PrevHash: photoncrypto.RecordHash(previous), Timestamp: f.now.Unix()}
	if err := photoncrypto.SignRecord(withdrawal, private); err != nil {
		t.Fatal(err)
	}
	f.view.State.Network.Zones[zone.RootZone].Records[key] = withdrawal
	snapshot, err := corestate.Snapshot(f.view.State.Network, zone.RootZone)
	if err != nil {
		t.Fatal(err)
	}
	limits := corestate.DefaultSyncLimits()
	limits.MaxBytes = 32 << 10
	result, err := store.ApplyRemoteBatch(t.Context(), "signed-root-withdrawal",
		[]corestate.RemoteSnapshot{{Snapshot: snapshot, Limits: limits}}, f.now)
	if err != nil || !result.Committed || len(result.Outcomes) != 1 || result.Outcomes[0].Err != nil {
		t.Fatal("signed remote withdrawal was not published", result, err)
	}
	current := reader.read(store)
	if current.State == view.State || current.Revision != view.Revision+1 {
		t.Fatal("packet snapshot owner missed the published withdrawal")
	}
	facts, ok = f.p.prepareSnapshot(f.config, current, f.plan, f.now.Add(time.Nanosecond))
	if !ok || f.p.policy == before {
		t.Fatal("valid attachment did not rebuild policy for the published withdrawal")
	}
	if accepted, err := f.p.acceptPrepared(facts, completion); accepted || err != nil {
		t.Fatal("published IPAM withdrawal delivered the previously queued packet", err)
	}
}
