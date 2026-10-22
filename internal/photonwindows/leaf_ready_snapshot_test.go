package photonwindows

import (
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
)

func leafReadyMessages(f *pipelineFixture) []babel.Message {
	return []babel.Message{{Type: babel.TLVHello, Seqno: 1, Interval: 400},
		{Type: babel.TLVIHU, Address: f.p.local, Metric: 100, Interval: 400},
		{Type: babel.TLVUpdate, Prefix: netip.MustParsePrefix("10.1.2.0/24"), RouterID: f.remoteID, NextHop: f.p.peer, Seqno: 7, Metric: 10, Interval: 1600}}
}

// The optimized and ordinary owners have independent candidate/neighbor tables
// so pruning by either implementation cannot hide a differential failure.
// The production owner learns the same real Babel frame through AES and UDP.
func leafReadyPair(t *testing.T, f *pipelineFixture, messages []babel.Message) (*leafRuntime, *leafRuntime) {
	t.Helper()
	payload, err := babel.Encode(messages)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := babel.BuildPacket(f.p.peer, f.p.local, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !f.inbound(t, packet) {
		t.Fatal("authenticated control rejected")
	}
	reference := *f.p
	reference.policy = nil
	reference.leaf, err = babel.NewLeaf(f.p.local, f.p.peer, f.p.routerID, 100)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reference.leaf.Receive(packet, f.now, currentBabelRouteAuthorizer(f.config, f.view, f.now)); err != nil {
		t.Fatal(err)
	}
	return &leafRuntime{pipeline: f.p}, &leafRuntime{pipeline: &reference}
}

func compareLeafReady(t *testing.T, f *pipelineFixture, optimized, reference *leafRuntime, view corestate.View, at time.Time, want bool) {
	t.Helper()
	got := optimized.readySnapshot(f.config, view, f.plan, at)
	ordinary := reference.ready(f.config, view, f.plan, at)
	if got != ordinary || got != want {
		t.Fatalf("readiness at %s: snapshot=%v ordinary=%v want=%v", at, got, ordinary, want)
	}
}

func TestLeafReadySnapshotUsableDeviceSourceDifferential(t *testing.T) {
	for _, scenario := range []string{"no route", "ordinary route", "installed source", "uninstalled source"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			messages := leafReadyMessages(f)
			want := true
			switch scenario {
			case "no route":
				messages, want = messages[:2], false
			case "installed source":
				messages[2].SourcePrefix = netip.MustParsePrefix("10.9.0.1/32")
			case "uninstalled source":
				prefix := "10.9.0.2/32"
				key, _ := routing.NormalizeIPAMAssignmentKey(prefix)
				f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: f.config.ManagedZone, Active: true})
				key, _ = routing.NormalizeRouteAnnouncementKey(prefix)
				f.put(f.config.ManagedZone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix, Active: true})
				messages[2].SourcePrefix, want = netip.MustParsePrefix(prefix), false
			}
			optimized, reference := leafReadyPair(t, f, messages)
			view := detachedPacketPolicyView(f.view)
			compareLeafReady(t, f, optimized, reference, view, f.now, want)
			before := f.p.policy
			compareLeafReady(t, f, optimized, reference, view, f.now.Add(50*time.Millisecond), want)
			if before == nil || f.p.policy != before {
				t.Fatal("readiness did not exercise a warm signed-policy projection")
			}
		})
	}
}

func TestLeafReadySnapshotLiveCandidateDeadlinesDifferential(t *testing.T) {
	for _, scenario := range []string{"route", "Hello", "IHU"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			messages := leafReadyMessages(f)
			index := map[string]int{"Hello": 0, "IHU": 1, "route": 2}[scenario]
			messages[index].Interval = 10
			optimized, reference := leafReadyPair(t, f, messages)
			view := detachedPacketPolicyView(f.view)
			deadline := f.now.Add(350 * time.Millisecond)
			compareLeafReady(t, f, optimized, reference, view, f.now, true)
			before := f.p.policy
			compareLeafReady(t, f, optimized, reference, view, deadline.Add(-time.Nanosecond), true)
			compareLeafReady(t, f, optimized, reference, view, deadline, false)
			if before == nil || f.p.policy != before {
				t.Fatal("candidate liveness was tested without a policy cache hit")
			}
		})
	}
}

func TestLeafReadySnapshotLiveWithdrawalWithWarmPolicy(t *testing.T) {
	for _, scenario := range []string{"route", "neighbor"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			messages := leafReadyMessages(f)
			optimized, reference := leafReadyPair(t, f, messages)
			view := detachedPacketPolicyView(f.view)
			compareLeafReady(t, f, optimized, reference, view, f.now, true)
			before := f.p.policy
			message := messages[2]
			if scenario == "neighbor" {
				message = messages[1]
			}
			message.Metric = babel.MetricInfinity
			payload, err := babel.Encode([]babel.Message{message})
			if err != nil {
				t.Fatal(err)
			}
			packet, err := babel.BuildPacket(f.p.peer, f.p.local, payload)
			if err != nil {
				t.Fatal(err)
			}
			at := f.now.Add(100 * time.Millisecond)
			facts, ok := f.p.prepareSnapshot(f.config, view, f.plan, at)
			if !ok {
				t.Fatal("warm policy unavailable")
			}
			if accepted, err := f.p.acceptPrepared(facts, f.directInboundCompletion(t, packet)); !accepted || err != nil {
				t.Fatal("authenticated withdrawal rejected", err)
			}
			if _, err := reference.pipeline.leaf.Receive(packet, at, facts.authorizeRoute); err != nil {
				t.Fatal(err)
			}
			compareLeafReady(t, f, optimized, reference, view, at, false)
			if before == nil || f.p.policy != before {
				t.Fatal("live withdrawal was tested without retaining the signed projection")
			}
		})
	}
}

func TestLeafReadySnapshotAuthorizationDeadlinesDifferential(t *testing.T) {
	for _, scenario := range []string{"delegation", "IKE", "CHILD", "DNS hint"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			deadline := f.now.Add(500 * time.Millisecond)
			switch scenario {
			case "delegation":
				delegation := f.view.State.Network.Zones[zone.RootZone].Delegations[f.config.ManagedZone]
				delegation.ExpiresAt = &deadline
				if err := photoncrypto.SignDelegation(delegation, zone.RootZone, packetFixtureRootSigner(t, f)); err != nil {
					t.Fatal(err)
				}
			case "IKE":
				f.p.tunnel.ikeExpiresAt = deadline
			case "CHILD":
				f.p.tunnel.expiresAt = deadline
			case "DNS hint":
				deadline = f.now.Add(10*time.Second + time.Nanosecond)
			}
			optimized, reference := leafReadyPair(t, f, leafReadyMessages(f))
			view := detachedPacketPolicyView(f.view)
			compareLeafReady(t, f, optimized, reference, view, f.now, true)
			compareLeafReady(t, f, optimized, reference, view, deadline.Add(-time.Nanosecond), true)
			compareLeafReady(t, f, optimized, reference, view, deadline, false)
		})
	}
}

func TestLeafReadySnapshotCurrentChangesDifferential(t *testing.T) {
	for _, scenario := range []string{"route withdrawal", "host withdrawal", "signed revocation", "generation", "active CHILD removed"} {
		t.Run(scenario, func(t *testing.T) {
			f := newPipelineFixture(t)
			optimized, reference := leafReadyPair(t, f, leafReadyMessages(f))
			view := detachedPacketPolicyView(f.view)
			compareLeafReady(t, f, optimized, reference, view, f.now, true)
			switch scenario {
			case "route withdrawal":
				key, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
				f.put(f.plan.Selected.Zone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: false})
			case "host withdrawal":
				key, _ := routing.NormalizeIPAMAssignmentKey("10.9.0.1/32")
				f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: "10.9.0.1/32", AssignedTo: f.config.ManagedZone, Active: false})
			case "signed revocation":
				delegation := f.view.State.Network.Zones[zone.RootZone].Delegations[f.config.ManagedZone]
				revocation := &zone.DelegationRevocation{ChildZone: f.config.ManagedZone, ParentZone: zone.RootZone, RevokedAuthorityEpoch: delegation.AuthorityEpoch, RevokedAuthorityHash: delegation.AuthorityHash, RevokedAt: f.now.Unix()}
				if err := photoncrypto.SignDelegationRevocation(revocation, zone.RootZone, packetFixtureRootSigner(t, f)); err != nil {
					t.Fatal(err)
				}
				f.view.State.Network.Zones[zone.RootZone].Revocations[f.config.ManagedZone] = revocation
			case "generation":
				f.p.tunnel.generation++
			case "active CHILD removed":
				f.p.tunnel.data.active = nil
			}
			// Even a replacement snapshot carrying the same external revision
			// must discard the old signed projection immediately.
			view = detachedPacketPolicyView(f.view)
			compareLeafReady(t, f, optimized, reference, view, f.now.Add(time.Nanosecond), false)
		})
	}
}

func TestLeafReadySnapshotOrdinaryMutableViewRemainsFresh(t *testing.T) {
	f := newPipelineFixture(t)
	f.learn(t)
	runtime := &leafRuntime{pipeline: f.p}
	if !runtime.readySnapshot(f.config, f.view, f.plan, f.now) || f.p.policy == nil {
		t.Fatal("initial signed projection unavailable")
	}
	key, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
	f.put(f.plan.Selected.Zone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: false})
	if runtime.ready(f.config, f.view, f.plan, f.now) {
		t.Fatal("ordinary mutable-view readiness reused the cached route grant")
	}
	if (&leafRuntime{}).readySnapshot(f.config, f.view, f.plan, f.now) {
		t.Fatal("readiness survived device removal")
	}
}

func BenchmarkGatewayPacketReadySnapshot(b *testing.B) {
	f := newPipelineFixture(b)
	f.learn(b)
	store := corestate.NewStore(f.view.State, nil, nil)
	b.Cleanup(store.Close)
	var reader packetStateView
	runtime := &leafRuntime{pipeline: f.p}
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if !runtime.readySnapshot(f.config, reader.read(store), f.plan, f.now) {
			b.Fatal("authorized fixture is not ready")
		}
	}
}
