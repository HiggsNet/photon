package photonwindows

import (
	"context"
	"errors"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func packetStateStore(t testing.TB, commit corestate.CommitFunc) *corestate.Store {
	t.Helper()
	network, root, private := signedNetwork(t)
	store := corestate.NewStore(&corestate.VerifiedState{ManagedZone: "node-a.catofes.", Network: network, TrustedRootPublicKey: root, IdentityPrivateKey: private}, commit, nil)
	t.Cleanup(store.Close)
	return store
}

func TestPacketStateTracksVerifiedPublication(t *testing.T) {
	store := packetStateStore(t, nil)
	var reader packetStateView
	first := reader.read(store)
	if first.State == nil || first.Gossip != nil || first.Revision != 0 {
		t.Fatal("initial packet snapshot missing or contains gossip")
	}
	if result, err := store.UpdatePeerCheckpoint(context.Background(), "peer", corestate.PeerCheckpointPatch{LastSyncUnix: corestate.PatchField[int64]{Set: true, Value: 123}}); err != nil || !result.Committed {
		t.Fatal("checkpoint fixture failed", err)
	}
	if next := reader.read(store); next.State != first.State || next.Gossip != nil || next.Revision != first.Revision {
		t.Fatal("checkpoint-only write replaced packet state or leaked stale hints")
	}
	result, err := store.ApplyLocalIntents(context.Background(), []corestate.LocalIntent{corestate.PutRecordIntent{Zone: first.State.ManagedZone, Key: "data/packet-test", Type: "test", Value: []byte("published")}}, time.Now())
	if err != nil || !result.Committed {
		t.Fatal("verified publication failed", err)
	}
	next := reader.read(store)
	if next.State == first.State || next.Revision != first.Revision+1 || string(next.State.Network.Zones[next.State.ManagedZone].Records["data/packet-test"].Value) != "published" {
		t.Fatal("packet owner missed a verified publication")
	}
	if first.State.Network.Zones[first.State.ManagedZone].Records["data/packet-test"] != nil {
		t.Fatal("publication mutated the retained old snapshot")
	}
	// Store's public read contract remains independently mutable by callers.
	detached := store.ReadView()
	delete(detached.State.Network.Zones, detached.State.ManagedZone)
	if reader.read(store).State.Network.Zones[next.State.ManagedZone] == nil {
		t.Fatal("external detached read mutated the packet snapshot")
	}
}

func TestPacketStateStoreIdentityAndFailedCommit(t *testing.T) {
	want := errors.New("fixture persistence failure")
	store := packetStateStore(t, func(context.Context, *corestate.CommitCandidate, corestate.ChangeSet) error { return want })
	var reader packetStateView
	first := reader.read(store)
	if _, err := store.ApplyLocalIntents(context.Background(), []corestate.LocalIntent{corestate.PutRecordIntent{Zone: first.State.ManagedZone, Key: "data/failure", Type: "test", Value: []byte("unpublished")}}, time.Now()); !errors.Is(err, want) {
		t.Fatal("failed commit fixture did not fail", err)
	}
	if got := reader.read(store); got.State != first.State || got.Revision != first.Revision || got.State.Network.Zones[first.State.ManagedZone].Records["data/failure"] != nil {
		t.Fatal("uncommitted candidate became packet state")
	}
	other := corestate.NewStore(&corestate.VerifiedState{ManagedZone: zone.RootZone, Network: first.State.Network}, nil, nil)
	t.Cleanup(other.Close)
	if got := reader.read(other); got.Revision != first.Revision || got.State == first.State || got.State.ManagedZone != zone.RootZone {
		t.Fatal("equal revisions from different stores reused an old owner")
	}
	if got := reader.read(nil); got.State != nil || got.Gossip != nil {
		t.Fatal("nil store retained previous state")
	}
}

func BenchmarkPacketStateView(b *testing.B) {
	store := packetStateStore(b, nil)
	var reader packetStateView
	reader.read(store)
	b.ReportAllocs()
	b.ResetTimer()
	for b.Loop() {
		if reader.read(store).State == nil {
			b.Fatal("missing verified state")
		}
	}
}
