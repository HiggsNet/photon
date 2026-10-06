package state

import (
	"bytes"
	"context"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"reflect"
	"testing"
	"time"
)

func TestReadCatalogMatchesSnapshotAndDetachesHashes(t *testing.T) {
	candidate := commonBoltTestCandidate(1)
	store := NewStoreWithCheckpoint(candidate.Verified, candidate.Gossip, nil, nil)
	view := store.ReadCatalog()
	if view.ManagedZone != candidate.Verified.ManagedZone || !reflect.DeepEqual(view.Digests, ZoneDigests(store.ReadView().State.Network)) {
		t.Fatal("catalog projection differs from full snapshot")
	}
	expected := append([]byte(nil), view.Digests[0].RootHash...)
	view.Digests[0].RootHash[0] ^= 0xff
	if !bytes.Equal(store.ReadCatalog().Digests[0].RootHash, expected) {
		t.Fatal("returned digest aliases store")
	}
	var absent *Store
	if absent.ReadCatalog() != nil {
		t.Fatal("nil store exposed catalog")
	}
}

func TestReadPeerActivityTracksTimeAndCheckpointChanges(t *testing.T) {
	candidate := commonBoltTestCandidate(1)
	path := zone.ZonePath("future.")
	candidate.Verified.Network.Zones[zone.RootZone].Revocations[path] = &zone.DelegationRevocation{ParentZone: zone.RootZone, ChildZone: path, RevokedAt: 100}
	candidate.Gossip.Peers["peer-a"] = PeerCheckpoint{LastSyncUnix: 10, ObservedLastSeenUnix: 20, LastFailure: &PeerFailure{Message: "not needed"}}
	store := NewStoreWithCheckpoint(candidate.Verified, candidate.Gossip, nil, nil)
	before := store.ReadPeerActivity(time.Unix(99, 0))
	if before.RevokedZones[path] || before.Peers["peer-a"] != (PeerActivity{LastSyncUnix: 10, ObservedLastSeenUnix: 20}) {
		t.Fatalf("wrong activity view: %+v", before)
	}
	delete(before.Peers, "peer-a")
	before.RevokedZones[path] = true
	if store.ReadPeerActivity(time.Unix(99, 0)).RevokedZones[path] {
		t.Fatal("returned map aliases store")
	}
	if _, err := store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{LastSyncUnix: PatchField[int64]{Set: true, Value: 30}}); err != nil {
		t.Fatal(err)
	}
	after := store.ReadPeerActivity(time.Unix(100, 0))
	if !after.RevokedZones[path] || after.Peers["peer-a"].LastSyncUnix != 30 || after.Peers["peer-a"].ObservedLastSeenUnix != 20 || store.VerifiedRevision() != 0 {
		t.Fatalf("projection missed time/checkpoint change: %+v", after)
	}
}

var benchmarkReadResult any

func BenchmarkReadProjection(b *testing.B) {
	fixture := checkpointBenchmarkCandidate()
	store := NewStoreWithCheckpoint(fixture.Verified, fixture.Gossip, nil, nil)
	now := time.Unix(100, 0)
	cases := []struct {
		name string
		read func() any
	}{
		{"catalog/full", func() any {
			v := store.ReadView()
			return &CatalogView{ManagedZone: v.State.ManagedZone, Digests: ZoneDigests(v.State.Network)}
		}},
		{"catalog/narrow", func() any { return store.ReadCatalog() }},
		{"activity/full", func() any {
			v := store.ReadView()
			out := PeerActivityView{RevokedZones: v.State.Network.RevokedZones(now), Peers: make(map[string]PeerActivity)}
			for id, p := range v.Gossip.Peers {
				out.Peers[id] = PeerActivity{LastSyncUnix: p.LastSyncUnix, ObservedLastSeenUnix: p.ObservedLastSeenUnix}
			}
			return out
		}},
		{"activity/narrow", func() any { return store.ReadPeerActivity(now) }},
	}
	for _, c := range cases {
		b.Run(c.name, func(b *testing.B) {
			b.ReportAllocs()
			for i := 0; i < b.N; i++ {
				benchmarkReadResult = c.read()
			}
		})
	}
}
