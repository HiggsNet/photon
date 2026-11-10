package state

import (
	"bytes"
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
		{"catalog/recompute", func() any {
			// The previous ReadCatalog path, measured against the same pinned
			// fixture without adding the unrelated full ReadView copy.
			store.mu.RLock()
			defer store.mu.RUnlock()
			return &CatalogView{ManagedZone: store.state.ManagedZone, Digests: ZoneDigests(store.state.Network)}
		}},
		{"catalog/cold", func() any {
			store.catalog.Store(nil)
			return store.ReadCatalog()
		}},
		{"revocations/full", func() any { return store.ReadView().State.Network.RevokedZones(now) }},
		{"revocations/narrow", func() any { return store.ReadRevokedZones(now) }},
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
