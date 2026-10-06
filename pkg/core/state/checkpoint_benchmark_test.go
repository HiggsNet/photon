package state

import (
	"context"
	"fmt"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

// Match the observed network's scale without copying production data or keys:
// Two base zones plus 26 leaf zones, each with 10 active and 80 history entries.
func checkpointBenchmarkCandidate() *CommitCandidate {
	candidate := commonBoltTestCandidate(1)
	for i := 0; i < 26; i++ {
		path := zone.ZonePath(fmt.Sprintf("node-%d.catofes.", i))
		zs := zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1})
		for j := 0; j < 10; j++ {
			key := fmt.Sprintf("record-%d", j)
			for v := uint64(1); v <= 8; v++ {
				r := &zone.Record{Zone: path, Key: key, Version: v, Value: make([]byte, 256),
					ValueHash: make([]byte, 32), PrevHash: make([]byte, 32), SignedBy: make([]byte, 32), Signature: make([]byte, 64)}
				zs.RecordHistory[key] = append(zs.RecordHistory[key], r)
				zs.Records[key] = r
			}
		}
		candidate.Verified.Network.Zones[path] = zs
	}
	return candidate
}

func BenchmarkCheckpointCommit(b *testing.B) {
	// Disable fsync only in this isolated benchmark to measure CPU/allocations.
	db, err := bolt.Open(filepath.Join(b.TempDir(), "state.db"), 0600, &bolt.Options{NoSync: true})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	candidate := checkpointBenchmarkCandidate()
	commit := func(tx *bolt.Tx) error {
		_, err := CommitBoltState(tx, candidate, ChangeSet{VerifiedRevision: 1, GossipCheckpointChanged: true})
		return err
	}
	if err := db.Update(commit); err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		candidate.Gossip.Peers["peer-a"] = PeerCheckpoint{LastSyncUnix: int64(i + 1)}
		if err := db.Update(commit); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCheckpointStoreUpdate(b *testing.B) {
	for _, changed := range []bool{false, true} {
		b.Run(fmt.Sprintf("changed=%v", changed), func(b *testing.B) {
			candidate := checkpointBenchmarkCandidate()
			store := NewStoreWithCheckpoint(candidate.Verified, candidate.Gossip, nil, func(context.Context, map[string]*PeerCheckpoint, VerifiedRevision) error { return nil })
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				failures := 2
				if changed {
					failures = i % 2
				}
				_, err := store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{FailureCount: PatchField[int]{Set: true, Value: failures}})
				if err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}

func BenchmarkCheckpointNarrowCommit(b *testing.B) {
	db, err := bolt.Open(filepath.Join(b.TempDir(), "state.db"), 0600, &bolt.Options{NoSync: true})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	disk := &BoltStore{db: db}
	candidate := checkpointBenchmarkCandidate()
	if err := disk.CommitCommon(context.Background(), candidate, ChangeSet{VerifiedRevision: 1}); err != nil {
		b.Fatal(err)
	}
	store, err := RestoreStore(candidate, 1, disk.CommitCommon, disk.CommitCheckpoints)
	if err != nil {
		b.Fatal(err)
	}
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{LastSyncUnix: PatchField[int64]{Set: true, Value: int64(i + 1)}}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRevocationRead(b *testing.B) {
	candidate := checkpointBenchmarkCandidate()
	store := NewStoreWithCheckpoint(candidate.Verified, candidate.Gossip, nil, nil)
	b.Run("full_view", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			store.ReadView().State.Network.RevokedZones(time.Unix(100, 0))
		}
	})
	b.Run("projection", func(b *testing.B) {
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			store.RevokedPeerCheckpoints(time.Unix(100, 0))
		}
	})
}
