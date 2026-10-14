package state

import (
	"path/filepath"
	"testing"

	bolt "go.etcd.io/bbolt"
)

// Use the existing history-heavy fixture and production codec. NoSync removes
// filesystem latency from CPU timing; PageAlloc still measures dirty DB pages.
func BenchmarkVerifiedZoneCommit(b *testing.B) {
	db, err := bolt.Open(filepath.Join(b.TempDir(), "state.db"), 0600, &bolt.Options{NoSync: true})
	if err != nil {
		b.Fatal(err)
	}
	defer db.Close()
	candidate := checkpointBenchmarkCandidate()
	if err := db.Update(func(tx *bolt.Tx) error {
		_, err := CommitBoltState(tx, candidate, ChangeSet{VerifiedRevision: 1})
		return err
	}); err != nil {
		b.Fatal(err)
	}
	before := db.Stats().TxStats.PageAlloc
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		candidate.Verified.Network.Zones["node-0.catofes."].Records["record-0"].Value[0] = byte((i % 255) + 1)
		if err := db.Update(func(tx *bolt.Tx) error {
			_, err := CommitBoltState(tx, candidate, ChangeSet{VerifiedRevision: VerifiedRevision(i + 2), NetworkChanged: true})
			return err
		}); err != nil {
			b.Fatal(err)
		}
	}
	b.StopTimer()
	b.ReportMetric(float64(db.Stats().TxStats.PageAlloc-before)/float64(b.N), "db-page-B/op")
}
