package state

import (
	"context"
	"errors"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestRevocationProjectionAcrossTimeIntervals(t *testing.T) {
	network := zone.NewNetworkState()
	for _, path := range []zone.ZonePath{zone.RootZone, "parent.", "child.parent.", "other."} {
		network.Zones[path] = zone.NewZoneState(path, nil)
	}
	root := network.Zones[zone.RootZone]
	for path, at := range map[zone.ZonePath]int64{"parent.": 100, "purged.": 200, "other.": 0} {
		root.Revocations[path] = &zone.DelegationRevocation{ParentZone: zone.RootZone, ChildZone: path, RevokedAt: at}
	}
	root.Revocations["nil."] = nil
	network.Zones["nil."] = nil
	store := NewStore(&VerifiedState{Network: network}, nil, nil)
	check := func(second int64) {
		t.Helper()
		now := time.Unix(second, 0)
		want := network.RevokedZones(now)
		got, _ := store.RevokedPeerCheckpoints(now)
		activity := store.ReadPeerActivity(now)
		if !reflect.DeepEqual(got, want) || !reflect.DeepEqual(activity.RevokedZones, want) {
			t.Errorf("at %d: cleanup=%v activity=%v, want %v", second, got, activity.RevokedZones, want)
		}
		// Even an empty result must remain detached from the cached projection.
		clear(got)
		activity.RevokedZones["caller."] = true
	}
	// Includes both sides of activation, purged tombstones, ancestors, negative
	// timestamps and rollback across more than one scheduled boundary.
	for _, second := range []int64{-1, 0, 99, 100, 101, 199, 200, 201, 150, 50, 100, 200} {
		check(second)
	}
	var readers sync.WaitGroup
	for i := range 4 {
		readers.Go(func() {
			for j := range 50 {
				check(int64((j+i)%4*75 - 1))
			}
		})
	}
	readers.Wait()
}

func TestRevocationProjectionFollowsPublication(t *testing.T) {
	for _, fail := range []bool{false, true} {
		t.Run(fmt.Sprintf("fail=%v", fail), func(t *testing.T) {
			network, _, _, parentPrivate := managedAuthorityFixture(t, true)
			path := zone.ZonePath("node-a.catofes.")
			entered, release := make(chan struct{}), make(chan struct{})
			wantErr := errors.New("disk failed")
			store := NewStore(&VerifiedState{ManagedZone: "catofes.", Network: network, IdentityPrivateKey: parentPrivate},
				func(context.Context, *CommitCandidate, ChangeSet) error {
					close(entered)
					<-release
					if fail {
						return wantErr
					}
					return nil
				}, func(context.Context, map[string]*PeerCheckpoint, VerifiedRevision) error { return nil })
			now := time.Unix(1000, 0)
			before, _ := store.RevokedPeerCheckpoints(now)
			if before[path] {
				t.Fatal("fixture already revoked")
			}
			done := make(chan error, 1)
			go func() {
				_, err := store.ApplyLocalIntent(t.Context(), RevokeDelegationIntent{Parent: path.Parent(), Child: path}, now)
				done <- err
			}()
			select {
			case <-entered:
			case <-time.After(2 * time.Second):
				close(release)
				t.Fatal("commit never reached persistence")
			}
			pending, _ := store.RevokedPeerCheckpoints(now)
			close(release)
			if err := <-done; (fail && !errors.Is(err, wantErr)) || (!fail && err != nil) {
				t.Fatalf("commit: %v", err)
			}
			if pending[path] {
				t.Fatal("uncommitted revocation was visible")
			}
			after, _ := store.RevokedPeerCheckpoints(now)
			if after[path] == fail {
				t.Fatal("projection did not follow committed revision")
			}
			if got := store.ReadDiscovery(path.String()); got.Revision != store.VerifiedRevision() {
				t.Fatal("discovery revision does not match state")
			}
			if _, err := store.UpdatePeerCheckpoint(t.Context(), path.String(), PeerCheckpointPatch{ObservedLastUnix: PatchField[int64]{Set: true, Value: 7}}); err != nil {
				t.Fatal(err)
			}
			_, peers := store.RevokedPeerCheckpoints(now)
			if !fail && peers[path.String()].ObservedLastSeenUnix != 7 {
				t.Fatal("cached revocations hid a new checkpoint")
			}
		})
	}
}

func BenchmarkRevocationZones(b *testing.B) {
	candidate := checkpointBenchmarkCandidate()
	network := candidate.Verified.Network
	network.Zones["catofes."] = zone.NewZoneState("catofes.", nil)
	for i := range 4 {
		path := zone.ZonePath(fmt.Sprintf("node-%d.catofes.", i))
		network.Zones["catofes."].Revocations[path] = &zone.DelegationRevocation{
			ParentZone: "catofes.", ChildZone: path, RevokedAt: 50,
		}
	}
	network.Zones["child.node-0.catofes."] = zone.NewZoneState("child.node-0.catofes.", nil)
	network.Zones["catofes."].Revocations["purged.catofes."] = &zone.DelegationRevocation{
		ParentZone: "catofes.", ChildZone: "purged.catofes.", RevokedAt: 200,
	}
	store := NewStore(candidate.Verified, nil, nil)
	now := time.Unix(100, 0)
	for _, mode := range []string{"recompute", "warm", "cold"} {
		b.Run(mode, func(b *testing.B) {
			read := func() map[zone.ZonePath]bool {
				store.mu.RLock()
				defer store.mu.RUnlock()
				if mode == "recompute" {
					return store.state.Network.RevokedZones(now)
				}
				if mode == "cold" {
					store.revocations.Store(nil)
				}
				return store.revokedZonesLocked(now)
			}
			if got := read(); len(got) != 5 || !got["child.node-0.catofes."] || got["purged.catofes."] {
				b.Fatalf("bad active/future revocation fixture: %v", got)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				benchmarkReadResult = read()
			}
		})
	}
}
