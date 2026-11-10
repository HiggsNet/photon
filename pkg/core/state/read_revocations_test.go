package state

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestZoneRevocationAcrossTimeIntervals(t *testing.T) {
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
		for _, path := range []zone.ZonePath{"parent.", "child.parent.", "purged.", "other.", "nil.", "unknown."} {
			if got, want := store.IsZoneRevoked(path, now), network.IsZoneRevoked(path, now); got != want {
				t.Errorf("at %d: %s revoked=%v, want %v", second, path, got, want)
			}
		}
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

func TestZoneRevocationFollowsPublication(t *testing.T) {
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
			if _, err := store.UpdatePeerCheckpoint(t.Context(), path.String(), PeerCheckpointPatch{ObservedLastUnix: PatchField[int64]{Set: true, Value: 7}}); err != nil {
				t.Fatal(err)
			}
			if store.IsZoneRevoked(path, now) {
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
			pending := store.IsZoneRevoked(path, now)
			close(release)
			if err := <-done; (fail && !errors.Is(err, wantErr)) || (!fail && err != nil) {
				t.Fatalf("commit: %v", err)
			}
			if pending {
				t.Fatal("uncommitted revocation was visible")
			}
			if store.IsZoneRevoked(path, now) == fail {
				t.Fatal("revocation did not follow committed revision")
			}
			if got := store.ReadPeerAuthorization(path.String()); got.Revision != store.VerifiedRevision() {
				t.Fatal("discovery revision does not match state")
			}
			_, retained := store.PeerCheckpoints([]string{path.String()})[path.String()]
			if retained != fail {
				t.Fatal("pruning did not follow committed revocation")
			}
		})
	}
}
