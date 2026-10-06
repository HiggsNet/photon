package state

import (
	"context"
	"errors"
	"testing"
)

func TestCheckpointCommitCannotMutateVerifiedRoot(t *testing.T) {
	for _, deletion := range []bool{false, true} {
		for _, fail := range []bool{false, true} {
			name := "update"
			if deletion {
				name = "delete"
			}
			if fail {
				name += "_rollback"
			}
			t.Run(name, func(t *testing.T) {
				initial := commonBoltTestCandidate(1)
				wantErr := errors.New("commit failed")
				var retained map[string]*PeerCheckpoint
				store := NewStoreWithCheckpoint(initial.Verified, initial.Gossip, nil, func(_ context.Context, candidate map[string]*PeerCheckpoint, _ VerifiedRevision) error {
					retained = candidate
					if peer := candidate["peer-a"]; peer != nil {
						peer.FailureCount = 99
					}
					if fail {
						return wantErr
					}
					return nil
				})
				var err error
				if deletion {
					_, err = store.DeletePeerCheckpoints(context.Background(), []string{"peer-a"})
				} else {
					_, err = store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{FailureCount: PatchField[int]{Set: true, Value: 3}})
				}
				if (fail && !errors.Is(err, wantErr)) || (!fail && err != nil) {
					t.Fatalf("commit error: %v", err)
				}
				if retained == nil {
					t.Fatal("commit callback not invoked")
				}
				retained["peer-a"] = &PeerCheckpoint{FailureCount: 999}
				view := store.ReadView()
				if view.Revision != 0 || view.State.ManagedZone != initial.Verified.ManagedZone || view.State.Network.Zones["node-a.catofes."].Authority.Epoch != 1 {
					t.Fatal("checkpoint callback mutated verified state or revision")
				}
				peer, exists := view.Gossip.Peers["peer-a"]
				if fail && (!exists || peer.FailureCount != 2) {
					t.Fatal("failed commit changed checkpoint")
				}
				if !fail && deletion && exists {
					t.Fatal("successful deletion retained peer")
				}
				if !fail && !deletion && (!exists || peer.FailureCount != 3) {
					t.Fatal("successful update not published")
				}
			})
		}
	}
}
