package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type memoryCommitSink struct {
	mu      sync.Mutex
	commits int
	state   *CommitCandidate
	changes ChangeSet
	err     error
}

func (commitSink *memoryCommitSink) Commit(_ context.Context, state *CommitCandidate, changes ChangeSet) error {
	commitSink.mu.Lock()
	defer commitSink.mu.Unlock()
	if commitSink.err != nil {
		return commitSink.err
	}
	commitSink.commits++
	commitSink.state = cloneCommitCandidate(state.Verified, state.Gossip)
	commitSink.changes = changes
	return nil
}

func TestStoreApplyRemoteBatchRetainsSuccessRejectSuccess(t *testing.T) {
	now := time.Unix(1000, 0)
	initial, privateKey := testNetwork(t)
	initial.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	source := cloneNetworkState(initial)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)

	v1 := signedRecord(t, privateKey, "catofes.", "identity", []byte("v1"), 1, nil, now.Unix())
	if err := source.PutAt(v1, now); err != nil {
		t.Fatalf("PutAt(v1): %v", err)
	}
	snapshotV1, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(v1): %v", err)
	}
	v2 := signedRecord(t, privateKey, "catofes.", "identity", []byte("v2"), 2, photoncrypto.RecordHash(v1), now.Unix()+1)
	if err := source.PutAt(v2, now.Add(time.Second)); err != nil {
		t.Fatalf("PutAt(v2): %v", err)
	}
	snapshotV2, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(v2): %v", err)
	}
	bad := &ZoneSnapshot{Zone: "evil.catofes.", Authority: snapshotV1.Authority}

	commitSink := &memoryCommitSink{}
	store := NewStore(&VerifiedState{ManagedZone: "node-a.catofes.", Network: initial}, commitSink.Commit, commitSink.CommitCheckpoints)
	result, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{
		{Snapshot: snapshotV1, ExpectedRoot: ZoneRoot(ZoneStateFromSnapshot(snapshotV1))},
		{Snapshot: bad, ExpectedRoot: []byte("advertised-root")},
		{Snapshot: snapshotV2, ExpectedRoot: ZoneRoot(ZoneStateFromSnapshot(snapshotV2))},
	}, now)
	if err != nil {
		t.Fatalf("ApplyRemoteBatch: %v", err)
	}
	if !result.Committed || !result.Changes.NetworkChanged || !result.Changes.GossipCheckpointChanged {
		t.Fatalf("commit result = %+v, want network and metadata commit", result.CommitResult)
	}
	if len(result.Outcomes) != 3 || result.Outcomes[0].Err != nil || !errors.Is(result.Outcomes[1].Err, ErrSnapshotRootMismatch) || result.Outcomes[2].Err != nil {
		t.Fatalf("outcomes = %#v, want success/reject/success", result.Outcomes)
	}
	view := store.ReadView()
	if got := string(view.State.Network.Zones["catofes."].Records["identity"].Value); got != "v2" {
		t.Fatalf("identity = %q, want v2", got)
	}
	rejected := view.Gossip.Peers["peer-a"].RejectedObjects["evil.catofes."]
	if rejected.Reason != "root_mismatch" || !bytes.Equal(rejected.RootHash, []byte("advertised-root")) {
		t.Fatalf("rejected metadata = %#v", rejected)
	}
	if view.Revision != 1 {
		t.Fatalf("verified revision = %d, want 1", view.Revision)
	}
	if commitSink.commits != 1 {
		t.Fatalf("commitSink commits = %d, want 1", commitSink.commits)
	}
}

func TestStoreApplyRemoteBatchIdenticalSnapshotOnlyClearsRejectedCheckpoint(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _ := testNetwork(t)
	network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	snapshot, err := Snapshot(network, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	root := ZoneRoot(ZoneStateFromSnapshot(snapshot))
	sink := &memoryCommitSink{}
	store := NewStoreWithCheckpoint(&VerifiedState{ManagedZone: "node-a.catofes.", Network: network}, &GossipCheckpoint{
		Peers: map[string]PeerCheckpoint{"peer-a": {RejectedObjects: map[zone.ZonePath]RejectedObject{
			"catofes.": {RootHash: append([]byte(nil), root...), Reason: "previous transient rejection", UpdatedUnix: now.Add(-time.Minute).Unix(), UntilUnix: now.Add(time.Minute).Unix()},
		}}},
	}, sink.Commit, sink.CommitCheckpoints)

	result, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{Snapshot: snapshot, ExpectedRoot: root}}, now)
	if err != nil {
		t.Fatalf("ApplyRemoteBatch: %v", err)
	}
	if !result.Committed || result.Changes.NetworkChanged || !result.Changes.GossipCheckpointChanged || result.Changes.VerifiedRevision != 0 {
		t.Fatalf("checkpoint-only result = %#v", result.CommitResult)
	}
	view := store.ReadView()
	if view.Revision != 0 || len(view.Gossip.Peers["peer-a"].RejectedObjects) != 0 || sink.commits != 1 {
		t.Fatalf("view/commits = revision %d checkpoint %#v commits %d", view.Revision, view.Gossip.Peers["peer-a"], sink.commits)
	}

	noop, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{Snapshot: snapshot, ExpectedRoot: root}}, now)
	if err != nil {
		t.Fatalf("ApplyRemoteBatch(no-op): %v", err)
	}
	if noop.Committed || noop.Changes.NetworkChanged || noop.Changes.GossipCheckpointChanged || sink.commits != 1 {
		t.Fatalf("pure no-op result/commits = %#v/%d", noop.CommitResult, sink.commits)
	}
}

func TestStoreApplyRemoteBatchRejectsRootAuthorityReplacement(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, identityPrivate, _ := managedAuthorityFixture(t, true)
	trustedRoot := append(ed25519.PublicKey(nil), network.Zones[zone.RootZone].Authority.Keys[0].Key...)
	source := cloneNetworkState(network)
	otherPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other root): %v", err)
	}
	source.Zones[zone.RootZone].Authority = &zone.ZoneAuthority{
		Zone: zone.RootZone, Epoch: 2, Threshold: 1,
		Keys: []zone.AuthorizedKey{{Key: otherPublic}},
	}
	snapshot, err := Snapshot(source, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot(root): %v", err)
	}
	store := NewStore(&VerifiedState{
		ManagedZone:          "node-a.catofes.",
		Network:              network,
		TrustedRootPublicKey: trustedRoot,
		IdentityPrivateKey:   identityPrivate,
	}, nil, nil)
	result, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{
		Snapshot: snapshot, ExpectedRoot: ZoneRoot(ZoneStateFromSnapshot(snapshot)),
	}}, now)
	if err != nil {
		t.Fatalf("ApplyRemoteBatch: %v", err)
	}
	if len(result.Outcomes) != 1 || !errors.Is(result.Outcomes[0].Err, ErrTrustedRootAuthorityChange) {
		t.Fatalf("outcomes = %#v, want trusted-root authority rejection", result.Outcomes)
	}
	view := store.ReadView()
	if view.Revision != 0 || !bytes.Equal(view.State.Network.Zones[zone.RootZone].Authority.Keys[0].Key, trustedRoot) {
		t.Fatalf("root replacement changed verified state at revision %d", view.Revision)
	}
}

func TestStorePersistenceFailureLeavesStateAndRevisionUnchanged(t *testing.T) {
	now := time.Unix(1000, 0)
	initial, privateKey := testNetwork(t)
	source := cloneNetworkState(initial)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	record := signedRecord(t, privateKey, "catofes.", "identity", []byte("new"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	wantErr := errors.New("disk unavailable")
	commitSink := &memoryCommitSink{err: wantErr}
	store := NewStore(&VerifiedState{Network: initial}, commitSink.Commit, commitSink.CommitCheckpoints)
	_, err = store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{Snapshot: snapshot}}, now)
	if !errors.Is(err, wantErr) {
		t.Fatalf("ApplyRemoteBatch error = %v, want %v", err, wantErr)
	}
	view := store.ReadView()
	if view.Revision != 0 {
		t.Fatalf("verified revision = %d, want zero", view.Revision)
	}
	if view.State.Network.Zones["catofes."].Records["identity"] != nil {
		t.Fatal("commitSink failure published candidate")
	}
}

func TestStoreDeletePeerCheckpointsDoesNotAdvanceVerifiedRevision(t *testing.T) {
	sink := &memoryCommitSink{}
	store := NewStore(&VerifiedState{}, sink.Commit, sink.CommitCheckpoints)
	if result, err := store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{
		FailureCount: PatchField[int]{Set: true, Value: 2},
	}); err != nil || !result.Committed {
		t.Fatalf("UpdatePeerCheckpoint = result %+v err %v", result, err)
	}

	result, err := store.DeletePeerCheckpoints(context.Background(), []string{"peer-a", "missing"})
	if err != nil {
		t.Fatalf("DeletePeerCheckpoints: %v", err)
	}
	if !result.Committed || !result.Changes.GossipCheckpointChanged || result.Changes.VerifiedRevision != 0 {
		t.Fatalf("delete result = %+v", result)
	}
	view := store.ReadView()
	if view.Revision != 0 || len(view.Gossip.Peers) != 0 {
		t.Fatalf("view after delete = revision %d gossip %+v", view.Revision, view.Gossip)
	}
	if sink.commits != 2 {
		t.Fatalf("commits = %d, want update plus delete", sink.commits)
	}
	result, err = store.DeletePeerCheckpoints(context.Background(), []string{"peer-a"})
	if err != nil || result.Committed || sink.commits != 2 {
		t.Fatalf("no-op delete = result %+v err %v commits %d", result, err, sink.commits)
	}
}

func TestStoreReadViewIsDetached(t *testing.T) {
	now := time.Unix(1000, 0)
	initial, privateKey := testNetwork(t)
	source := cloneNetworkState(initial)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	record := signedRecord(t, privateKey, "catofes.", "identity", []byte("committed"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	store := NewStore(&VerifiedState{Network: initial, TrustedRootPublicKey: ed25519.PublicKey("root")}, nil, nil)
	if _, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{Snapshot: snapshot}}, now); err != nil {
		t.Fatalf("ApplyRemoteBatch: %v", err)
	}
	view := store.ReadView()
	view.State.TrustedRootPublicKey[0] = 'X'
	view.State.Network.Zones["catofes."].Records["identity"].Value[0] = 'X'
	fresh := store.ReadView()
	if string(fresh.State.TrustedRootPublicKey) != "root" || string(fresh.State.Network.Zones["catofes."].Records["identity"].Value) != "committed" {
		t.Fatal("mutating read view changed committed state")
	}
}

func TestRestoreStorePreservesRevisionAndDetachesCandidate(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, identityPrivate, _ := managedAuthorityFixture(t, true)
	candidate := &CommitCandidate{
		Verified: &VerifiedState{
			ManagedZone:        "node-a.catofes.",
			Network:            network,
			IdentityPrivateKey: identityPrivate,
		},
		Gossip: &GossipCheckpoint{Peers: map[string]PeerCheckpoint{
			"peer.catofes.": {BackoffUntilUnix: 10},
		}},
	}
	commitSink := &memoryCommitSink{}
	store, err := RestoreStore(candidate, 7, commitSink.Commit, commitSink.CommitCheckpoints)
	if err != nil {
		t.Fatalf("RestoreStore: %v", err)
	}
	candidate.Verified.ManagedZone = "mutated.catofes."
	metadata := candidate.Gossip.Peers["peer.catofes."]
	metadata.BackoffUntilUnix = 99
	candidate.Gossip.Peers["peer.catofes."] = metadata
	view := store.ReadView()
	if view.Revision != 7 || view.State.ManagedZone != "node-a.catofes." || view.Gossip.Peers["peer.catofes."].BackoffUntilUnix != 10 {
		t.Fatalf("restored view = %+v", view)
	}

	result, err := store.ApplyLocalIntent(context.Background(), PutRecordIntent{
		Zone: "node-a.catofes.", Key: "config", Type: "text", Value: []byte("restored"),
	}, now)
	if err != nil {
		t.Fatalf("ApplyLocalIntent: %v", err)
	}
	if !result.Committed || result.Changes.VerifiedRevision != 8 || store.ReadView().Revision != 8 || commitSink.changes.VerifiedRevision != 8 {
		t.Fatalf("restored commit result/view/sink = %+v/%+v/%+v", result, store.ReadView(), commitSink.changes)
	}
}

func TestRestoreStoreRejectsInvalidCandidate(t *testing.T) {
	if _, err := RestoreStore(nil, 3, nil, nil); !errors.Is(err, ErrInvalidStateRoot) {
		t.Fatalf("nil RestoreStore error = %v", err)
	}
	if _, err := RestoreStore(&CommitCandidate{Verified: &VerifiedState{}}, 3, nil, nil); !errors.Is(err, ErrInvalidStateRoot) {
		t.Fatalf("invalid RestoreStore error = %v", err)
	}
}

func TestStoreDoesNotRetainInitialState(t *testing.T) {
	initial, _ := testNetwork(t)
	rootKey := ed25519.PublicKey("root")
	input := &VerifiedState{Network: initial, TrustedRootPublicKey: rootKey}
	store := NewStore(input, nil, nil)

	rootKey[0] = 'X'
	input.TrustedRootPublicKey[1] = 'Y'
	delete(initial.Zones, "catofes.")
	view := store.ReadView()
	if string(view.State.TrustedRootPublicKey) != "root" || view.State.Network.Zones["catofes."] == nil {
		t.Fatal("store retained mutable initial state")
	}
}

func TestStoreConcurrentReadersSeeWholeRevision(t *testing.T) {
	now := time.Unix(1000, 0)
	initial, privateKey := testNetwork(t)
	source := cloneNetworkState(initial)
	source.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	record := signedRecord(t, privateKey, "catofes.", "identity", []byte("committed"), 1, nil, now.Unix())
	if err := source.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}
	snapshot, err := Snapshot(source, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot: %v", err)
	}
	store := NewStore(&VerifiedState{Network: initial}, nil, nil)

	var readers sync.WaitGroup
	for range 8 {
		readers.Add(1)
		go func() {
			defer readers.Done()
			for range 100 {
				view := store.ReadView()
				record := view.State.Network.Zones[zone.ZonePath("catofes.")].Records["identity"]
				if view.Revision == 0 && record != nil {
					t.Errorf("reader saw new state at old revision")
					return
				}
				if view.Revision == 1 && (record == nil || string(record.Value) != "committed") {
					t.Errorf("reader saw incomplete state at new revision")
					return
				}
			}
		}()
	}
	if _, err := store.ApplyRemoteBatch(context.Background(), "peer-a", []RemoteSnapshot{{Snapshot: snapshot}}, now); err != nil {
		t.Fatalf("ApplyRemoteBatch: %v", err)
	}
	readers.Wait()
}

func TestStoreUpdatePeerCheckpointIsTypedDetachedAndCheckpointOnly(t *testing.T) {
	initial, _ := testNetwork(t)
	commitSink := &memoryCommitSink{}
	store := NewStore(&VerifiedState{Network: initial}, commitSink.Commit, commitSink.CommitCheckpoints)
	root := []byte("rejected-root")
	grace := []ObservedGraceEndpoint{{Endpoint: "192.0.2.2:4242", UntilUnix: 200}}
	failure := &PeerFailure{Code: "timeout", Message: "round timed out", AtUnix: 99}
	result, err := store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{
		LastSyncUnix:       PatchField[int64]{Set: true, Value: 100},
		BackoffUntilUnix:   PatchField[int64]{Set: true, Value: 150},
		FailureCount:       PatchField[int]{Set: true, Value: 2},
		DiscoveredEndpoint: PatchField[string]{Set: true, Value: "192.0.2.1:4242"},
		ObservedGrace:      PatchField[[]ObservedGraceEndpoint]{Set: true, Value: grace},
		LastFailure:        PatchField[*PeerFailure]{Set: true, Value: failure},
		Reject: map[zone.ZonePath]RejectedObject{
			"bad.catofes.": {RootHash: root, Reason: "untrusted_zone", UpdatedUnix: 100},
		},
	})
	if err != nil {
		t.Fatalf("UpdatePeerCheckpoint: %v", err)
	}
	if !result.Committed || result.Changes.NetworkChanged || !result.Changes.GossipCheckpointChanged {
		t.Fatalf("commit result = %+v", result)
	}
	if result.Changes.VerifiedRevision != 0 {
		t.Fatalf("checkpoint changed verified revision to %d", result.Changes.VerifiedRevision)
	}
	root[0] = 'X'
	grace[0].Endpoint = "mutated"
	failure.Message = "mutated"
	view := store.ReadView()
	peer := view.Gossip.Peers["peer-a"]
	if peer.LastSyncUnix != 100 || peer.BackoffUntilUnix != 150 || peer.FailureCount != 2 || peer.ObservedGraceEndpoints[0].Endpoint != "192.0.2.2:4242" {
		t.Fatalf("peer metadata = %+v", peer)
	}
	if peer.LastFailure == nil || peer.LastFailure.Code != "timeout" || peer.LastFailure.Error() != "round timed out" {
		t.Fatalf("peer failure = %+v", peer.LastFailure)
	}
	if string(peer.RejectedObjects["bad.catofes."].RootHash) != "rejected-root" {
		t.Fatal("metadata patch retained rejected root input")
	}
	if commitSink.commits != 1 || commitSink.changes.NetworkChanged {
		t.Fatalf("commitSink commit = %d/%+v", commitSink.commits, commitSink.changes)
	}

	clearResult, err := store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{
		ClearRejected: []zone.ZonePath{"bad.catofes."},
	})
	if err != nil || !clearResult.Committed {
		t.Fatalf("clear rejected result/error = %+v/%v", clearResult, err)
	}
	if len(store.ReadView().Gossip.Peers["peer-a"].RejectedObjects) != 0 {
		t.Fatal("clear rejected patch did not remove entry")
	}
}

func TestStoreUpdatePeerCheckpointNoopAndPersistenceFailure(t *testing.T) {
	commitSink := &memoryCommitSink{}
	store := NewStore(nil, commitSink.Commit, commitSink.CommitCheckpoints)
	result, err := store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{})
	if err != nil || result.Committed || commitSink.commits != 0 {
		t.Fatalf("empty patch result/error/commits = %+v/%v/%d", result, err, commitSink.commits)
	}

	wantErr := errors.New("metadata persistence failed")
	commitSink.err = wantErr
	_, err = store.UpdatePeerCheckpoint(context.Background(), "peer-a", PeerCheckpointPatch{
		LastAttemptUnix: PatchField[int64]{Set: true, Value: 100},
	})
	if !errors.Is(err, wantErr) {
		t.Fatalf("UpdatePeerCheckpoint error = %v, want %v", err, wantErr)
	}
	view := store.ReadView()
	if view.Revision != 0 || len(view.Gossip.Peers) != 0 {
		t.Fatalf("commitSink failure published metadata: %+v", view)
	}
}

func (sink *memoryCommitSink) CommitCheckpoints(_ context.Context, peers map[string]*PeerCheckpoint, revision VerifiedRevision) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	if sink.err != nil {
		return sink.err
	}
	sink.commits++
	sink.changes = ChangeSet{VerifiedRevision: revision, GossipCheckpointChanged: true}
	if sink.state == nil {
		sink.state = &CommitCandidate{Gossip: &GossipCheckpoint{Peers: make(map[string]PeerCheckpoint)}}
	}
	for id, p := range peers {
		if p == nil {
			delete(sink.state.Gossip.Peers, id)
		} else {
			sink.state.Gossip.Peers[id] = clonePeerCheckpoint(*p)
		}
	}
	return nil
}
