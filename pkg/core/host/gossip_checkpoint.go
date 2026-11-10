package host

import (
	"context"
	"errors"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// gossipObservedVerification lives only across one packet's state update
// and address-book publication, both evaluated at the same time.
type gossipObservedVerification struct {
	revision         corestate.VerifiedRevision
	valid            bool
	confirmedChanged bool
}

// recordGossipObservedPath checks the peer's current authorization before
// recording the packet source. Only a changed address from a probe is durable.
func (driver *GossipDriver) recordGossipObservedPath(ctx context.Context, peerID, endpoint string, confirmed bool, suppressed map[string]bool, now time.Time) (gossipObservedVerification, bool, error) {
	defer driver.LogSlowOperation("observed_path_update", time.Now(), driver.PendingEventCount())
	if driver == nil || driver.gossipState == nil {
		return gossipObservedVerification{}, false, ErrGossipDriverStopped
	}
	input := driver.gossipDiscoveryInput(peerID, suppressed, false, "")
	input.observedVerifier = &driver.observedPathVerifier
	patch, ok := PlanVerifiedObservedCheckpoint(input, peerID, endpoint, now)
	verification := gossipObservedVerification{revision: input.verifiedRevision, valid: ok}
	if !ok {
		return verification, false, nil
	}
	if confirmed && !input.Suppressed[peerID] && input.Peers[peerID].LastSuccessfulEndpoint != endpoint {
		patch.LastSuccessfulEndpoint = corestate.PatchField[string]{Set: true, Value: endpoint}
	}
	_, err := driver.gossipState.UpdatePeerCheckpoints(ctx, map[string]corestate.PeerCheckpointPatch{peerID: patch})
	verification.confirmedChanged = err == nil && patch.LastSuccessfulEndpoint.Set
	return verification, err == nil, err
}

// RecordGossipRejectedObject stores a bounded retry-suppression hint for a
// chunk whose advertised object could not be decoded or verified.
func (driver *GossipDriver) RecordGossipRejectedObject(ctx context.Context, peerID string, chunk *gossip.ObjectChunk, rejection error, now time.Time) error {
	if driver == nil || driver.gossipState == nil {
		return ErrGossipDriverStopped
	}
	if peerID == "" || chunk == nil || chunk.Object != gossip.ObjectPullZone || !chunk.Zone.Valid() || len(chunk.RootHash) == 0 {
		return nil
	}
	reason := gossip.RejectReason(rejection)
	if reason == "" {
		reason = "verify_failed"
	}
	_, err := driver.gossipState.UpdatePeerCheckpoints(ctx, map[string]corestate.PeerCheckpointPatch{peerID: {
		Reject: map[zone.ZonePath]corestate.RejectedObject{chunk.Zone: {
			RootHash: append([]byte(nil), chunk.RootHash...), Reason: reason,
			UpdatedUnix: now.Unix(), UntilUnix: now.Add(corestate.RejectedObjectTTL).Unix(),
		}},
	}})
	return err
}

// recordGossipRelays updates the live throttle and catalog deduplication state.
func (driver *GossipDriver) recordGossipRelays(ctx context.Context, peerIDs []string, catalogRoot string, now time.Time) (bool, error) {
	if driver == nil || driver.gossipState == nil {
		return false, ErrGossipDriverStopped
	}
	patch := corestate.PeerCheckpointPatch{
		LastRelayUnix:    corestate.PatchField[int64]{Set: true, Value: now.Unix()},
		LastRelayRootHex: corestate.PatchField[string]{Set: true, Value: catalogRoot},
	}
	patches := make(map[string]corestate.PeerCheckpointPatch, len(peerIDs))
	for _, peerID := range peerIDs {
		if peerID == "" {
			return false, errors.New("gossip relay peer is required")
		}
		patches[peerID] = patch
	}
	result, err := driver.gossipState.UpdatePeerCheckpoints(ctx, patches)
	return result.Committed, err
}

// commitGossipEventCheckpoint records the terminal result once per session.
func (driver *GossipDriver) commitGossipEventCheckpoint(ctx context.Context, session *gossip.SyncSession, now time.Time) error {
	if driver == nil || driver.gossipState == nil || session == nil || !session.Done() || session.PeerID == "" {
		return nil
	}
	defer driver.LogSlowOperation("session_checkpoint", time.Now(), driver.PendingEventCount())
	peerID := session.PeerID
	peer := driver.gossipState.PeerCheckpoints([]string{peerID})[peerID]
	if !applyGossipCompletionCheckpoint(&peer, session.LastError(), now) {
		if ctx != nil {
			return ctx.Err()
		}
		return nil
	}
	patch := corestate.PeerCheckpointPatch{
		BackoffUntilUnix: corestate.PatchField[int64]{Set: true, Value: peer.BackoffUntilUnix},
		FailureCount:     corestate.PatchField[int]{Set: true, Value: peer.FailureCount},
		LastFailure:      corestate.PatchField[*corestate.PeerFailure]{Set: true, Value: peer.LastFailure},
	}
	if session.LastError() == nil {
		patch.LastSyncUnix = corestate.PatchField[int64]{Set: true, Value: peer.LastSyncUnix}
	}
	if _, err := driver.gossipState.UpdatePeerCheckpoints(ctx, map[string]corestate.PeerCheckpointPatch{peerID: patch}); err != nil {
		return err
	}
	driver.observeSyncAttempt(peerID, now)
	return nil
}

func applyGossipCompletionCheckpoint(peer *corestate.PeerCheckpoint, syncErr error, now time.Time) bool {
	previous := *peer
	if syncErr != nil {
		peer.FailureCount++
		peer.BackoffUntilUnix = now.Add(gossipFailureBackoff(peer.FailureCount)).Unix()
		peer.LastFailure = &corestate.PeerFailure{Code: corestate.PeerFailureUnknown, Message: syncErr.Error(), AtUnix: now.Unix()}
		return true
	}
	peer.LastSyncUnix = now.Unix()
	peer.BackoffUntilUnix = 0
	peer.FailureCount = 0
	peer.LastFailure = nil
	return peer.LastSyncUnix != previous.LastSyncUnix ||
		peer.BackoffUntilUnix != previous.BackoffUntilUnix || peer.FailureCount != previous.FailureCount ||
		peer.LastFailure != previous.LastFailure
}

func gossipFailureBackoff(failures int) time.Duration {
	if failures > 6 {
		failures = 6
	}
	if failures < 0 {
		failures = 0
	}
	return time.Duration(1<<failures) * time.Second
}
