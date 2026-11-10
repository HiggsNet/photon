package host

import (
	"context"
	"errors"
	"slices"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
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
func (driver *GossipDriver) recordGossipObservedPath(ctx context.Context, peerID, endpoint string, confirmed bool, now time.Time) (gossipObservedVerification, bool, error) {
	defer driver.LogSlowOperation("observed_path_update", time.Now(), driver.PendingEventCount())
	if driver == nil || driver.gossipState == nil {
		return gossipObservedVerification{}, false, ErrGossipDriverStopped
	}
	input := driver.gossipDiscoveryInput(peerID, false, "")
	input.observedVerifier = &driver.observedPathVerifier
	patch, ok := PlanVerifiedObservedCheckpoint(input, peerID, endpoint, now)
	verification := gossipObservedVerification{revision: input.verifiedRevision, valid: ok}
	if !ok {
		return verification, false, nil
	}
	if confirmed && input.Peers[peerID].LastSuccessfulEndpoint != endpoint {
		patch.LastSuccessfulEndpoint = corestate.PatchField[string]{Set: true, Value: endpoint}
	}
	_, err := driver.gossipState.UpdatePeerCheckpoints(ctx, map[string]corestate.PeerCheckpointPatch{peerID: patch})
	verification.confirmedChanged = err == nil && patch.LastSuccessfulEndpoint.Set
	return verification, err == nil, err
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
	syncErr := session.LastError()
	pingTimeout := errors.Is(syncErr, gossip.ErrPingTimeout) && !driver.isGossipBootstrapPeer(peerID)
	if !applyGossipCompletionCheckpoint(&peer, syncErr, pingTimeout, now) {
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
	if syncErr == nil {
		patch.LastSyncUnix = corestate.PatchField[int64]{Set: true, Value: peer.LastSyncUnix}
	}
	if _, err := driver.gossipState.UpdatePeerCheckpoints(ctx, map[string]corestate.PeerCheckpointPatch{peerID: patch}); err != nil {
		return err
	}
	driver.observeSyncAttempt(peerID, now)
	return nil
}

func (driver *GossipDriver) isGossipBootstrapPeer(peerID string) bool {
	driver.mu.RLock()
	defer driver.mu.RUnlock()
	discovery := driver.gossipConfig.Discovery
	_, resolved := discovery.Bootstrap[peerID]
	return resolved || slices.Contains(discovery.BootstrapPeers, peerID)
}

func applyGossipCompletionCheckpoint(peer *corestate.PeerCheckpoint, syncErr error, pingTimeout bool, now time.Time) bool {
	previous := *peer
	if syncErr != nil {
		code, maxFailures, limit := corestate.PeerFailureUnknown, 6, 64*time.Second
		if pingTimeout {
			code, maxFailures, limit = corestate.PeerFailurePingTimeout, 9, 5*time.Minute
		}
		if wasPingTimeout := peer.LastFailure != nil && peer.LastFailure.Code == corestate.PeerFailurePingTimeout; wasPingTimeout != pingTimeout {
			peer.FailureCount = 0
		}
		peer.FailureCount++
		backoff := min(time.Duration(1<<min(max(peer.FailureCount, 0), maxFailures))*time.Second, limit)
		peer.BackoffUntilUnix = now.Add(backoff).Unix()
		peer.LastFailure = &corestate.PeerFailure{Code: code, Message: syncErr.Error(), AtUnix: now.Unix()}
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
