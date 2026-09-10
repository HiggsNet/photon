package main

import (
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const peerCleanupReasonOffline = "cleanup_after_exceeded"

func peerLifecycleLastActiveUnix(peer corestate.PeerCheckpoint) int64 {
	lastActive := peer.LastSyncUnix
	if peer.ObservedLastSeenUnix > 0 && peer.ObservedLastSeenUnix > lastActive {
		lastActive = peer.ObservedLastSeenUnix
	}
	return lastActive
}

func peerLifecycleCleanupDue(peer corestate.PeerCheckpoint, now time.Time, cfg inspect.PeerLifecycleConfig) bool {
	lastActive := peerLifecycleLastActiveUnix(peer)
	if lastActive == 0 {
		return false
	}
	cfg = inspect.NormalizePeerLifecycleConfig(cfg)
	return !now.Before(time.Unix(lastActive, 0).Add(cfg.CleanupAfter))
}

// peerLifecycleExcludedPeers returns local data-plane suppressions. An offline
// peer remains available to gossip so a successful sync can refresh its
// checkpoint, but IPsec must not recreate its link from stale Zone records.
func peerLifecycleExcludedPeers(checkpoint *corestate.GossipCheckpoint, now time.Time, cfg inspect.PeerLifecycleConfig) map[zone.ZonePath]string {
	out := make(map[zone.ZonePath]string)
	if checkpoint != nil {
		for peerID, peer := range checkpoint.Peers {
			if peerLifecycleCleanupDue(peer, now, cfg) {
				out[zone.ZonePath(peerID)] = peerCleanupReasonOffline
			}
		}
	}
	return out
}

func peerLifecycleSuppressions(network *zone.NetworkState, checkpoint *corestate.GossipCheckpoint, now time.Time, cfg inspect.PeerLifecycleConfig) map[string]bool {
	suppressed := make(map[string]bool)
	for path := range collectAllRevokedZones(network, now) {
		suppressed[path.String()] = true
	}
	if checkpoint != nil {
		for peerID, peer := range checkpoint.Peers {
			if peerLifecycleCleanupDue(peer, now, cfg) {
				suppressed[peerID] = true
			}
		}
	}
	return suppressed
}
