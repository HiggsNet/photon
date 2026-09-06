package main

import (
	"context"
	"sort"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	peerCleanupReasonOffline = "cleanup_after_exceeded"
	peerCleanupReasonRevoked = "zone_revoked"
)

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

// peerLifecycleExcludedPeers returns local data-plane suppressions. A marked
// peer remains available to gossip so a successful sync can clear the marker,
// but IPsec must not recreate its owner-managed link from stale Zone records.
func peerLifecycleExcludedPeers(cleanups map[string]peerLifecycleCleanupState, checkpoint *corestate.GossipCheckpoint, now time.Time, cfg inspect.PeerLifecycleConfig) map[zone.ZonePath]string {
	out := make(map[zone.ZonePath]string)
	for peerID, cleanup := range cleanups {
		if cleanup.Reason == peerCleanupReasonOffline {
			out[zone.ZonePath(peerID)] = peerCleanupReasonOffline
		}
	}
	if checkpoint != nil {
		for peerID, peer := range checkpoint.Peers {
			if peerLifecycleCleanupDue(peer, now, cfg) {
				out[zone.ZonePath(peerID)] = peerCleanupReasonOffline
			}
		}
	}
	return out
}

// applyPeerLifecycleCleanup mutates an owner-provided workspace. peers and
// cleanups must be initialized maps so changes remain visible to the caller.
// Revoked peers retain diagnostics for one cleanup_after window; offline peers
// are removed immediately and receive a local data-plane suppression marker.
func applyPeerLifecycleCleanup(network *zone.NetworkState, peers map[string]corestate.PeerCheckpoint, cleanups map[string]peerLifecycleCleanupState, now time.Time, cfg inspect.PeerLifecycleConfig) (removed []string, changed bool) {
	if peers == nil {
		peers = make(map[string]corestate.PeerCheckpoint)
	}
	if cleanups == nil {
		return nil, false
	}
	cfg = inspect.NormalizePeerLifecycleConfig(cfg)
	revoked := collectAllRevokedZones(network, now)

	for peerID, cleanup := range cleanups {
		peer, exists := peers[peerID]
		switch cleanup.Reason {
		case peerCleanupReasonRevoked:
			if !revoked[zone.ZonePath(peerID)] {
				delete(cleanups, peerID)
				changed = true
				continue
			}
			if cleanup.CleanupUnix <= 0 {
				cleanup.CleanupUnix = now.Unix()
				cleanups[peerID] = cleanup
				changed = true
				continue
			}
			if now.Before(time.Unix(cleanup.CleanupUnix, 0).Add(cfg.CleanupAfter)) {
				continue
			}
			if exists {
				delete(peers, peerID)
				removed = append(removed, peerID)
			}
			delete(cleanups, peerID)
			changed = true
		case peerCleanupReasonOffline:
			if exists && peer.LastSyncUnix > cleanup.LastActiveUnix {
				delete(cleanups, peerID)
				changed = true
				continue
			}
			if exists {
				delete(peers, peerID)
				removed = append(removed, peerID)
				changed = true
			}
		default:
			delete(cleanups, peerID)
			changed = true
		}
	}

	for peerID, peer := range peers {
		if _, marked := cleanups[peerID]; marked {
			continue
		}
		lastActive := peerLifecycleLastActiveUnix(peer)
		if revoked[zone.ZonePath(peerID)] {
			cleanups[peerID] = peerLifecycleCleanupState{
				LastActiveUnix: lastActive,
				CleanupUnix:    now.Unix(),
				Reason:         peerCleanupReasonRevoked,
			}
			changed = true
			continue
		}
		if !peerLifecycleCleanupDue(peer, now, cfg) {
			continue
		}
		cleanups[peerID] = peerLifecycleCleanupState{
			LastActiveUnix: lastActive,
			CleanupUnix:    now.Unix(),
			Reason:         peerCleanupReasonOffline,
		}
		delete(peers, peerID)
		removed = append(removed, peerID)
		changed = true
	}
	sort.Strings(removed)
	return removed, changed
}

func (d *Daemon) flushPeerLifecycleCleanup() bool {
	if d == nil || d.StateStore == nil || d.currentGossipConfig() == nil {
		return false
	}
	cfg := inspect.PeerLifecycleConfig{}
	if d.App != nil && d.App.Config != nil {
		cfg = d.App.Config.PeerLifecycle
	}
	now := d.now()
	d.StateStore.writeMu.Lock()
	view := d.StateStore.common.ReadView()
	d.StateStore.mu.RLock()
	cleanups := photonstate.ClonePeerLifecycleCleanups(d.StateStore.runtime.PeerCleanups)
	d.StateStore.mu.RUnlock()
	d.StateStore.writeMu.Unlock()
	if view.State == nil {
		return false
	}
	if cleanups == nil {
		cleanups = make(map[string]peerLifecycleCleanupState)
	}
	var peers map[string]corestate.PeerCheckpoint
	if view.Gossip != nil {
		peers = view.Gossip.Peers
	}
	removed, changed := applyPeerLifecycleCleanup(view.State.Network, peers, cleanups, now, cfg)
	if !changed {
		return false
	}
	if _, _, err := d.StateStore.commitRuntimeIfRevision(uint64(view.Revision), func(candidate *linuxRuntimeState) {
		candidate.PeerCleanups = photonstate.ClonePeerLifecycleCleanups(cleanups)
	}); err != nil {
		d.logWarn("peer_lifecycle", "cleanup_commit_failed", map[string]any{"error": err})
		return false
	}
	if _, err := d.StateStore.common.DeletePeerCheckpoints(context.Background(), removed); err != nil {
		d.logWarn("peer_lifecycle", "checkpoint_cleanup_failed", map[string]any{"error": err})
		return false
	}
	for _, peerID := range removed {
		if d.gossipDriver != nil && d.gossipDriver.Observability != nil {
			d.gossipDriver.Observability.Delete(peerID)
		}
	}
	d.logInfo("peer_lifecycle", "cleanup_applied", map[string]any{"peers": removed})
	return true
}
