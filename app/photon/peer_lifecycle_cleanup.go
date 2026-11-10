package main

import (
	"maps"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const peerCleanupReasonOffline = "cleanup_after_exceeded"

// tunnelPeerActivity is daemon-loop state. A peer without any activity gets
// a full observation window when its tunnel records first become known.
type tunnelPeerActivity struct {
	firstTracked          time.Time
	suspendedLastActivity int64
}

func peerLifecycleLastActiveUnix(peer corestate.PeerCheckpoint) int64 {
	return max(peer.LastSyncUnix, peer.ObservedLastSeenUnix)
}

func (d *Daemon) reconcileTunnelPeerSuspensions(common corestate.View, runtime *photonlinux.LinuxState, now time.Time) error {
	suspended := maps.Clone(runtime.SuspendedTunnelPeers)
	if suspended == nil {
		suspended = make(map[zone.ZonePath]bool)
	}
	tracked := make(map[zone.ZonePath]tunnelPeerActivity)
	network := common.State.Network
	cfg := inspect.NormalizePeerLifecycleConfig(d.Config.PeerLifecycle)
	for peerID, peerZone := range network.Zones {
		if peerZone == nil || peerID == common.State.ManagedZone || peerID.IsRoot() || network.IsZoneRevoked(peerID, now) || !hasPeerIPsecRecords(peerZone) {
			continue
		}
		activity := d.tunnelPeerActivity[peerID]
		if activity.firstTracked.IsZero() {
			activity.firstTracked = now
		}
		lastActive := int64(0)
		if common.Gossip != nil {
			lastActive = peerLifecycleLastActiveUnix(common.Gossip.Peers[peerID.String()])
		}
		if suspended[peerID] {
			// Only new activity clears a suspension. Merely changing the
			// inactivity threshold does not constitute activity.
			if lastActive > activity.suspendedLastActivity {
				delete(suspended, peerID)
				activity.suspendedLastActivity = 0
			}
		} else {
			lastSeen := activity.firstTracked
			if lastActive != 0 {
				lastSeen = time.Unix(lastActive, 0)
			}
			if !now.Before(lastSeen.Add(cfg.CleanupAfter)) {
				suspended[peerID] = true
				activity.suspendedLastActivity = lastActive
			}
		}
		tracked[peerID] = activity
	}
	for peerID := range suspended {
		if _, ok := tracked[peerID]; !ok {
			delete(suspended, peerID)
		}
	}
	if !maps.Equal(runtime.SuspendedTunnelPeers, suspended) {
		if len(suspended) == 0 {
			suspended = nil
		}
		if _, err := d.State.updateLinuxStateIfRevision(common.Revision, func(candidate *photonlinux.LinuxState) {
			candidate.SuspendedTunnelPeers = suspended
		}); err != nil {
			return err
		}
		runtime.SuspendedTunnelPeers = suspended
	}
	d.tunnelPeerActivity = tracked
	return nil
}

func peerLifecycleExcludedPeers(suspended map[zone.ZonePath]bool) map[zone.ZonePath]string {
	excluded := make(map[zone.ZonePath]string, len(suspended))
	for peerID, active := range suspended {
		if active {
			excluded[peerID] = peerCleanupReasonOffline
		}
	}
	return excluded
}
