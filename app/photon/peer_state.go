package main

import (
	"sort"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func peerLifecycleInput(network *zone.NetworkState, checkpoint *corestate.GossipCheckpoint, links map[string]linkInstanceState, reconcile *ipsecObservationSummary, peerID string, peerZone zone.ZonePath, now time.Time, cfg inspect.PeerLifecycleConfig, hasOverlayConfig bool) inspect.PeerLifecycleInput {
	input := inspect.PeerLifecycleInput{
		PeerID:           peerID,
		PeerZone:         peerZone,
		StateAvailable:   true,
		HasOverlayConfig: hasOverlayConfig,
		Now:              now,
		Config:           cfg,
	}
	var ps corestate.PeerCheckpoint
	if checkpoint != nil {
		ps = checkpoint.Peers[peerID]
	}
	input.LastSyncUnix = ps.LastSyncUnix
	input.ObservedLastSeenUnix = ps.ObservedLastSeenUnix
	input.HasIPsecConfig = reconcile != nil && reconcile.DesiredLinks > 0
	if network != nil {
		input.PeerZoneKnown = network.Zones[peerZone] != nil
		input.ZoneRevoked = network.IsZoneRevoked(peerZone, now)
		if peerZoneState := network.Zones[peerZone]; peerZoneState != nil {
			input.PeerHasIPsecRecords = hasPeerIPsecRecords(peerZoneState)
		}
	}
	for _, inst := range links {
		if inst.PeerZone != peerZone {
			continue
		}
		input.ActualLinks++
		if inst.ActualState == "up" {
			input.UpLinks++
		}
		if inst.LastTransition > input.LastTransitionUnix {
			input.LastTransitionUnix = inst.LastTransition
		}
	}
	if rec := reconcile; rec != nil {
		for _, d := range rec.Desired {
			if d.PeerZone == peerZone {
				input.DesiredLinks++
			}
		}
		for _, skip := range rec.Skipped {
			if skip.Peer == peerZone {
				input.PolicyDeniedReason = skip.Reason
				input.PolicyDeniedDetail = skip.Detail
				break
			}
		}
	}
	return input
}

// derivePeerStatuses computes status for all known peers from the common
// checkpoint plus Linux link observations. The result is sorted by peer id
// for stable output.
func derivePeerStatuses(managedZone zone.ZonePath, network *zone.NetworkState, checkpoint *corestate.GossipCheckpoint, links map[string]linkInstanceState, reconcile *ipsecObservationSummary, now time.Time, cfg inspect.PeerLifecycleConfig, hasOverlayConfig bool) []inspect.PeerStatusInfo {
	seen := make(map[string]bool)
	var out []inspect.PeerStatusInfo

	// Gather all candidate peers: checkpoint peers, LinkInstances peer zones,
	// desired link peer zones, and active state zones with IPsec records.
	addPeer := func(peerID string, peerZone zone.ZonePath) {
		if peerID == "" || seen[peerID] {
			return
		}
		seen[peerID] = true
		info := inspect.BuildPeerLifecycleStatus(peerLifecycleInput(network, checkpoint, links, reconcile, peerID, peerZone, now, cfg, hasOverlayConfig))
		out = append(out, info)
	}

	if checkpoint != nil {
		for peerID := range checkpoint.Peers {
			// Derive zone from peer id: peer id is typically the zone FQDN.
			addPeer(peerID, zone.ZonePath(peerID))
		}
	}
	for _, inst := range links {
		addPeer(string(inst.PeerZone), inst.PeerZone)
	}
	if rec := reconcile; rec != nil {
		for _, d := range rec.Desired {
			addPeer(string(d.PeerZone), d.PeerZone)
		}
		for _, skip := range rec.Skipped {
			addPeer(string(skip.Peer), skip.Peer)
		}
	}
	// Scan active state for zones that have ipsec profile records but aren't
	// in the checkpoint yet (eligible peers discovered via gossip).
	if network != nil {
		for z, zs := range network.Zones {
			if z == managedZone || z.IsRoot() {
				continue
			}
			if hasPeerIPsecRecords(zs) {
				addPeer(string(z), z)
			}
		}
	}

	sort.SliceStable(out, func(i, j int) bool {
		return inspect.ZonePathLess(out[i].PeerID, out[j].PeerID)
	})
	return out
}

// hasPeerIPsecRecords checks if a zone has any ipsec/* records published.
func hasPeerIPsecRecords(zs *zone.ZoneState) bool {
	if zs == nil || zs.Records == nil {
		return false
	}
	for key := range zs.Records {
		if len(key) >= 6 && key[:6] == "ipsec/" {
			return true
		}
	}
	return false
}

// collectRevokedPeerZones returns the set of peer zones that are currently
// revoked, expanded from LinkInstances and gossip checkpoint peers. This is used to feed
// the revoked set into IPsec/routing/firewall reconcile.
func collectRevokedPeerZones(network *zone.NetworkState, instances map[string]linkInstanceState, checkpoint *corestate.GossipCheckpoint, now time.Time) map[zone.ZonePath]bool {
	out := make(map[zone.ZonePath]bool)
	if network == nil {
		return out
	}
	for _, inst := range instances {
		if network.IsZoneRevoked(inst.PeerZone, now) {
			out[inst.PeerZone] = true
		}
	}
	if checkpoint != nil {
		for peerID := range checkpoint.Peers {
			zp := zone.ZonePath(peerID)
			if network.IsZoneRevoked(zp, now) {
				out[zp] = true
			}
		}
	}
	return out
}
