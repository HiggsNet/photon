package main

import (
	"slices"
	"sort"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// ComputeRevocationImpact computes the full impact of a revocation on the
// local daemon's runtime state. It is a pure function that reads from verified
// active state and local runtime state; it does not mutate anything.
//
// The impact includes:
//   - The revoked zone and its descendant subtree (zones under the revoked path)
//   - LinkInstances whose peer zone is in the subtree
//   - Gossip checkpoint entries whose peer ID maps to a revoked zone
//   - Bootstrap peers that are configured but now revoked
//   - IPAM prefixes assigned to revoked zones (from route authorization errors)
func ComputeRevocationImpact(network *zone.NetworkState, links map[string]linkInstanceState, checkpoint *corestate.GossipCheckpoint, revokedZone zone.ZonePath, now time.Time) inspect.RevocationImpact {
	impact := inspect.RevocationImpact{
		RevokedZone: revokedZone,
		Layers:      make(map[string]*inspect.RevocationLayerStatus),
	}
	if network == nil || !revokedZone.Valid() {
		return impact
	}

	// Determine source zone from active revocation.
	if rev := network.ActiveRevocation(revokedZone, now); rev != nil {
		impact.SourceZone = rev.ParentZone
	}

	// Compute descendant subtree: any zone whose path has revokedZone as a
	// strict prefix.
	impact.RevokedSubtree = computeRevokedSubtree(network, revokedZone, now)

	// Build a set for fast lookup: revokedZone + all descendants.
	revokedSet := make(map[zone.ZonePath]bool, len(impact.RevokedSubtree)+1)
	revokedSet[revokedZone] = true
	for _, z := range impact.RevokedSubtree {
		revokedSet[z] = true
	}

	// Affected LinkInstances.
	for id, inst := range links {
		if revokedSet[inst.PeerZone] {
			impact.AffectedLinkInstances = append(impact.AffectedLinkInstances, id)
		}
	}
	sort.Strings(impact.AffectedLinkInstances)

	// Affected gossip checkpoint peers.
	if checkpoint != nil {
		for peerID := range checkpoint.Peers {
			zp := zone.ZonePath(peerID)
			if revokedSet[zp] {
				impact.AffectedSyncPeers = append(impact.AffectedSyncPeers, peerID)
			}
		}
	}
	inspect.SortZoneStrings(impact.AffectedSyncPeers)

	// Initialize all layer statuses as pending.
	for _, layer := range []string{inspect.RevocationLayerIPsec, inspect.RevocationLayerRouting, inspect.RevocationLayerFirewall, inspect.RevocationLayerGossip} {
		impact.Layers[layer] = &inspect.RevocationLayerStatus{Status: inspect.RevocationStatusPending}
	}

	return impact
}

// computeRevokedSubtree returns all descendant zones of revokedZone that exist
// in the active state. A descendant is any zone path that starts with
// revokedZone as a parent prefix. The revoked zone itself is not included in
// the result (only strict descendants).
func computeRevokedSubtree(ns *zone.NetworkState, revokedZone zone.ZonePath, _ time.Time) []zone.ZonePath {
	if ns == nil || !revokedZone.Valid() {
		return nil
	}
	var out []zone.ZonePath
	for z := range ns.Zones {
		if z == revokedZone || z.IsRoot() {
			continue
		}
		// Check if z is a descendant of revokedZone: revokedZone must appear
		// in z's ancestor chain (excluding z itself).
		isDescendant := false
		for _, ancestor := range z.Ancestors() {
			if ancestor == z {
				continue
			}
			if ancestor == revokedZone {
				isDescendant = true
				break
			}
		}
		if isDescendant {
			out = append(out, z)
		}
	}
	inspect.SortZonePaths(out)
	return out
}

// isConfiguredBootstrapPeerWithConfig checks if a peer ID appears in the
// bootstrap config. This is the config-aware version called by the daemon.
func isConfiguredBootstrapPeerWithConfig(config *gossipStartupConfig, peerID string) bool {
	if config == nil {
		return false
	}
	for _, peer := range config.Bootstrap {
		if peer.ID == peerID {
			return true
		}
	}
	return false
}

// peerNeedsRevocationCleanup reports whether the typed checkpoint cleanup
// would change the runtime-owned fields of one peer.
func peerNeedsRevocationCleanup(peer corestate.PeerCheckpoint) bool {
	return peer.DiscoveredEndpoint != "" ||
		peer.DiscoveredAtUnix != 0 ||
		peer.ObservedEndpoint != "" ||
		peer.ObservedFirstSeenUnix != 0 ||
		peer.ObservedLastSeenUnix != 0 ||
		peer.ObservedLastSyncUnix != 0 ||
		peer.ObservedUntilUnix != 0 ||
		peer.ObservedFailureCount != 0 ||
		peer.ObservedGraceEndpoints != nil ||
		peer.BackoffUntilUnix != 0 ||
		peer.FailureCount != 0 ||
		peer.LastFailure == nil ||
		peer.LastFailure.Code != corestate.PeerFailureLegacy ||
		peer.LastFailure.Message != "zone revoked"
}

func collectAllRevokedZones(network *zone.NetworkState, now time.Time) map[zone.ZonePath]bool {
	out := make(map[zone.ZonePath]bool)
	if network == nil {
		return out
	}
	for z := range network.Zones {
		if z.IsRoot() {
			continue
		}
		if network.IsZoneRevoked(z, now) {
			out[z] = true
		}
	}
	return out
}

// purgePlan describes the local state that a manual revoked-zone GC would
// remove. It is computed without mutating state so the CLI can print a dry-run
// preview and reuse the same logic when applying.
type purgePlan struct {
	// Zones are the revoked zone paths whose ZoneState bodies will be deleted
	// from Network.Zones, sorted ascending. Includes descendant subtrees.
	Zones []zone.ZonePath `json:"zones,omitempty"`
	// LinkInstances lists LinkInstance IDs whose PeerZone is in Zones.
	LinkInstances []string `json:"link_instances,omitempty"`
	// SyncPeers lists peer IDs (zone FQDNs) whose SyncPeers entries are removed.
	SyncPeers []string `json:"sync_peers,omitempty"`
	// ManagedZoneSkipped lists revoked zones excluded because they are the
	// local node's ManagedZone or one of its ancestors.
	// Reported for transparency; never deleted.
	ManagedZoneSkipped []zone.ZonePath `json:"managed_zone_skipped,omitempty"`
}

func mergePurgePlan(common corestate.PurgeRevokedPlan, links map[string]linkInstanceState) *purgePlan {
	plan := &purgePlan{
		Zones:              append([]zone.ZonePath(nil), common.Zones...),
		SyncPeers:          append([]string(nil), common.CheckpointPeers...),
		ManagedZoneSkipped: append([]zone.ZonePath(nil), common.ManagedZoneSkipped...),
	}
	zoneSet := make(map[zone.ZonePath]bool, len(plan.Zones))
	for _, path := range plan.Zones {
		zoneSet[path] = true
	}
	for id, instance := range links {
		if zoneSet[instance.PeerZone] {
			plan.LinkInstances = append(plan.LinkInstances, id)
		}
	}
	slices.Sort(plan.LinkInstances)
	return plan
}

// AllRevocationImpact computes impact for all currently-revoked zones and
// returns a combined result for debug/diagnostic output.
func AllRevocationImpact(network *zone.NetworkState, links map[string]linkInstanceState, checkpoint *corestate.GossipCheckpoint, config *gossipStartupConfig, now time.Time) []inspect.RevocationImpact {
	if network == nil {
		return nil
	}
	revokedZones := collectAllRevokedZones(network, now)
	if len(revokedZones) == 0 {
		return nil
	}
	// Sort for stable output.
	zones := make([]zone.ZonePath, 0, len(revokedZones))
	for z := range revokedZones {
		zones = append(zones, z)
	}
	inspect.SortZonePaths(zones)
	var out []inspect.RevocationImpact
	for _, z := range zones {
		impact := ComputeRevocationImpact(network, links, checkpoint, z, now)
		// Supplement configured_but_revoked with actual config.
		if config != nil {
			if isConfiguredBootstrapPeerWithConfig(config, string(z)) {
				impact.ConfiguredButRevoked = appendIfMissing(impact.ConfiguredButRevoked, string(z))
			}
			for _, sub := range impact.RevokedSubtree {
				if isConfiguredBootstrapPeerWithConfig(config, string(sub)) {
					impact.ConfiguredButRevoked = appendIfMissing(impact.ConfiguredButRevoked, string(sub))
				}
			}
			inspect.SortZoneStrings(impact.ConfiguredButRevoked)
		}
		out = append(out, impact)
	}
	return out
}

func appendIfMissing(slice []string, val string) []string {
	if slices.Contains(slice, val) {
		return slice
	}
	return append(slice, val)
}
