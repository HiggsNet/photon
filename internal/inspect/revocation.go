package inspect

import "github.com/HiggsNet/photon/pkg/core/zone"

// RevocationImpact describes the set of objects affected by a revocation.
type RevocationImpact struct {
	// RevokedZone is the zone whose delegation was revoked by its parent.
	RevokedZone zone.ZonePath `json:"revoked_zone"`
	// SourceZone is the parent zone that issued the revocation/tombstone.
	SourceZone zone.ZonePath `json:"source_zone"`
	// RevokedSubtree lists all descendant zones of RevokedZone that are
	// transitively affected by this revocation.
	RevokedSubtree []zone.ZonePath `json:"revoked_subtree,omitempty"`
	// AffectedLinkInstances lists LinkInstance IDs whose peer zone is in the
	// revoked subtree.
	AffectedLinkInstances []string `json:"affected_link_instances,omitempty"`
	// AffectedSyncPeers lists peer IDs whose entries should be cleaned or
	// marked as revoked.
	AffectedSyncPeers []string `json:"affected_sync_peers,omitempty"`
	// ConfiguredButRevoked lists bootstrap peer IDs that are still in local
	// config but are now revoked.
	ConfiguredButRevoked []string `json:"configured_but_revoked,omitempty"`
	// AffectedIPAMPrefixes lists authorized prefixes that belong to revoked
	// zones and will be removed from routing/firewall allow sets.
	AffectedIPAMPrefixes []string `json:"affected_ipam_prefixes,omitempty"`
	// Layers tracks per-layer cleanup status.
	Layers map[string]*RevocationLayerStatus `json:"layers,omitempty"`
}

// RevocationLayerStatus tracks the cleanup status for a single subsystem.
type RevocationLayerStatus struct {
	Status   string       `json:"status"`            // pending, removed, not_found, owner_conflict, error
	Failure  *FailureView `json:"failure,omitempty"` // populated when Status == "error"
	Reason   string       `json:"reason,omitempty"`  // human-readable detail
	UnixTime int64        `json:"unix_time,omitempty"`
}

const (
	RevocationLayerIPsec    = "ipsec_xfrm"
	RevocationLayerRouting  = "routing_bird"
	RevocationLayerFirewall = "firewall"
	RevocationLayerGossip   = "gossip_peer_cache"
)

const (
	RevocationStatusPending       = "pending"
	RevocationStatusRemoved       = "removed"
	RevocationStatusNotFound      = "not_found"
	RevocationStatusOwnerConflict = "owner_conflict"
	RevocationStatusError         = "error"
)

func RevocationLayerOrder() []string {
	return []string{
		RevocationLayerFirewall,
		RevocationLayerRouting,
		RevocationLayerIPsec,
		RevocationLayerGossip,
	}
}

// HasPendingCleanup returns true if any layer in the impact is still pending.
func (impact *RevocationImpact) HasPendingCleanup() bool {
	if impact == nil || impact.Layers == nil {
		return false
	}
	for _, s := range impact.Layers {
		if s != nil && s.Status == RevocationStatusPending {
			return true
		}
	}
	return false
}
