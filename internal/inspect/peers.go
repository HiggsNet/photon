package inspect

import (
	"sort"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// PeerStatusInfo is the derived runtime status view for a peer. Producers
// compute it from committed state and runtime observations; presenters render
// it without depending on app-private stateFile internals.
type PeerStatusInfo struct {
	PeerID            string        `json:"peer_id"`
	Zone              zone.ZonePath `json:"zone"`
	State             string        `json:"state"`
	Reason            string        `json:"reason,omitempty"`
	Detail            string        `json:"detail,omitempty"`
	LastSeenUnix      int64         `json:"last_seen_unix,omitempty"`
	LastSyncUnix      int64         `json:"last_sync_unix,omitempty"`
	LastEndpointUnix  int64         `json:"last_endpoint_change_unix,omitempty"`
	LastReconcileUnix int64         `json:"last_reconcile_unix,omitempty"`
	DesiredLinks      int           `json:"desired_links,omitempty"`
	ActualLinks       int           `json:"actual_links,omitempty"`
	UpLinks           int           `json:"up_links,omitempty"`
	OfflineSinceUnix  int64         `json:"offline_since_unix,omitempty"`
	NextCleanupUnix   int64         `json:"next_cleanup_unix,omitempty"`
}

func ZonePathLess(a, b string) bool { return zone.ComparePaths(a, b) < 0 }

func SortZoneStrings(paths []string) {
	sort.SliceStable(paths, func(i, j int) bool {
		return ZonePathLess(paths[i], paths[j])
	})
}

func SortZonePaths(paths []zone.ZonePath) {
	sort.SliceStable(paths, func(i, j int) bool {
		return ZonePathLess(string(paths[i]), string(paths[j]))
	})
}
