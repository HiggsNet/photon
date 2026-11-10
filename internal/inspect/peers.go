package inspect

import (
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"sort"
	"time"
)

type PeerSignedEndpoint struct {
	Address      string
	Port         uint16
	Protocol     string
	Scope        string
	Source       string
	Priority     int
	LastObserved int64
}

type EndpointDebugView struct {
	ManagedPeerID string
	Peers         []EndpointPeerView
}

type EndpointPeerView struct {
	PeerID    string
	Endpoints []PeerSignedEndpoint
}

func BuildEndpointDebug(state *corestate.VerifiedState, now time.Time) EndpointDebugView {
	view := EndpointDebugView{}
	if state == nil || state.Network == nil {
		return view
	}
	view.ManagedPeerID = string(state.ManagedZone)
	discovered := gossip.ExtractPeerEndpointsAt(state.Network, now)
	peerIDs := make([]string, 0, len(discovered))
	for peerID := range discovered {
		peerIDs = append(peerIDs, peerID)
	}
	SortZoneStrings(peerIDs)
	for _, peerID := range peerIDs {
		signed := discovered[peerID]
		endpoints := make([]PeerSignedEndpoint, 0, len(signed))
		for _, endpoint := range signed {
			endpoints = append(endpoints, PeerSignedEndpoint{
				Address: endpoint.Address, Port: endpoint.Port, Scope: endpoint.Scope,
				Priority: endpoint.Priority, Protocol: endpoint.Protocol, Source: endpoint.Source,
				LastObserved: endpoint.LastObserved,
			})
		}
		sort.SliceStable(endpoints, func(i, j int) bool {
			return signedEndpointLess(endpoints[i], endpoints[j])
		})
		view.Peers = append(view.Peers, EndpointPeerView{
			PeerID:    peerID,
			Endpoints: endpoints,
		})
	}
	return view
}

func signedEndpointLess(a, b PeerSignedEndpoint) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if a.LastObserved != b.LastObserved {
		return a.LastObserved > b.LastObserved
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if a.Scope != b.Scope {
		return a.Scope < b.Scope
	}
	if a.Address != b.Address {
		return a.Address < b.Address
	}
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	return a.Protocol < b.Protocol
}

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
