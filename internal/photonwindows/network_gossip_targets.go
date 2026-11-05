package photonwindows

import (
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// Reachability hints only. Tracking a public path never authorizes its peer.
// Read from the planner's detached view; do not read/clone state on packet I/O.
func gossipRouteTargets(view corestate.View, now time.Time) []netip.Addr {
	var addresses []netip.Addr
	add := func(endpoint string) {
		if value, err := netip.ParseAddrPort(endpoint); err == nil {
			addresses = append(addresses, value.Addr().Unmap())
		}
	}
	if view.State != nil && view.State.Network != nil {
		for _, entries := range gossip.ExtractPeerEndpointsAt(view.State.Network, now) {
			for _, entry := range entries {
				if value, err := netip.ParseAddr(entry.Address); err == nil {
					addresses = append(addresses, value.Unmap())
				}
			}
		}
	}
	if view.Gossip != nil {
		for _, peer := range view.Gossip.Peers {
			add(peer.DiscoveredEndpoint)
			if peer.ObservedUntilUnix > now.Unix() {
				add(peer.ObservedEndpoint)
			}
			for _, grace := range peer.ObservedGraceEndpoints {
				if grace.UntilUnix > now.Unix() {
					add(grace.Endpoint)
				}
			}
		}
	}
	return addresses
}
