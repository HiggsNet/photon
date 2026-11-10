package photonwindows

import (
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
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
		for id, peer := range view.Gossip.Peers {
			if path := zone.ZonePath(id); peer.LastSuccessfulEndpoint != "" && view.State != nil &&
				path != view.State.ManagedZone && photoncrypto.VerifyChain(view.State.Network, path, now) == nil {
				add(peer.LastSuccessfulEndpoint)
			}
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
