package photonwindows

import (
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// lookupBabelRoutes is called by the active tunnel owner at packet use time.
// The candidate planner's revision must still be current, and expiration is
// rechecked even if no gossip revision changed. source is the exact local host
// on outbound packets and the original local destination on inbound packets.
// The pipeline additionally pins this address to its actual device addresses.
func (t *gatewayTunnel) lookupBabelRoutes(config *Config, view corestate.View, plan GatewayPlan, planned corestate.VerifiedRevision, candidates []sadr.Route, source, destination netip.Addr, now time.Time) []sadr.Route {
	if config == nil || t == nil || t.phase != 3 || t.session == nil || t.data == nil || t.data.active == nil || t.failed != nil || view.Revision != planned || !now.Before(t.ikeExpiresAt) || !now.Before(t.expiresAt) {
		return nil
	}
	binding, err := localTransportAuthorization(config, view, now)
	if err != nil || binding != t.localAuthorization {
		return nil
	}
	current := revalidateActiveGateway(config, view, plan, now)
	if !t.current(current) || !t.data.current(t.generation, t.data.active, current) {
		return nil
	}
	hosts, _ := leafDeviceIntent(config, view, now)
	local := false
	for _, host := range hosts {
		local = local || host.Addr() == source
	}
	if !local {
		return nil
	}
	return sadr.Lookup(candidates, source, destination, now, currentBabelRouteAuthorizer(config, view, now))
}

func currentBabelRouteAuthorizer(config *Config, view corestate.View, now time.Time) func(sadr.Route) bool {
	authorized := authorizedGatewayRoutes(config, view, now)
	var hosts []netip.Prefix
	if config != nil {
		hosts, _ = leafDeviceIntent(config, view, now)
	}
	return babelRouteAuthorizer(authorized, hosts)
}

// The authenticated gateway supplies reachability. Signed Photon records
// authorize destination prefixes; Babel Router IDs are protocol state, not
// identity credentials, and need no routing/babel/identities binding.
func babelRouteAuthorizer(authorized []AuthorizedGatewayRoute, hosts []netip.Prefix) func(sadr.Route) bool {
	return func(route sadr.Route) bool {
		if route.Source.IsValid() {
			// A source prefix only narrows local-host use of an independently
			// authorized destination. It neither assigns source addresses nor
			// permits forwarding. The remote destination owner need not own the
			// source pool; require at least one current nonshared local host.
			source := route.Source
			if source.Bits() == 0 || source != source.Masked() || source.Addr().Is4In6() || source.Addr().Zone() != "" || source.Addr().BitLen() != route.Destination.Addr().BitLen() {
				return false
			}
			matched := false
			for _, host := range hosts {
				matched = matched || source.Contains(host.Addr())
			}
			if !matched {
				return false
			}
		}
		for _, permission := range authorized {
			if permission.Prefix == route.Destination {
				return true
			}
		}
		return false
	}
}
