package photonwindows

import (
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
)

// currentBabelOrigins derives no origin from a next hop or BIRD's low 32 bits.
// Every binding is a current signed assertion for the exact 64-bit Router ID.
// Collisions between zones invalidate every claimant, independent of map order.
// This authenticates the ID claim, not a forwarded Babel Update: a gateway can
// still impersonate a published ID. The leaf therefore remains experimental
// with an explicitly trusted gateway until Update origin proofs exist.
func currentBabelOrigins(config *Config, view corestate.View, now time.Time) map[[8]byte]zone.ZonePath {
	result := make(map[[8]byte]zone.ZonePath)
	if config == nil || view.State == nil || view.State.Network == nil || photoncrypto.VerifyPinnedRoot(view.State.Network, config.TrustedRootPublicKey) != nil {
		return result
	}
	conflicts := make(map[[8]byte]bool)
	for path, zs := range view.State.Network.Zones {
		if zs == nil || photoncrypto.VerifyChain(view.State.Network, path, now) != nil {
			continue
		}
		record := zs.Records[routing.RecordKeyBabelIdentity]
		if record == nil || record.Zone != path || photoncrypto.VerifyRecord(record, zs.Authority, now) != nil {
			continue
		}
		value, err := routing.ParseBabelIdentityRecord(record, now)
		if err != nil {
			continue
		}
		ids, _ := value.IDs()
		for _, id := range ids {
			if old, ok := result[id]; ok && old != path {
				conflicts[id] = true
			}
			result[id] = path
		}
	}
	for id := range conflicts {
		delete(result, id)
	}
	return result
}

// lookupBabelRoutes is called by the active tunnel owner at packet use time.
// The candidate planner's revision must still be current, and expiration is
// rechecked even if no gossip revision changed. Source-constrained routes remain
// denied until a separate source-prefix authorization contract is implemented.
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
	return sadr.Lookup(candidates, source, destination, now, currentBabelRouteAuthorizer(config, view, now))
}

func currentBabelRouteAuthorizer(config *Config, view corestate.View, now time.Time) func(sadr.Route) bool {
	origins := currentBabelOrigins(config, view, now)
	authorized := authorizedGatewayRoutes(config, view, now)
	return func(route sadr.Route) bool {
		if route.Source.IsValid() {
			return false
		}
		origin, ok := origins[route.RouterID]
		if !ok {
			return false
		}
		for _, permission := range authorized {
			if permission.Origin == origin && permission.Prefix == route.Destination {
				return true
			}
		}
		return false
	}
}
