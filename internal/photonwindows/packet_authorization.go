package photonwindows

import (
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// packetAuthorization belongs to one synchronous owner event, never to a
// tunnel, crypto job or cache. Every completion constructs fresh facts from the
// current view and exact time, including expiry without a revision change.
// The callbacks in gatewayDataplane execute synchronously and do not retain it.
type packetAuthorization struct {
	owner          *gatewayBabelPipeline
	plan           GatewayPlan
	now            time.Time
	localOrigins   []babel.Origin
	hosts          []netip.Prefix
	authorizeRoute func(sadr.Route) bool
}

func (p *gatewayBabelPipeline) attached(now time.Time) bool {
	t := p.tunnel
	return p.leaf != nil && t.generation == p.generation && t.phase == 3 && t.failed == nil && t.session != nil && t.data != nil && now.Before(t.ikeExpiresAt) && now.Before(t.expiresAt)
}

func (p *gatewayBabelPipeline) prepare(config *Config, view corestate.View, plan GatewayPlan, now time.Time) (*packetAuthorization, bool) {
	if config == nil || !p.attached(now) {
		p.leaf = nil
		return nil, false
	}
	t := p.tunnel
	binding, err := localTransportAuthorizationWithVerifier(config, view, now, p.verifier)
	if err != nil || binding != t.localAuthorization {
		p.leaf = nil
		return nil, false
	}
	origins := currentBabelOriginsWithVerifier(config, view, now, p.verifier)
	if origins[p.routerID] != config.ManagedZone {
		p.leaf = nil
		return nil, false
	}
	current := revalidateActiveGatewaySelection(config, view, plan, now, p.verifier)
	if !t.current(current) || !t.data.current(t.generation, t.data.active, current) {
		p.leaf = nil
		return nil, false
	}
	// Build signed IPAM/route facts once for this event. Gateway selection and
	// local/Babel identities retain their existing independent verification.
	set := currentAuthorizedRouteSetWithVerifier(config, view, now, p.verifier)
	current.Routes = authorizedGatewayRoutesFromSet(config, set)
	hosts, _ := leafDeviceIntentFromSet(config, set)
	return &packetAuthorization{owner: p, plan: current, now: now,
		localOrigins: p.originsFromRoutes(config, current.Routes), hosts: hosts,
		authorizeRoute: babelRouteAuthorizer(origins, current.Routes, hosts)}, true
}

func (p *gatewayBabelPipeline) preparedCurrent(facts *packetAuthorization) bool {
	// Keep mutable SA/generation checks at use time: observeData may activate a
	// new CHILD between prepare and delivery in this same owner event.
	return facts != nil && facts.owner == p && p.attached(facts.now) && p.tunnel.current(facts.plan) && p.tunnel.data.current(p.generation, p.tunnel.data.active, facts.plan)
}
