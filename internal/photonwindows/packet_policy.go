package photonwindows

import (
	"slices"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// packetPolicy is private to the serial pipeline owner. Its view must come
// from packetStateView: that owner retains one detached, read-only snapshot,
// refreshing it at every verified revision. Ordinary prepare never uses it.
// We retain only the successful signed-policy projection, until its earliest
// actual time transition; crypto jobs retain neither this projection nor facts.
type packetPolicy struct {
	state    *corestate.VerifiedState
	revision corestate.VerifiedRevision
	config   Config
	hint     GatewayPlan
	deadline time.Time
	lastWall time.Time
	facts    packetAuthorization
}

// prepareSnapshot is only for the daemon's immutable packetStateView. A caller
// with an arbitrary mutable corestate.View must call prepare. Each event still
// supplies the immediately current snapshot, original DNS plan and exact now.
func (p *gatewayBabelPipeline) prepareSnapshot(config *Config, view corestate.View, hint GatewayPlan, now time.Time) (*packetAuthorization, bool) {
	var facts packetAuthorization
	if !p.prepareSnapshotInto(config, view, hint, now, &facts) {
		return nil, false
	}
	return &facts, true
}

// The serial daemon can keep each event's facts on its own stack. The output
// is never retained by the policy or a crypto job, and a denied event clears it.
// The pointer-returning component entry point delegates to these same gates.
func (p *gatewayBabelPipeline) prepareSnapshotInto(config *Config, view corestate.View, hint GatewayPlan, now time.Time, facts *packetAuthorization) bool {
	*facts = packetAuthorization{}
	wall := now.Round(0)
	if config == nil || !p.attached(now) || !packetGatewayHintCurrent(hint, now) {
		p.policy, p.leaf = nil, nil
		return false
	}
	policy := p.policy
	if policy != nil && policy.state == view.State && policy.revision == view.Revision &&
		!wall.Before(policy.lastWall) && wall.Before(policy.deadline) &&
		packetPolicyConfigEqual(config, &policy.config) && packetGatewayHintEqual(hint, policy.hint) {
		policy.lastWall = wall
		// Only static signed facts are shared. The event has its own current
		// time and still tests live generation, SA, CHILD and packet gates.
		*facts = policy.facts
		facts.now, facts.plan.EvaluatedAt = now, now
		if !p.preparedCurrent(facts) {
			p.policy, p.leaf = nil, nil
			*facts = packetAuthorization{}
			return false
		}
		return true
	}
	prepared, ok := p.prepare(config, view, hint, now)
	if !ok {
		return false // failed authorization is never retained
	}
	deadline := packetPolicyDeadline(view, now)
	if wall.Before(deadline) {
		p.policy = &packetPolicy{state: view.State, revision: view.Revision,
			config: clonePacketPolicyConfig(config), hint: clonePacketGatewayHint(hint),
			deadline: deadline, lastWall: wall, facts: *prepared}
	}
	*facts = *prepared
	return true
}

func (p *gatewayBabelPipeline) submitSnapshotPacket(config *Config, view corestate.View, plan GatewayPlan, now time.Time, packet []byte) bool {
	if _, _, ok := businessEndpoints(packet); !ok {
		return false
	}
	facts, ok := p.prepareSnapshot(config, view, plan, now)
	if !ok {
		return false
	}
	return p.tunnel.data.submitOutbound(p.generation, facts.plan, packet, func(packet []byte, outbound bool) bool { return p.authorize(facts, packet, outbound) })
}

func (p *gatewayBabelPipeline) tickSnapshot(config *Config, view corestate.View, plan GatewayPlan, now time.Time) {
	if facts, ok := p.prepareSnapshot(config, view, plan, now); ok {
		p.tickPrepared(facts)
	}
}

func packetGatewayHintCurrent(hint GatewayPlan, now time.Time) bool {
	// Preserve the original elapsed-time check and additionally compare wall
	// time: an actual wall-clock rollback can retain monotonic forward motion.
	wall, original := now.Round(0), hint.EvaluatedAt.Round(0)
	return hint.Selected != nil && hint.Rejected == "" && !now.Before(hint.EvaluatedAt) &&
		now.Sub(hint.EvaluatedAt) <= 10*time.Second && !wall.Before(original) && wall.Sub(original) <= 10*time.Second
}

func clonePacketPolicyConfig(config *Config) Config {
	copy := *config
	copy.TrustedRootPublicKey = slices.Clone(config.TrustedRootPublicKey)
	copy.Overlay.SplitRoutes = slices.Clone(config.Overlay.SplitRoutes)
	copy.Gateway.AllowedZones = slices.Clone(config.Gateway.AllowedZones)
	return copy
}

func packetPolicyConfigEqual(a, b *Config) bool {
	return a.ManagedZone == b.ManagedZone && slices.Equal(a.TrustedRootPublicKey, b.TrustedRootPublicKey) &&
		a.Overlay.ID == b.Overlay.ID && slices.Equal(a.Overlay.SplitRoutes, b.Overlay.SplitRoutes) &&
		slices.Equal(a.Gateway.AllowedZones, b.Gateway.AllowedZones)
}

func clonePacketGatewayHint(hint GatewayPlan) GatewayPlan {
	copy := hint
	// Routes are freshly derived from the signed snapshot, never DNS input.
	copy.Routes = nil
	if hint.Selected != nil {
		selected := *hint.Selected
		selected.PublicKey = slices.Clone(hint.Selected.PublicKey)
		copy.Selected = &selected
	}
	copy.Candidates = slices.Clone(hint.Candidates)
	for i := range copy.Candidates {
		copy.Candidates[i].PublicKey = slices.Clone(hint.Candidates[i].PublicKey)
		copy.Candidates[i].Contacts = slices.Clone(hint.Candidates[i].Contacts)
	}
	return copy
}

func packetGatewayHintEqual(a, b GatewayPlan) bool {
	if a.Revision != b.Revision || a.EvaluatedAt != b.EvaluatedAt || a.Rejected != b.Rejected ||
		(a.Selected == nil) != (b.Selected == nil) || len(a.Candidates) != len(b.Candidates) {
		return false
	}
	if a.Selected != nil {
		x, y := a.Selected, b.Selected
		if x.Zone != y.Zone || x.Identity != y.Identity || x.Fingerprint != y.Fingerprint || x.Contact != y.Contact || !slices.Equal(x.PublicKey, y.PublicKey) {
			return false
		}
	}
	for i, x := range a.Candidates {
		y := b.Candidates[i]
		if x.Zone != y.Zone || x.Identity != y.Identity || x.Fingerprint != y.Fingerprint || x.Rejected != y.Rejected ||
			!slices.Equal(x.PublicKey, y.PublicKey) || !slices.Equal(x.Contacts, y.Contacts) {
			return false
		}
	}
	return true
}
