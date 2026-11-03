package photonwindows

import (
	"context"
	"errors"
	"net/netip"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
)

const (
	meshPolicyQueueSize = 64
	// Bound publication-to-application latency even if the verifier is stalled.
	meshPolicyRevisionGrace = 2 * time.Second
)

// meshPeerPolicy belongs to the Mesh event owner. A request contains no
// references to mutable session, device, or route state used by the worker.
type meshPeerPolicy struct {
	pending       *meshPolicyRequest
	current       *meshPolicyProjection
	graceDeadline time.Time
}

type meshPolicyRequest struct {
	peer     *meshPeer // Opaque completion identity. The worker never reads it.
	revision corestate.VerifiedRevision
	at       time.Time
	config   Config
	hint     GatewayPlan
}

type meshPolicyProjection struct {
	request             *meshPolicyRequest
	deadline, monotonic time.Time
	refreshAt           time.Time
	lastWall            time.Time // Advanced by the Mesh owner only.
	binding             [32]byte
	plan                GatewayPlan
	attachment          leafAttachment
	attachmentErr       error
	hosts               []netip.Prefix
	addresses           []netip.Addr
	origins             []babel.Origin
	authorize           func(sadr.Route) bool
}

type meshPolicyResult struct {
	request    *meshPolicyRequest
	projection *meshPolicyProjection
}

type meshPolicyWorker struct {
	store    *corestate.Store
	requests chan *meshPolicyRequest
	results  chan meshPolicyResult
}

func newMeshPolicyWorker(store *corestate.Store) *meshPolicyWorker {
	return &meshPolicyWorker{
		store: store, requests: make(chan *meshPolicyRequest, meshPolicyQueueSize),
		results: make(chan meshPolicyResult, meshPolicyQueueSize),
	}
}

// The verified revision is checked independently by matches. An equivalent
// DNS hint can update its planner metadata without changing any inputs to
// revalidateActiveGatewaySelection.
func plannerPolicyEqual(a, b GatewayPlan) bool {
	a.Revision, a.EvaluatedAt = b.Revision, b.EvaluatedAt
	return packetGatewayHintEqual(a, b)
}

func (r *meshPolicyRequest) matchesHint(p *meshPeer) bool {
	return packetPolicyConfigEqual(&p.config, &r.config) && plannerPolicyEqual(p.plan, r.hint)
}

func (p *meshPolicyProjection) validAt(now time.Time) bool {
	wall := now.Round(0)
	return !wall.Before(p.lastWall) && (p.deadline.IsZero() || wall.Before(p.deadline)) &&
		(p.monotonic.IsZero() || now.Before(p.monotonic))
}

func (p *meshPolicyProjection) current(peer *meshPeer, revision corestate.VerifiedRevision, now time.Time) bool {
	return p.request.revision == revision && p.request.matchesHint(peer) &&
		p.validAt(now) && packetGatewayHintCurrent(peer.plan, now)
}

func (p *meshPeerPolicy) accepts(projection *meshPolicyProjection, now time.Time) bool {
	return p.current == projection && projection.validAt(now) &&
		(p.graceDeadline.IsZero() || now.Before(p.graceDeadline))
}

// project queues at most one request per peer. While a newer revision is
// pending, ESP can use the unchanged installed policy for one bounded grace.
// IKE and device attachment must wait for a settled current projection.
func (w *meshPolicyWorker) project(p *meshPeer, revision corestate.VerifiedRevision, now time.Time) (*meshPolicyProjection, bool) {
	policy := &p.policy
	if !packetGatewayHintCurrent(p.plan, now) {
		*policy = meshPeerPolicy{}
		return nil, false
	}
	wall := now.Round(0)
	if policy.pending != nil && wall.Before(policy.pending.at) {
		policy.pending = nil
	}
	var installed *meshPolicyProjection
	pendingRevision := true
	if current := policy.current; current != nil {
		switch {
		case !current.validAt(now) || !current.request.matchesHint(p) || current.request.revision > revision:
			policy.current, policy.graceDeadline = nil, time.Time{}
		case current.request.revision == revision:
			current.lastWall = wall
			if current.refreshAt.IsZero() || wall.Before(current.refreshAt) {
				return current, false
			}
			// Soft cache age asks the worker to refresh. The same revision
			// remains settled until an actual signed boundary or replacement.
			installed, pendingRevision = current, false
		case current.plan.Selected != nil:
			if policy.graceDeadline.IsZero() {
				policy.graceDeadline = now.Add(meshPolicyRevisionGrace)
			}
			if policy.accepts(current, now) {
				current.lastWall = wall
				installed = current
			}
		}
	}
	if policy.pending == nil && len(w.requests) < cap(w.requests) {
		request := &meshPolicyRequest{
			peer: p, revision: revision, at: wall, config: clonePacketPolicyConfig(&p.config), hint: clonePacketGatewayHint(p.plan),
		}
		select {
		case w.requests <- request:
			policy.pending = request
		default:
		}
	}
	return installed, pendingRevision
}

// finish runs on the Mesh owner. Revocation and plan changes invalidate even
// results which were already computed and queued before the owner saw them.
func (w *meshPolicyWorker) finish(result meshPolicyResult, revision corestate.VerifiedRevision, now time.Time) {
	p := result.request.peer
	if p.policy.pending != result.request {
		return
	}
	p.policy.pending = nil
	if result.projection != nil && !result.projection.lastWall.Before(result.request.at) &&
		result.projection.current(p, revision, now) {
		if p.leaf != nil && p.leaf.pipeline != nil {
			p.leaf.pipeline.leaf.RevalidateRoutes(now, result.projection.authorize)
		}
		p.policy.current, p.policy.graceDeadline = result.projection, time.Time{}
	}
}

func (p *meshPolicyProjection) packetFacts(pipeline *gatewayBabelPipeline, now time.Time, facts *packetAuthorization) bool {
	*facts = packetAuthorization{}
	if p == nil || pipeline == nil || p.binding != pipeline.tunnel.localAuthorization ||
		p.attachment.local != pipeline.local || p.attachment.peer != pipeline.peer ||
		(p.attachmentErr != nil && !errors.Is(p.attachmentErr, errLeafHostAssignmentUnavailable) &&
			!errors.Is(p.attachmentErr, errLeafHostAnnouncementUnavailable)) {
		return false
	}
	origins := p.origins
	if len(pipeline.addresses) == 0 {
		// An authenticated control-only adjacency advertises no business IP.
		origins = nil
	} else if !slices.Equal(p.addresses, pipeline.addresses) {
		// A change in signed interface addresses must be applied by the
		// attachment owner before business traffic can use the new policy.
		return false
	}
	prepared := packetAuthorization{
		owner: pipeline, projection: p, plan: p.plan, now: now, hosts: p.hosts, localOrigins: origins, authorizeRoute: p.authorize,
	}
	if !pipeline.preparedCurrent(&prepared) {
		return false
	}
	*facts = prepared
	return true
}

// meshPolicyInputs are worker-owned. All peers share the immutable signed
// route set and its time boundary for a verified revision and root pin.
type meshPolicyInputs struct {
	view         packetStateView
	verifier     photoncrypto.Verifier
	revision     corestate.VerifiedRevision
	config       Config
	at, deadline time.Time
	refreshAt    time.Time
	monotonic    time.Time
	routes       *routing.AuthorizedRouteSet
}

func (w *meshPolicyWorker) run(ctx context.Context) {
	var inputs meshPolicyInputs
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-w.requests:
			now := time.Now()
			view := inputs.view.read(w.store)
			result := meshPolicyResult{request: request}
			if request.revision == view.Revision && packetGatewayHintCurrent(request.hint, now) {
				result.projection = inputs.project(request, view, now)
			}
			select {
			case w.results <- result:
			case <-ctx.Done():
				return
			}
		}
	}
}

func (s *meshPolicyInputs) project(request *meshPolicyRequest, view corestate.View, now time.Time) *meshPolicyProjection {
	config := &request.config
	wall := now.Round(0)
	if s.revision != view.Revision || !slices.Equal(s.config.TrustedRootPublicKey, config.TrustedRootPublicKey) ||
		wall.Before(s.at) || !wall.Before(s.refreshAt) ||
		(!s.deadline.IsZero() && !wall.Before(s.deadline)) || (!s.monotonic.IsZero() && !now.Before(s.monotonic)) {
		s.revision, s.config, s.at = view.Revision, *config, wall
		s.refreshAt = wall.Add(packetPolicyMaxAge)
		s.monotonic = time.Time{}
		s.deadline = meshPolicySignedDeadline(view, now, &s.monotonic)
		s.routes = currentAuthorizedRouteSetWithVerifier(config, view, now, &s.verifier)
	}
	projection := &meshPolicyProjection{
		request: request, lastWall: wall, deadline: s.deadline, monotonic: s.monotonic, refreshAt: s.refreshAt,
	}
	binding, err := localTransportAuthorizationWithVerifier(config, view, now, &s.verifier)
	if err != nil {
		projection.plan.Rejected = "local transport authorization changed"
		projection.attachmentErr = err
		return projection
	}
	projection.binding = binding
	projection.plan = revalidateActiveGatewaySelection(config, view, request.hint, now, &s.verifier)
	if projection.plan.Selected == nil {
		return projection
	}
	projection.plan.Routes = authorizedGatewayRoutesFromSet(config, s.routes)
	projection.attachment.local, projection.attachment.peer, err = leafLinkLocalAddressesWithVerifier(config, view, projection.plan, now, &s.verifier)
	if err != nil {
		projection.attachmentErr = err
		return projection
	}
	hosts, routes, err := requiredLeafDeviceIntentFromSet(config, s.routes)
	projection.attachment.addresses, projection.attachment.routes, projection.attachmentErr = hosts, routes, err
	projection.hosts = hosts
	projection.authorize = babelRouteAuthorizer(projection.plan.Routes, hosts)
	for _, host := range hosts {
		projection.addresses = append(projection.addresses, host.Addr())
	}
	pipeline := gatewayBabelPipeline{addresses: projection.addresses}
	projection.origins = pipeline.originsFromRoutes(config, projection.plan.Routes)
	return projection
}
