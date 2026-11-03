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

const meshPolicyQueueSize = 64

// meshPeerPolicy belongs to the Mesh event owner. A request contains no
// references to mutable session, device, or route state used by the worker.
type meshPeerPolicy struct {
	pending *meshPolicyRequest
	current *meshPolicyProjection
}

type meshPolicyRequest struct {
	peer     *meshPeer // Opaque completion identity. The worker never reads it.
	revision corestate.VerifiedRevision
	store    *corestate.Store
	config   Config
	hint     GatewayPlan
}

type meshPolicyProjection struct {
	request             *meshPolicyRequest
	deadline, monotonic time.Time
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

func (r *meshPolicyRequest) matches(p *meshPeer, revision corestate.VerifiedRevision) bool {
	return r.revision == revision && packetPolicyConfigEqual(&p.config, &r.config) && plannerPolicyEqual(p.plan, r.hint)
}

func (p *meshPolicyProjection) current(peer *meshPeer, revision corestate.VerifiedRevision, now time.Time) bool {
	wall := now.Round(0)
	return p.request.matches(peer, revision) && !wall.Before(p.lastWall) &&
		wall.Before(p.deadline) && (p.monotonic.IsZero() || now.Before(p.monotonic)) && packetGatewayHintCurrent(peer.plan, now)
}

// project never reads the full store view or verifies records. On a miss it
// queues at most one request per peer and immediately marks the peer pending.
// Returning pending is distinct from a verified denial and must not tear down
// an otherwise live session. Packets for a pending peer still fail closed.
func (w *meshPolicyWorker) project(p *meshPeer, revision corestate.VerifiedRevision, now time.Time) (*meshPolicyProjection, bool) {
	if !packetGatewayHintCurrent(p.plan, now) {
		return nil, false
	}
	if current := p.policy.current; current != nil {
		if current.current(p, revision, now) {
			current.lastWall = now.Round(0)
			return current, false
		}
		p.policy.current = nil
	}
	if p.policy.pending == nil {
		request := &meshPolicyRequest{
			peer: p, revision: revision, store: w.store, config: clonePacketPolicyConfig(&p.config), hint: clonePacketGatewayHint(p.plan),
		}
		select {
		case w.requests <- request:
			p.policy.pending = request
		default:
		}
	}
	return nil, true
}

// finish runs on the Mesh owner. Revocation and plan changes invalidate even
// results which were already computed and queued before the owner saw them.
func (w *meshPolicyWorker) finish(result meshPolicyResult, revision corestate.VerifiedRevision, now time.Time) {
	p := result.request.peer
	if p.policy.pending != result.request {
		return
	}
	p.policy.pending = nil
	if result.projection != nil && result.projection.current(p, revision, now) {
		p.policy.current = result.projection
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
		owner: pipeline, revisionStore: p.request.store, revision: p.request.revision, plan: p.plan, now: now, hosts: p.hosts, localOrigins: origins, authorizeRoute: p.authorize,
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
		wall.Before(s.at) || !wall.Before(s.deadline) || (!s.monotonic.IsZero() && !now.Before(s.monotonic)) {
		s.revision, s.config, s.at = view.Revision, *config, wall
		s.monotonic = time.Time{}
		s.deadline = packetPolicyDeadlineWithMonotonic(view, now, &s.monotonic)
		s.routes = currentAuthorizedRouteSetWithVerifier(config, view, now, &s.verifier)
	}
	projection := &meshPolicyProjection{request: request, lastWall: wall, deadline: s.deadline, monotonic: s.monotonic}
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
