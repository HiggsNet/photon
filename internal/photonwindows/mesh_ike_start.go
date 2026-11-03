package photonwindows

import (
	"context"
	"net/netip"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

type meshIKEStart struct {
	ctx      context.Context
	cancel   context.CancelFunc
	peer     *meshPeer
	config   Config
	hint     GatewayPlan
	endpoint netip.AddrPort
}

type meshIKEStartResult struct {
	request   *meshIKEStart
	revision  corestate.VerifiedRevision
	published bool
	local     LocalTransportIdentity
	plan      GatewayPlan
	binding   [32]byte
	start     preparedIKEStart
	err       error
}

func (m *meshRuntime) attempt(p *meshPeer) {
	if p.plan.Selected == nil {
		return
	}
	addr := m.socket.LocalAddr()
	if addr == nil {
		return
	}
	ctx, cancel := context.WithCancel(m.ctx)
	request := &meshIKEStart{ctx: ctx, cancel: cancel, peer: p, config: p.config, hint: p.plan, endpoint: addr.AddrPort()}
	select {
	case m.ikeStarts <- request:
		p.starting = request
	default:
		cancel()
	}
}

// The worker owns identity reads and initial exchange preparation. It never
// reads live peer or SA state, and the Mesh owner decides whether to install.
func (m *meshRuntime) runIKEStarts(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-m.ikeStarts:
			stop := context.AfterFunc(ctx, request.cancel)
			result := m.prepareIKEAttempt(request.ctx, request)
			stop()
			request.cancel()
			select {
			case m.ikePrepared <- result:
			case <-ctx.Done():
				clear(result.local.PrivateKey)
				return
			}
		}
	}
}

func (m *meshRuntime) prepareIKEAttempt(ctx context.Context, request *meshIKEStart) meshIKEStartResult {
	if err := ctx.Err(); err != nil {
		return meshIKEStartResult{request: request, err: err}
	}
	store := m.state.Store()
	view, now := store.ReadView(), time.Now()
	result := meshIKEStartResult{request: request, revision: view.Revision}
	result.plan = RevalidateGatewayPlan(&request.config, view, request.hint, now)
	if result.plan.Selected == nil {
		return result
	}
	result.local, result.err = m.state.EnsureLocalTransport(ctx, &request.config, now, result.plan, request.endpoint)
	if store.VerifiedRevision() != view.Revision {
		result.published = true
		return result
	}
	if result.err == nil {
		result.binding, result.err = localTransportAuthorization(&request.config, view, now)
	}
	if result.err == nil {
		result.err = ctx.Err()
	}
	if result.err == nil {
		result.start, result.err = prepareIKEStart(result.plan, request.endpoint)
	}
	return result
}

func (m *meshRuntime) finishIKEStart(result meshIKEStartResult) {
	defer clear(result.local.PrivateKey)
	if result.published {
		m.onPublication()
	}
	p := result.request.peer
	if p.starting != result.request {
		return
	}
	p.starting = nil
	if result.published || result.revision != m.state.Store().VerifiedRevision() || !packetGatewayHintEqual(p.plan, result.request.hint) || result.plan.Selected == nil {
		return
	}
	now := time.Now()
	current := m.fresh(p, m.view.read(m.state.Store()), now)
	if current.Selected == nil || !dataplaneGatewayEqual(*current.Selected, *result.plan.Selected) {
		return
	}
	if result.err == nil {
		binding, err := localTransportAuthorization(&p.config, m.view.read(m.state.Store()), now)
		if err != nil || binding != result.binding {
			return
		}
	}
	if err := p.tunnel.installIKEStart(current, result.local.ID, result.local.PrivateKey, result.start, now, result.err); err != nil {
		m.stopPeer(p, err.Error())
		return
	}
	p.tunnel.localAuthorization = result.binding
}
