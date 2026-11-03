package photonwindows

import (
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
)

// meshRuntime is owned by the existing daemon event loop. Every neighbor has
// independent IKE, CHILD, Babel and retry state. Only adapter acquisition/read
// runs outside that owner. Ingress goes to the local device, never to a peer.
type meshRuntime struct {
	ctx              context.Context
	config           *Config
	state            *State
	socket           *packetSockets
	logger           *slog.Logger
	peers            map[zone.ZonePath]*meshPeer
	peerOrder        []*meshPeer
	seqno            uint16
	byData           map[*gatewayDataplane]*meshPeer
	device           *meshDevice
	opened           chan leafOpenResult
	jobs             chan dataplaneJob
	onPublication    func()
	ikeStarts        chan *meshIKEStart
	ikePrepared      chan meshIKEStartResult
	ikeResponses     chan *meshIKEResponse
	ikeResponded     chan meshIKEResponseResult
	initial, maximum time.Duration
	id               [8]byte
	nextIntent       time.Time
	view             packetStateView
}

type meshPeer struct {
	config     Config
	plan       GatewayPlan
	tunnel     *gatewayTunnel
	leaf       *leafRuntime
	backoff    time.Duration
	next       time.Time
	contact    int
	rejected   string
	starting   *meshIKEStart
	responding *meshIKEResponse
	ikeInbox   []tunnelDatagram
}

func newMeshRuntime(ctx context.Context, config *Config, state *State, socket *packetSockets, factory packetDeviceFactory, logger *slog.Logger, onPublication func()) *meshRuntime {
	m := &meshRuntime{ctx: ctx, config: config, state: state, socket: socket, logger: logger, peers: make(map[zone.ZonePath]*meshPeer), byData: make(map[*gatewayDataplane]*meshPeer), device: newMeshDevice(ctx, factory), opened: make(chan leafOpenResult, 64), jobs: make(chan dataplaneJob, dataplaneQueueSize), onPublication: onPublication}
	m.ikeStarts = make(chan *meshIKEStart, 4)
	m.ikePrepared = make(chan meshIKEStartResult)
	m.ikeResponses = make(chan *meshIKEResponse, 4)
	m.ikeResponded = make(chan meshIKEResponseResult)
	m.initial, m.maximum = config.Reconnect.InitialBackoff, config.Reconnect.MaxBackoff
	if m.initial <= 0 {
		m.initial = time.Second
	}
	if m.maximum < m.initial {
		m.maximum = 30 * time.Second
	}
	return m
}

func (m *meshRuntime) ordered() []*meshPeer {
	if m.peerOrder != nil {
		return m.peerOrder
	}
	keys := make([]zone.ZonePath, 0, len(m.peers))
	for key := range m.peers {
		keys = append(keys, key)
	}
	slices.Sort(keys)
	peers := make([]*meshPeer, 0, len(keys))
	for _, key := range keys {
		peers = append(peers, m.peers[key])
	}
	m.peerOrder = peers
	return peers
}

func peerGatewayPlan(plan GatewayPlan, candidate GatewayCandidate, contact int) GatewayPlan {
	plan.Targets = nil
	plan.Candidates = []GatewayCandidate{candidate}
	plan.Selected = &GatewaySelection{Zone: candidate.Zone, Identity: candidate.Identity, PublicKey: slices.Clone(candidate.PublicKey), Fingerprint: candidate.Fingerprint, Contact: candidate.Contacts[contact%len(candidate.Contacts)]}
	plan.Rejected = ""
	return plan
}

func (m *meshRuntime) update(plan GatewayPlan) {
	seen := make(map[zone.ZonePath]bool)
	for _, candidate := range plan.Candidates {
		if candidate.Rejected != "" || len(candidate.Contacts) == 0 || plan.Rejected != "" {
			continue
		}
		seen[candidate.Zone] = true
		p := m.peers[candidate.Zone]
		if p == nil {
			config := *m.config
			config.Gateway.AllowedZones = []zone.ZonePath{candidate.Zone}
			data := newSerialGatewayDataplane(m.ctx)
			data.jobs = m.jobs
			leaf := newLeafRuntime(m.device.acquire)
			leaf.opened = m.opened
			leaf.sharedCompletions = true
			p = &meshPeer{config: config, tunnel: &gatewayTunnel{socket: m.socket, data: data}, leaf: leaf, backoff: m.initial}
			m.peers[candidate.Zone], m.byData[data] = p, p
			m.peerOrder = nil
		}
		if p.tunnel.phase != 0 && p.plan.Selected != nil {
			for i, contact := range candidate.Contacts {
				if contact == p.plan.Selected.Contact {
					p.contact = i
					break
				}
			}
		}
		p.plan = peerGatewayPlan(plan, candidate, p.contact)
	}
	for key, p := range m.peers {
		if seen[key] {
			continue
		}
		m.stopPeer(p, "peer authorization or signed contact withdrawn")
		_ = p.leaf.close()
		p.tunnel.data.close()
		delete(m.byData, p.tunnel.data)
		delete(m.peers, key)
		m.peerOrder = nil
	}
}

func (m *meshRuntime) fresh(p *meshPeer, view corestate.View, now time.Time) GatewayPlan {
	if pipeline := p.leaf.pipeline; pipeline != nil && p.tunnel.phase == 3 {
		var facts packetAuthorization
		if pipeline.prepareSnapshotInto(&p.config, view, p.plan, now, &facts) {
			return facts.plan
		}
	}
	if p.tunnel.phase != 0 {
		binding, err := localTransportAuthorization(&p.config, view, now)
		if err != nil || binding != p.tunnel.localAuthorization {
			return GatewayPlan{Rejected: "local transport authorization changed"}
		}
		return revalidateActiveGateway(&p.config, view, p.plan, now)
	}
	return RevalidateGatewayPlan(&p.config, view, p.plan, now)
}

func (m *meshRuntime) stopPeer(p *meshPeer, reason string) {
	p.responding, p.ikeInbox = nil, nil
	if p.starting != nil {
		p.starting.cancel()
		p.starting = nil
	}
	if err := p.leaf.stop(); err != nil {
		m.logger.Warn("leaf_cleanup_failed", "peer", p.config.Gateway.AllowedZones[0], "error", err)
	}
	p.tunnel.observeEvent("attempt_failed", time.Now(), errors.New(reason))
	p.tunnel.stop()
	p.next = time.Now().Add(p.backoff)
	p.tunnel.diagnostic.retryAt = p.next
	p.backoff = min(p.backoff*2, m.maximum)
	p.contact++
	if len(p.plan.Candidates) > 0 && len(p.plan.Candidates[0].Contacts) > 0 {
		p.plan = peerGatewayPlan(p.plan, p.plan.Candidates[0], p.contact)
	}
	m.logger.Info("tunnel_stopped", "peer", p.config.Gateway.AllowedZones[0], "reason", reason, "retry_at", p.next)
}

func (m *meshRuntime) stopAll(reason string) {
	for _, p := range m.ordered() {
		m.stopPeer(p, reason)
	}
}

func (m *meshRuntime) close() error {
	var err error
	// All opens must join before draining the shared completion queue.
	for _, p := range m.ordered() {
		err = errors.Join(err, p.leaf.close())
		p.tunnel.stop()
		p.tunnel.data.close()
	}
	for {
		select {
		case result := <-m.opened:
			if result.device != nil {
				err = errors.Join(err, result.device.Close())
			}
		case event := <-m.device.packets:
			event.timing.Finish(fixturePacketTimingCanceled)
		default:
			return err
		}
	}
}

func (m *meshRuntime) reconcile() error {
	active := false
	for _, p := range m.peers {
		active = active || p.tunnel.phase == 3
	}
	if !active {
		return nil
	}
	now := time.Now()
	if m.id == [8]byte{} || !now.Before(m.nextIntent) {
		m.nextIntent = now.Add(5 * time.Second)
		var err error
		m.id, err = routing.StableBabelRouterID(m.config.ManagedZone, m.config.TrustedRootPublicKey, m.config.Overlay.ID)
		if err != nil {
			return err
		}
		before := m.state.Store().VerifiedRevision()
		if err = m.state.EnsureLocalLeafRoutes(m.ctx, m.config, now); err != nil {
			m.stopAll(err.Error())
			return nil
		}
		if before != m.state.Store().VerifiedRevision() {
			m.onPublication()
		}
	}
	for _, p := range m.ordered() {
		if p.tunnel.phase != 3 {
			continue
		}
		err := p.leaf.reconcile(m.ctx, &p.config, m.view.read(m.state.Store()), p.plan, p.tunnel, m.id, now)
		rejected := ""
		if err != nil {
			rejected = err.Error()
		}
		if rejected != p.rejected {
			p.rejected = rejected
			if err != nil {
				m.logger.Info("leaf_unavailable", "peer", p.config.Gateway.AllowedZones[0], "reason", rejected)
			}
		}
		if errors.Is(err, errPacketDeviceRecoveryExpired) {
			return err
		}
	}
	return nil
}

func (m *meshRuntime) tick() error {
	now := time.Now()
	starts := 0
	for _, p := range m.ordered() {
		if p.responding != nil && p.tunnel.phase == 3 &&
			(!now.Before(p.tunnel.ikeExpiresAt) || !now.Before(p.tunnel.expiresAt)) {
			m.stopPeer(p, "tunnel hard lifetime reached while processing IKE")
		}
		if p.tunnel.phase != 0 && p.responding == nil {
			if err := p.tunnel.tickWithScheduler(m.fresh(p, m.view.read(m.state.Store()), now), now, func(request ikeTimerRequest) {
				m.scheduleIKETimer(p, request, now)
			}); err != nil {
				m.stopPeer(p, err.Error())
			} else {
				m.dispatchPendingIKE(p, now)
			}
		}
		// Bound work per owner turn without serializing peer lifetimes. A dead
		// first peer never blocks attempts to the other authorized peers.
		if p.tunnel.phase == 0 && p.starting == nil && !now.Before(p.next) && starts < 4 {
			m.attempt(p)
			starts++
		}
	}
	if err := m.reconcile(); err != nil {
		return err
	}
	for _, p := range m.ordered() {
		if p.leaf.pipeline != nil {
			p.leaf.pipeline.leaf.SynchronizeSequence(m.seqno)
			p.leaf.pipeline.tickSnapshot(&p.config, m.view.read(m.state.Store()), p.plan, time.Now())
			m.synchronizeSequences()
		}
	}
	return nil
}

func (m *meshRuntime) invalidate() error {
	for _, p := range m.ordered() {
		if p.tunnel.phase != 0 && !p.tunnel.current(m.fresh(p, m.view.read(m.state.Store()), time.Now())) {
			m.stopPeer(p, "verified authorization withdrawn")
		}
	}
	return m.reconcile()
}

func (m *meshRuntime) findGeneration(generation uint64) *meshPeer {
	for _, p := range m.peers {
		if p.tunnel.generation == generation {
			return p
		}
	}
	return nil
}

func (m *meshRuntime) handleIKE(packet tunnelDatagram) error {
	p := m.findGeneration(packet.generation)
	if p == nil {
		return nil
	}
	now := time.Now()
	plan := m.fresh(p, m.view.read(m.state.Store()), now)
	m.enqueueIKEResponse(p, packet, plan, now)
	return nil
}

func (m *meshRuntime) handleESP(packet tunnelDatagram) {
	packet.timing.Dequeue()
	p := m.findGeneration(packet.generation)
	if p != nil {
		completion, ok := p.tunnel.data.processOwnedInbound(packet.generation, m.fresh(p, m.view.read(m.state.Store()), time.Now()), packet.peer, packet.packet, packet.timing)
		if ok {
			m.complete(completion)
			return
		}
	}
	packet.timing.Finish(fixturePacketTimingRejected)
}

func (m *meshRuntime) complete(completion dataplaneCompletion) {
	defer m.synchronizeSequences()
	p := m.byData[completion.job.owner]
	if p == nil {
		completion.timing.Finish(fixturePacketTimingCanceled)
		return
	}
	view, now := m.view.read(m.state.Store()), time.Now()
	var facts packetAuthorization
	haveFacts := p.leaf.pipeline != nil && p.leaf.pipeline.prepareSnapshotInto(&p.config, view, p.plan, now, &facts)
	plan := facts.plan
	if !haveFacts {
		plan = m.fresh(p, view, now)
	}
	p.tunnel.observeData(completion, plan, now)
	if haveFacts {
		if _, err := p.leaf.pipeline.acceptPrepared(&facts, completion); err != nil {
			m.logger.Warn("leaf_packet_failed", "error", errors.Join(err, p.leaf.stop()))
		}
	} else {
		p.tunnel.data.accept(completion, plan, nil)
		completion.timing.Finish(fixturePacketTimingRejected)
	}
}

func (m *meshRuntime) completeOpen(result leafOpenResult) error {
	for _, p := range m.peers {
		if p.leaf != result.owner {
			continue
		}
		err := p.leaf.complete(m.ctx, &p.config, m.view.read(m.state.Store()), p.plan, p.tunnel, m.id, time.Now(), result)
		if errors.Is(err, errPacketDeviceConflict) || errors.Is(err, errPacketDeviceRecoveryExpired) {
			return err
		}
		if err != nil {
			m.logger.Warn("leaf_device_failed", "error", err)
		}
		return nil
	}
	if result.device != nil {
		return result.device.Close()
	}
	return nil
}

type meshChoice struct {
	peer  *meshPeer
	facts packetAuthorization
	route sadr.Route
}

// Only locally originated packets enter selection. RFC 9079 destination then
// source specificity precedes cost; a stable address hash spreads equal paths.
func (m *meshRuntime) selectRoute(packet []byte, view corestate.View, now time.Time) *meshChoice {
	source, destination, ok := businessEndpoints(packet)
	if !ok {
		return nil
	}
	var choices []meshChoice
	for _, p := range m.ordered() {
		pipeline := p.leaf.pipeline
		if pipeline == nil {
			continue
		}
		var facts packetAuthorization
		if !pipeline.prepareSnapshotInto(&p.config, view, p.plan, now, &facts) || !pipeline.localAddress(source, facts.localOrigins) {
			continue
		}
		routes := sadr.Lookup(pipeline.leaf.Candidates(now, facts.authorizeRoute), source, destination, now, facts.authorizeRoute)
		if len(routes) == 0 {
			continue
		}
		candidate := meshChoice{p, facts, routes[0]}
		if len(choices) > 0 {
			r, b := candidate.route, choices[0].route
			d, s, bd, bs := r.Destination.Bits(), max(0, r.Source.Bits()), b.Destination.Bits(), max(0, b.Source.Bits())
			if d < bd || d == bd && s < bs || d == bd && s == bs && r.Metric > b.Metric {
				continue
			}
			if d > bd || s > bs || r.Metric < b.Metric {
				choices = choices[:0]
			}
		}
		choices = append(choices, candidate)
	}
	if len(choices) == 0 {
		return nil
	}
	hash := fnv.New32a()
	_, _ = hash.Write(source.AsSlice())
	_, _ = hash.Write(destination.AsSlice())
	return &choices[int(hash.Sum32()%uint32(len(choices)))]
}

func (m *meshRuntime) handleHost(event leafDevicePacket) {
	event.timing.Dequeue()
	if event.err != nil {
		event.timing.Finish(fixturePacketTimingRejected)
		m.stopAll(event.err.Error())
		return
	}
	if !m.device.current(event.generation) {
		event.timing.Finish(fixturePacketTimingRejected)
		return
	}
	choice := m.selectRoute(event.packet, m.view.read(m.state.Store()), time.Now())
	if choice == nil {
		event.timing.Finish(fixturePacketTimingRejected)
		return
	}
	event.timing.Classify(fixturePacketTimingBusiness)
	pipeline := choice.peer.leaf.pipeline
	completion, ok := choice.peer.tunnel.data.processOwnedOutbound(pipeline.generation, choice.facts.plan, event.packet, func(packet []byte, outbound bool) bool { return pipeline.authorize(&choice.facts, packet, outbound) }, event.timing)
	if ok {
		m.complete(completion)
	} else {
		completion.timing.Finish(fixturePacketTimingRejected)
	}
}

func (m *meshRuntime) ready() bool {
	for _, p := range m.ordered() {
		if p.leaf.readySnapshot(&p.config, m.view.read(m.state.Store()), p.plan, time.Now()) {
			return true
		}
	}
	return false
}

// Network replacement invalidates every peer's old endpoint reservation. This
// is the only shared transport teardown; ordinary peer failures stay isolated.
func (m *meshRuntime) reset() {
	m.stopAll("local network endpoint replaced")
	for _, p := range m.peers {
		p.plan = GatewayPlan{}
	}
}

func (m *meshRuntime) synchronizeSequences() {
	for _, p := range m.ordered() {
		if p.leaf.pipeline == nil || p.leaf.pipeline.leaf == nil {
			continue
		}
		seqno := p.leaf.pipeline.leaf.OriginSequence()
		if int16(seqno-m.seqno) > 0 {
			m.seqno = seqno
		}
	}
	for _, p := range m.ordered() {
		if p.leaf.pipeline != nil && p.leaf.pipeline.leaf != nil {
			p.leaf.pipeline.leaf.SynchronizeSequence(m.seqno)
		}
	}
}
