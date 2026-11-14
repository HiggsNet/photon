package photonwindows

import (
	"context"
	"errors"
	"hash/fnv"
	"log/slog"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// The daemon owns control events. Packet workers use stateMu to select and
// validate live state, and run crypto and I/O separately.
type meshRuntime struct {
	stateMu          sync.Mutex
	cleanupWG        sync.WaitGroup
	cleanupMu        sync.Mutex
	cleanupErr       error
	ctx              context.Context
	config           *Config
	state            *State
	socket           *packetSockets
	logger           *slog.Logger
	peers            map[meshPath]*meshPeer
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
	ikeWrites        chan meshIKEWrite
	ikeWriteFailures chan meshIKEWriteFailure
	initial, maximum time.Duration
	id               [8]byte
	nextIntent       time.Time
	leafIntents      chan struct{}
	policy           *meshPolicyWorker
	txWake           meshTXWake
	outboundBatch    []byte // Owned by the TX worker.
	outboundScratch  []byte // Owned by the TX worker.
}

type meshPath struct {
	zone   zone.ZonePath
	family string
}

type meshPeer struct {
	policy       meshPeerPolicy
	config       Config
	plan         GatewayPlan
	planEpoch    uint64
	tunnel       *gatewayTunnel
	leaf         *leafRuntime
	backoff      time.Duration
	next         time.Time
	contact      int
	rejected     string
	starting     *meshIKEStart
	responding   *meshIKEResponse
	heldResponse *meshIKEResponseResult
	ikeInbox     []tunnelDatagram
}

func newMeshRuntime(ctx context.Context, config *Config, state *State, socket *packetSockets, factory packetDeviceFactory, logger *slog.Logger, onPublication func()) *meshRuntime {
	m := &meshRuntime{ctx: ctx, config: config, state: state, socket: socket, logger: logger, peers: make(map[meshPath]*meshPeer), byData: make(map[*gatewayDataplane]*meshPeer), device: newMeshDevice(ctx, factory), opened: make(chan leafOpenResult, 64), jobs: make(chan dataplaneJob, dataplaneQueueSize), onPublication: onPublication}
	m.ikeStarts = make(chan *meshIKEStart, 4)
	m.txWake.ready = make(chan struct{}, 1)
	m.device.wake = m.txWake.signal
	m.ikePrepared = make(chan meshIKEStartResult)
	m.ikeResponses = make(chan *meshIKEResponse, 4)
	m.ikeResponded = make(chan meshIKEResponseResult)
	if state != nil {
		m.policy = newMeshPolicyWorker(state.Store())
		m.leafIntents = make(chan struct{}, 1)
		m.ikeWrites = make(chan meshIKEWrite, meshIKEWriteQueueSize)
		m.ikeWriteFailures = make(chan meshIKEWriteFailure, meshIKEWriteQueueSize)
	}
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
	keys := make([]meshPath, 0, len(m.peers))
	for key := range m.peers {
		keys = append(keys, key)
	}
	slices.SortFunc(keys, func(a, b meshPath) int {
		if a.zone != b.zone {
			return strings.Compare(string(a.zone), string(b.zone))
		}
		return strings.Compare(a.family, b.family)
	})
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

// setPlan is the owner-side publication point for peer planner hints. Plans
// and their nested slices are immutable after publication.
func (p *meshPeer) setPlan(next GatewayPlan) {
	if p.planEpoch == 0 || !plannerPolicyEqual(p.plan, next) {
		p.planEpoch++
	}
	p.plan = next
}

func (m *meshRuntime) update(plan GatewayPlan) {
	local := m.socket.LocalAddr()
	if local == nil {
		return
	}
	address := local.AddrPort().Addr().Unmap()
	seen := make(map[meshPath]bool)
	for _, candidate := range plan.Candidates {
		if candidate.Rejected != "" || plan.Rejected != "" {
			continue
		}
		for _, family := range []string{ipsec.FamilyIPv4, ipsec.FamilyIPv6} {
			// Go's IPv6 wildcard UDP socket accepts both families. A specific
			// bind, or a wildcard on a host with only IPv4, is single-family.
			if !(address.Is6() && address.IsUnspecified()) && outerFamily(address) != family {
				continue
			}
			familyCandidate := candidate
			familyCandidate.Contacts = contactsForFamily(candidate.Contacts, family)
			if len(familyCandidate.Contacts) == 0 {
				continue
			}
			key := meshPath{zone: candidate.Zone, family: family}
			seen[key] = true
			m.updatePath(plan, familyCandidate, key)
		}
	}
	for key, p := range m.peers {
		if seen[key] {
			continue
		}
		m.stopPeer(p, "peer authorization or signed contact withdrawn")
		// stopPeer already detached/cancelled this leaf. Join its platform
		// opener outside stateMu, retaining ownership until daemon shutdown.
		m.retire(func() error { p.leaf.openWG.Wait(); return nil })
		p.tunnel.data.close()
		delete(m.byData, p.tunnel.data)
		delete(m.peers, key)
		m.peerOrder = nil
	}
}

func (m *meshRuntime) updatePath(plan GatewayPlan, candidate GatewayCandidate, key meshPath) {
	plan.outerFamily = key.family
	p := m.peers[key]
	if p == nil {
		config := *m.config
		config.Gateway.AllowedZones = []zone.ZonePath{candidate.Zone}
		data := newSerialGatewayDataplane(m.ctx)
		data.jobs = m.jobs
		data.jobReady = m.txWake.signal
		leaf := newLeafRuntime(m.device.acquire)
		leaf.opened = m.opened
		leaf.sharedCompletions = true
		leaf.retireDevice = m.retireDevice
		p = &meshPeer{config: config, tunnel: &gatewayTunnel{socket: m.socket, data: data, offerMOBIKE: config.Gateway.MOBIKE}, leaf: leaf, backoff: m.initial}
		if m.ikeWrites != nil {
			p.tunnel.queueIKE = m.queueIKEWrite
		}
		m.peers[key], m.byData[data] = p, p
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
	p.setPlan(peerGatewayPlan(plan, candidate, p.contact))
}

func (m *meshRuntime) stopPeer(p *meshPeer, reason string) {
	m.stopPeerWithEvent(p, "attempt_failed", reason)
}

// cancelWork releases owner-held results. In-flight response inputs remain
// worker-owned until completion; clearing them here would race the worker.
func (p *meshPeer) cancelWork() {
	if p.heldResponse != nil {
		clear(p.heldResponse.request.input.private)
		p.heldResponse = nil
	}
	p.responding, p.ikeInbox = nil, nil
	p.policy = meshPeerPolicy{}
	if p.starting != nil {
		p.starting.cancel()
		p.starting = nil
	}
}

func (m *meshRuntime) stopPeerWithEvent(p *meshPeer, event, reason string) {
	p.cancelWork()
	if err := p.leaf.stop(); err != nil {
		m.logger.Warn("leaf_cleanup_failed", "peer", p.config.Gateway.AllowedZones[0], "error", err)
	}
	p.tunnel.observeEvent(event, time.Now(), errors.New(reason))
	p.tunnel.stop()
	p.next = time.Now().Add(p.backoff)
	p.tunnel.diagnostic.retryAt = p.next
	p.backoff = min(p.backoff*2, m.maximum)
	p.contact++
	if len(p.plan.Candidates) > 0 && len(p.plan.Candidates[0].Contacts) > 0 {
		p.setPlan(peerGatewayPlan(p.plan, p.plan.Candidates[0], p.contact))
	}
	m.logger.Info("tunnel_stopped", "peer", p.config.Gateway.AllowedZones[0], "outer_family", p.plan.outerFamily, "reason", reason, "retry_at", p.next)
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
		p.cancelWork()
		err = errors.Join(err, p.leaf.close())
		p.tunnel.stop()
		p.tunnel.data.close()
	}
	// Removed peers may still have openers publishing into the shared queue.
	// Join those as well as deferred closes before its final drain.
	m.cleanupWG.Wait()
	err = errors.Join(err, m.cleanupErr)
	for {
		select {
		case result := <-m.opened:
			if result.device != nil {
				err = errors.Join(err, result.device.Close())
			}
		default:
			return err
		}
	}
}

// packetFacts uses only the worker's settled projection and the current SA.
func (m *meshRuntime) packetFacts(p *meshPeer, view corestate.View, now time.Time, facts *packetAuthorization) bool {
	pipeline := p.leaf.pipeline
	if pipeline == nil {
		return false
	}
	if m.policy == nil {
		return pipeline.prepareSnapshotInto(&p.config, view, p.plan, now, facts)
	}
	projection, _ := m.policy.project(p, m.state.Store().VerifiedRevision(), now)
	return projection.packetFacts(pipeline, now, facts)
}

func (m *meshRuntime) projectedPlan(p *meshPeer, now time.Time) (GatewayPlan, bool) {
	projection, pending := m.policy.project(p, m.state.Store().VerifiedRevision(), now)
	if pending {
		return GatewayPlan{}, true
	}
	if projection == nil || projection.binding != p.tunnel.localAuthorization {
		return GatewayPlan{}, false
	}
	return projection.plan, false
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
		select {
		case m.leafIntents <- struct{}{}:
		default:
		}
	}
	for _, p := range m.ordered() {
		if p.tunnel.phase != 3 {
			continue
		}
		revision := m.state.Store().VerifiedRevision()
		projection, pending := m.policy.project(p, revision, now)
		if pending || projection == nil || projection.plan.Selected == nil || projection.binding != p.tunnel.localAuthorization ||
			!p.tunnel.current(projection.plan) || !p.tunnel.data.current(p.tunnel.generation, p.tunnel.data.active, projection.plan) ||
			!now.Before(p.tunnel.ikeExpiresAt) || !now.Before(p.tunnel.expiresAt) {
			continue
		}
		want := projection.attachment
		want.generation, want.id = p.tunnel.generation, m.id
		err := p.leaf.reconcilePrepared(m.ctx, &p.config, revision, p.tunnel, m.id, now, want, projection.attachmentErr)
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
			plan, pending := m.projectedPlan(p, now)
			if pending {
				continue
			}
			if err := p.tunnel.tickWithScheduler(plan, now, func(request ikeTimerRequest) {
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
			var facts packetAuthorization
			if m.packetFacts(p, corestate.View{}, time.Now(), &facts) {
				p.leaf.pipeline.tickPrepared(&facts)
			}
			m.noteSequence(p)
		}
	}
	return nil
}

func (m *meshRuntime) invalidate() error {
	for _, p := range m.ordered() {
		if p.tunnel.phase != 0 {
			plan, pending := m.projectedPlan(p, time.Now())
			if !pending && !p.tunnel.current(plan) {
				m.stopPeer(p, "verified authorization withdrawn")
			}
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
	plan, pending := m.projectedPlan(p, now)
	if pending {
		if packet.peer == p.tunnel.peer && len(p.ikeInbox) < meshIKEPendingResponses {
			p.ikeInbox = append(p.ikeInbox, packet)
		}
		return nil
	}
	m.enqueueIKEResponse(p, packet, plan, now)
	return nil
}

func (m *meshRuntime) handleESP(packet tunnelDatagram) {
	m.receiveESP(packet)
}

func (m *meshRuntime) prepareCompletion(completion *dataplaneCompletion, now time.Time, facts *packetAuthorization) *meshPeer {
	p := m.byData[completion.job.owner]
	if p == nil {
		completion.timing.Finish(fixturePacketTimingCanceled)
		return nil
	}
	if !m.packetFacts(p, corestate.View{}, now, facts) {
		completion.timing.Finish(fixturePacketTimingRejected)
		return nil
	}
	p.tunnel.observeData(*completion, facts.plan, now)
	p.leaf.pipeline.leaf.SynchronizeSequence(m.seqno)
	return p
}

func (m *meshRuntime) failDelivery(p *meshPeer, err error) {
	m.logger.Warn("leaf_packet_failed", "error", errors.Join(err, p.leaf.stop()))
}

func (m *meshRuntime) completeOpen(result leafOpenResult) error {
	for _, p := range m.peers {
		if p.leaf != result.owner {
			continue
		}
		now, revision := time.Now(), m.state.Store().VerifiedRevision()
		projection, pending := m.policy.project(p, revision, now)
		var want leafAttachment
		var intentErr error
		if !pending && projection != nil && projection.attachmentErr == nil && p.tunnel.phase == 3 && p.tunnel.failed == nil &&
			projection.binding == p.tunnel.localAuthorization && p.tunnel.current(projection.plan) &&
			p.tunnel.data.current(p.tunnel.generation, p.tunnel.data.active, projection.plan) &&
			now.Before(p.tunnel.ikeExpiresAt) && now.Before(p.tunnel.expiresAt) {
			want = projection.attachment
			want.generation, want.id = p.tunnel.generation, m.id
		}
		err := p.leaf.completePrepared(m.ctx, &p.config, revision, p.tunnel, m.id, now, result, want, intentErr)
		if errors.Is(err, errPacketDeviceConflict) || errors.Is(err, errPacketDeviceRecoveryExpired) {
			return err
		}
		if err != nil {
			m.logger.Warn("leaf_device_failed", "error", err)
		}
		return nil
	}
	if result.device != nil {
		m.retireDevice(result.device)
	}
	return nil
}

type meshChoice struct {
	peer  *meshPeer
	facts packetAuthorization
	route sadr.Route
	flow  dataplaneFlow
}

// Only locally originated packets enter selection. RFC 9079 destination then
// source specificity precedes cost; a stable address hash spreads equal paths.
func (m *meshRuntime) selectRoute(packet []byte, view corestate.View, now time.Time) meshChoice {
	flow, ok := parseDataplaneFlow(packet)
	source, destination := flow.source, flow.destination
	if !ok || !businessAddress(source) || !businessAddress(destination) {
		return meshChoice{}
	}
	var best meshChoice
	var ties []meshChoice
	for _, p := range m.ordered() {
		pipeline := p.leaf.pipeline
		if pipeline == nil {
			continue
		}
		var facts packetAuthorization
		if !m.packetFacts(p, view, now, &facts) || !pipeline.localAddress(source, facts.localOrigins) {
			continue
		}
		var route sadr.Route
		var ok bool
		if facts.projection != nil {
			// Babel admits updates with this installed signed policy. The
			// policy owner prunes the table before replacing the projection.
			route, ok = pipeline.leaf.LookupInstalledRoute(source, destination, now)
		} else {
			route, ok = pipeline.leaf.LookupRoute(source, destination, now, facts.authorizeRoute)
		}
		if !ok {
			continue
		}
		candidate := meshChoice{peer: p, facts: facts, route: route, flow: flow}
		if best.peer == nil {
			best = candidate
			continue
		}
		r, b := route, best.route
		d, s, bd, bs := r.Destination.Bits(), max(0, r.Source.Bits()), b.Destination.Bits(), max(0, b.Source.Bits())
		if d < bd || d == bd && s < bs || d == bd && s == bs && r.Metric > b.Metric {
			continue
		}
		if d > bd || s > bs || r.Metric < b.Metric {
			best, ties = candidate, ties[:0]
			continue
		}
		if len(ties) == 0 {
			ties = append(ties, best)
		}
		ties = append(ties, candidate)
	}
	if len(ties) == 0 {
		return best
	}
	hash := fnv.New32a()
	_, _ = hash.Write(source.AsSlice())
	_, _ = hash.Write(destination.AsSlice())
	return ties[int(hash.Sum32()%uint32(len(ties)))]
}

// Recheck the attachment, SA and policy across concurrent control updates.
// Route selection stays committed for packets already prepared by the sender.
func (m *meshRuntime) currentHost(completion *meshHostCompletion, now time.Time) *meshPeer {
	job := completion.job
	p := m.byData[job.owner]
	if p == nil || p.leaf.pipeline != completion.pipeline || !completion.pipeline.attached(now) ||
		job.generation != job.owner.generation || job.sa != job.owner.active || job.ctx.Err() != nil ||
		completion.projection != nil && !p.policy.accepts(completion.projection, now) {
		return nil
	}
	return p
}

func (m *meshRuntime) prepareHost(event leafDevicePacket) (meshHostCompletion, bool) {
	event.timing.Dequeue()
	if event.err != nil {
		event.timing.Finish(fixturePacketTimingRejected)
		if m.device.current(event.generation) {
			m.stopAll(event.err.Error())
		}
		return meshHostCompletion{}, false
	}
	if !m.device.current(event.generation) {
		event.timing.Finish(fixturePacketTimingRejected)
		return meshHostCompletion{}, false
	}
	choice := m.selectRoute(event.packet, corestate.View{}, time.Now())
	if choice.peer == nil {
		event.timing.Finish(fixturePacketTimingRejected)
		return meshHostCompletion{}, false
	}
	event.timing.Classify(fixturePacketTimingBusiness)
	pipeline := choice.peer.leaf.pipeline
	// Selection already checked the advertised origin and learned route in
	// this owner turn. The device and exact signed host assignment still
	// have to authorize this source, regardless of the advertised prefix.
	if !pipeline.assignedHost(&choice.facts, choice.flow.source) {
		event.timing.Finish(fixturePacketTimingRejected)
		return meshHostCompletion{}, false
	}
	data := choice.peer.tunnel.data
	sa := data.active
	if !data.current(pipeline.generation, sa, choice.facts.plan) || !choice.flow.matches(sa, true) {
		event.timing.Finish(fixturePacketTimingRejected)
		return meshHostCompletion{}, false
	}
	job := dataplaneJob{owner: data, ctx: data.generationCtx, generation: data.generation, sa: sa, packet: event.packet, outbound: true}
	return meshHostCompletion{dataplaneCompletion{job: job, timing: event.timing}, pipeline, choice.facts.projection}, true
}

func (m *meshRuntime) ready() bool {
	for _, p := range m.ordered() {
		var facts packetAuthorization
		if m.packetFacts(p, corestate.View{}, time.Now(), &facts) && p.leaf.readyPrepared(&facts) {
			return true
		}
	}
	return false
}

// Network replacement invalidates every peer's old endpoint reservation. This
// is the only shared transport teardown; ordinary peer failures stay isolated.
func (m *meshRuntime) reset(reason string) {
	for _, p := range m.ordered() {
		m.stopPeerWithEvent(p, "network_rebind", reason)
		p.setPlan(GatewayPlan{outerFamily: p.plan.outerFamily})
	}
}

// A wildcard socket can send on the new route without replacing its
// reservations. Preserve each negotiated SA; other peers reconnect.
func (m *meshRuntime) roam(now time.Time) bool {
	if !m.config.Gateway.MOBIKE || !m.socket.LocalAddr().AddrPort().Addr().Unmap().IsUnspecified() {
		return false
	}
	peers := m.ordered()
	if !slices.ContainsFunc(peers, func(p *meshPeer) bool { return p.tunnel.mobike }) {
		return false
	}
	for _, p := range peers {
		if p.tunnel.mobike {
			p.tunnel.requestMOBIKE(now)
		} else if p.tunnel.phase != 0 || p.starting != nil {
			m.stopPeerWithEvent(p, "network_rebind", "mobike_not_negotiated")
		}
	}
	return true
}

func (m *meshRuntime) noteSequence(p *meshPeer) {
	if p.leaf.pipeline == nil || p.leaf.pipeline.leaf == nil {
		return
	}
	seqno := p.leaf.pipeline.leaf.OriginSequence()
	if int16(seqno-m.seqno) <= 0 {
		return
	}
	m.seqno = seqno
	for _, p := range m.ordered() {
		if p.leaf.pipeline != nil && p.leaf.pipeline.leaf != nil {
			p.leaf.pipeline.leaf.SynchronizeSequence(m.seqno)
		}
	}
}
