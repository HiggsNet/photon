package photonwindows

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"slices"
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// RunConsole owns the common state and gossip resources until cancellation.
// Absent state initializes a stable pending identity; admission remains driven
// by verified parent delegation synchronized through the shared GossipDriver.
func RunConsole(ctx context.Context, config *Config, logger *slog.Logger) error {
	if config == nil {
		return errors.New("Windows config is required")
	}
	return RunControlled(ctx, NewDaemon(config, logger), config.State.Path)
}

// Daemon owns one run of the Windows composition. The event loop coordinates
// socket replacement with tunnel state while a worker owns the socket I/O.
type Daemon struct {
	instanceID       string
	config           *Config
	logger           *slog.Logger
	started          bool // Guarded by lifecycle; each Daemon owns exactly one run.
	ready            chan struct{}
	observations     chan meshObservationRequest
	lifecycle        sync.Mutex
	runCancel        context.CancelFunc
	runErr           error
	rebind           chan rebindRequest
	serviceInputs    chan chan serviceInputs
	done             chan struct{}
	planGateway      func(context.Context, *Config, corestate.View, time.Time, ipsec.DNSResolver) GatewayPlan
	deviceFactory    packetDeviceFactory
	watchResume      func(context.Context) (<-chan struct{}, func() error, error)
	resolveBootstrap func(context.Context, *Config, netip.AddrPort) (map[string]*net.UDPAddr, error)
	rebindSocket     func(*packetSockets, context.Context) error
}

type rebindRequest struct {
	ctx    context.Context
	result chan error
}

func NewDaemon(config *Config, logger *slog.Logger) *Daemon {
	return &Daemon{instanceID: rand.Text(), config: config, logger: logger, ready: make(chan struct{}), observations: make(chan meshObservationRequest), rebind: make(chan rebindRequest), serviceInputs: make(chan chan serviceInputs), done: make(chan struct{}), planGateway: planGateway, deviceFactory: openConfiguredPacketDevice, watchResume: watchPowerResume, resolveBootstrap: resolveGossipBootstrap, rebindSocket: (*packetSockets).Rebind}
}

// Rebind waits for a local socket replacement, bounded by the caller's context.
func (d *Daemon) Rebind(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	request := rebindRequest{ctx: ctx, result: make(chan error, 1)}
	select {
	case d.rebind <- request:
	case <-d.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case err := <-request.result:
		return err
	case <-d.done:
		return net.ErrClosed
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Daemon) Run(ctx context.Context) (err error) {
	d.lifecycle.Lock()
	if d.started {
		d.lifecycle.Unlock()
		return errors.New("Windows daemon already started")
	}
	d.started = true
	ctx, runCancel := context.WithCancel(ctx)
	d.runCancel = runCancel
	d.lifecycle.Unlock()
	defer func() {
		runCancel()
		d.lifecycle.Lock()
		d.runErr = err
		close(d.done)
		d.lifecycle.Unlock()
	}()
	config, logger := d.config, d.logger
	if config == nil {
		return errors.New("Windows config is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if logger == nil {
		logger = slog.Default()
	}
	gossipLog := logger.With("component", "gossip")
	listenAddr, err := netip.ParseAddrPort(config.GossipListen)
	if err != nil {
		return fmt.Errorf("gossip_listen: %w", err)
	}
	state, err := OpenOrInitializeState(config, time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, state.Close()) }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	ikeTrace := startIKETrace(logger)
	defer ikeTrace.close()
	if _, ok := ctx.Value(outboundDNSKey{}).(outboundDNS); !ok {
		ctx = context.WithValue(ctx, outboundDNSKey{}, newControlDNS())
	}
	bootstrap, err := d.resolveBootstrap(ctx, config, listenAddr)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Offline startup must retain IPC and the join request. The existing
		// planner refreshes these address hints; peer IDs remain configured.
		gossipLog.Warn("gossip_bootstrap_refresh_failed", "error", err)
		bootstrap = make(map[string]*net.UDPAddr)
	}
	var peers []string
	for _, hint := range config.Gateway.BootstrapHints {
		peers = append(peers, string(hint.Peer))
	}
	driver := corehost.NewGossipDriver(nil, 0, state.Store(), corehost.GossipDriverConfig{
		PeerID: string(config.ManagedZone), Limits: corestate.DefaultSyncLimits(),
		Discovery: corehost.GossipDiscoveryConfig{Bootstrap: bootstrap, BootstrapPeers: peers},
		Log:       logger.Handler(),
	})
	defer driver.Stop()
	packet, err := openPacketSockets(ctx, config.GossipListen)
	if err != nil {
		return fmt.Errorf("listen gossip UDP: %w", err)
	}
	defer packet.Close()
	packet.ikeTrace = ikeTrace
	packet.configureOutboundRoutes(listenAddr.Addr(), config.Overlay.SplitRoutes)
	transport, err := gossip.NewTransport(gossip.Config{PeerID: string(config.ManagedZone), KnownPeers: bootstrap}, packet)
	if err != nil {
		return err
	}
	if err := driver.StartGossipObjectPullServer(ctx, gossipListener{packet}, 0, 0); err != nil {
		return err
	}
	executor := corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{
		Client:    objectPullClient{routes: packet.outboundRoutes},
		Discovery: driver.GossipPeerDiscoveryInput,
	})
	if err := driver.StartGossipObjectPullWorkers(ctx, executor, 0, 0); err != nil {
		return err
	}
	if err := driver.RefreshGossipDiscovery(time.Now(), transport); err != nil {
		return err
	}
	if err := driver.StartGossipTransport(ctx, transport, func(err error) { gossipLog.Warn("gossip_receive_failed", "error", err) }); err != nil {
		return err
	}
	networkTargets := networkRouteTargets{splitRoutes: config.Overlay.SplitRoutes, changed: make(chan struct{}, 1)}
	networkTargets.update(GatewayPlan{}, bootstrap)
	networkChanges, stopNetworkChanges, err := watchNetworkChangesForTargets(ctx, &networkTargets, packet.outboundRoutes)
	if err != nil {
		return fmt.Errorf("watch network changes: %w", err)
	}
	defer func() { err = errors.Join(err, stopNetworkChanges()) }()
	powerResumes, stopPowerResumes, err := d.watchResume(ctx)
	if err != nil {
		return fmt.Errorf("watch power resume: %w", err)
	}
	defer func() { err = errors.Join(err, stopPowerResumes()) }()
	gossipLog.Info("gossip_started", "address", packet.LocalAddr().String(), "zone", config.ManagedZone, "tunnel_ready", false)
	type planRequest struct {
		ctx        context.Context
		generation uint64
		network    uint64
	}
	type planResult struct {
		generation   uint64
		plan         GatewayPlan
		bootstrap    map[string]*net.UDPAddr
		bootstrapErr error
		paths        []netip.Addr
	}
	planRequests := make(chan planRequest, 1)
	plans := make(chan planResult, 1)
	plannerCtx, stopPlanner := context.WithCancel(ctx)
	initialView := state.Store().ReadView()
	dns := newGatewayDNS()
	dns.reset(plannerCtx)
	var plannerWG sync.WaitGroup
	for range gatewayDNSWorkers {
		plannerWG.Go(func() { dns.resolve(plannerCtx, controlDNS(plannerCtx)) })
	}
	plannerWG.Add(1)
	go func(initialBootstrap map[string]*net.UDPAddr) {
		defer plannerWG.Done()
		var lastCandidates []GatewayCandidate
		observeGateways := func(view corestate.View, now time.Time) {
			candidates := GatewayCandidates(config, view, now)
			if !reflect.DeepEqual(lastCandidates, candidates) {
				logger.Info("gateway_candidates_changed", "revision", view.Revision, "evaluated_at", now,
					"candidates", candidates, "tunnel_ready", false, "route_authorized", false)
				lastCandidates = candidates
			}
		}
		observeGateways(initialView, time.Now())
		var request planRequest
		var dnsChanged <-chan time.Time
		bootstrap := initialBootstrap
		publishPlan := func(bootstrapErr error) {
			view := state.Store().ReadView()
			now := time.Now()
			dns.beginPlan(now)
			plan := d.planGateway(request.ctx, config, view, now, dns)
			dns.endPlan()
			paths := networkRouteTargets{splitRoutes: config.Overlay.SplitRoutes}
			paths.update(plan, bootstrap, gossipRouteTargets(view, now)...)
			select {
			case plans <- planResult{request.generation, plan, bootstrap, bootstrapErr, paths.load()}:
			case <-plannerCtx.Done():
			}
		}
		for {
			jobs, job := dns.next()
			select {
			case <-plannerCtx.Done():
				return
			case next := <-planRequests:
				if next.network != request.network {
					dns.reset(plannerCtx)
				}
				request = next
				nextBootstrap, err := d.resolveBootstrap(request.ctx, config, listenAddr)
				if err == nil {
					bootstrap = nextBootstrap
				}
				observeGateways(state.Store().ReadView(), time.Now())
				publishPlan(err)
			case jobs <- job:
				dns.dispatched()
			case result := <-dns.results:
				if dns.complete(result, time.Now()) && dnsChanged == nil {
					dnsChanged = time.After(gatewayDNSPlanDelay)
				}
			case <-dnsChanged:
				dnsChanged = nil
				if request.ctx.Err() == nil {
					publishPlan(nil)
				}
			}
		}
	}(bootstrap)
	var generation uint64
	var networkGeneration uint64
	type socketReplacement struct {
		done   <-chan error
		reply  chan<- error
		cancel context.CancelFunc
		reason string
	}
	var replacement socketReplacement
	cancelPlan := func() {}
	defer func() { cancelPlan(); stopPlanner(); plannerWG.Wait() }()
	requestPlan := func() {
		if replacement.done != nil {
			return
		}
		cancelPlan()
		generation++
		var requestCtx context.Context
		requestCtx, cancelPlan = context.WithCancel(plannerCtx)
		request := planRequest{requestCtx, generation, networkGeneration}
		select {
		case <-planRequests:
		default:
		}
		planRequests <- request
	}
	var lastPlan GatewayPlan
	mesh := newMeshRuntime(ctx, config, state, packet, d.deviceFactory, logger, requestPlan)
	defer func() { err = errors.Join(err, mesh.close()) }()
	proxyCtx, stopProxy := context.WithCancel(ctx)
	if config.proxyV2 != nil {
		mesh.proxyDirect = newProxyDirectHost(proxyCtx, mesh)
	}
	defer stopProxy()
	ikeCtx, stopIKE := context.WithCancel(ctx)
	var ikeWorkers sync.WaitGroup
	ikeWorkers.Go(func() { mesh.runIKEStarts(ikeCtx) })
	ikeWorkers.Go(func() { mesh.runIKEWrites(ikeCtx) })
	ikeWorkers.Go(func() { mesh.runIKEResponses(ikeCtx) })
	defer func() {
		stopIKE()
		ikeWorkers.Wait()
	}()
	policyCtx, stopPolicy := context.WithCancel(ctx)
	policyDone := make(chan struct{})
	go func() {
		defer close(policyDone)
		mesh.policy.run(policyCtx)
	}()
	defer func() {
		stopPolicy()
		<-policyDone
	}()

	var lastReady bool
	observeReady := func() {
		ready := mesh.ready()
		if ready != lastReady {
			lastReady = ready
			logger.Info("tunnel_ready_changed", "tunnel_ready", ready)
		}
	}
	var rebindPending string
	rebindRequests := d.rebind
	startRebind := func(rebindCtx context.Context, reason string, reply chan<- error) {
		if replacement.done != nil {
			return
		}
		if err := rebindCtx.Err(); err != nil {
			if reply != nil {
				reply <- err
			}
			return
		}
		// Deny old tunnel generations and discard planner results from the
		// old network before the worker can replace the shared endpoint.
		cancelPlan()
		generation++
		networkGeneration++
		lastPlan = GatewayPlan{}
		rebindPending = ""
		mesh.stateMu.Lock()
		mesh.reset(reason)
		observeReady()
		mesh.stateMu.Unlock()
		workCtx, cancelRebind := context.WithCancel(rebindCtx)
		stopCancel := context.AfterFunc(ctx, cancelRebind)
		done := make(chan error, 1)
		replacement = socketReplacement{done: done, reply: reply, cancel: cancelRebind, reason: reason}
		// Concurrent manual requests keep their caller deadline and wait
		// for the event loop to accept them after this replacement.
		rebindRequests = nil
		go func() {
			defer cancelRebind()
			defer stopCancel()
			done <- d.rebindSocket(packet, workCtx)
		}()
	}
	defer func() {
		if replacement.done != nil {
			replacement.cancel()
			<-replacement.done
		}
	}()
	roam := func(reason string) (bool, error) {
		if replacement.done != nil {
			return false, nil
		}
		mesh.stateMu.Lock()
		preserved := rebindPending == "" && packet.bound() && mesh.roam(time.Now())
		var err error
		if preserved {
			err = mesh.tick()
			observeReady()
		}
		mesh.stateMu.Unlock()
		if preserved {
			networkGeneration++
			requestPlan()
		} else {
			startRebind(ctx, reason, nil)
		}
		return preserved, err
	}
	gossipCtx, stopGossip := context.WithCancel(ctx)
	gossipRefresh := make(chan map[string]*net.UDPAddr, 1)
	gossipPublished := make(chan struct{}, 1)
	proxyPublished := make(chan struct{}, 1)
	gossipDone := make(chan error, 1)
	go func(initial map[string]*net.UDPAddr) {
		gossipDone <- runMeshGossip(gossipCtx, config, state, driver, transport, logger, initial, gossipRefresh, mesh.leafIntents, proxyPublished, gossipPublished)
	}(bootstrap)
	gossipExited := false
	defer func() {
		stopGossip()
		if !gossipExited {
			<-gossipDone
		}
	}()
	refreshGossip := func() {
		// The worker needs the latest bootstrap snapshot, not every intermediate
		// discovery request. The packet loop never waits for Gossip to catch up.
		select {
		case <-gossipRefresh:
		default:
		}
		gossipRefresh <- bootstrap
	}
	requestPlan()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	tunnelTicker := time.NewTicker(250 * time.Millisecond)
	defer tunnelTicker.Stop()
	observationSnapshots := make(chan chan meshObservationSnapshot)
	observationCtx, cancelObservations := context.WithCancel(ctx)
	observationsDone := make(chan struct{})
	go func() {
		defer close(observationsDone)
		d.runObservations(observationCtx, observationSnapshots, state.Store(), driver)
	}()
	defer func() {
		cancelObservations()
		<-observationsDone
	}()
	packetCtx, stopPackets := context.WithCancel(ctx)
	var packetWorkers sync.WaitGroup
	packetWorkers.Go(func() { mesh.runTX(packetCtx) })
	packetWorkers.Go(func() { mesh.runRX(packetCtx) })
	defer func() {
		stopPackets()
		packetWorkers.Wait()
	}()
	if mesh.proxyDirect != nil {
		var proxyWorkers sync.WaitGroup
		proxyWorkers.Go(mesh.proxyDirect.run)
		proxyWorkers.Go(func() {
			d.runProxyV2(proxyCtx, logger, state.Store(), mesh.proxyDirect, packet.outboundRoutes, proxyPublished)
		})
		defer func() { stopProxy(); proxyWorkers.Wait() }()
	}
	close(d.ready)
	for {
		select {
		case <-ctx.Done():
			return nil
		case result := <-d.serviceInputs:
			result <- serviceInputs{plan: lastPlan, store: state.Store(), underlay: packet.outboundRoutes != nil}
		case sampled := <-observationSnapshots:
			mesh.stateMu.Lock()
			snapshot := mesh.observationSnapshot(lastPlan)
			mesh.stateMu.Unlock()
			sampled <- snapshot
		case result := <-mesh.policy.results:
			mesh.stateMu.Lock()
			mesh.policy.finish(result, state.Store().VerifiedRevision(), time.Now())
			var finishErr error
			if held := result.request.peer.heldResponse; held != nil {
				finishErr = mesh.finishIKEResponse(*held)
			}
			mesh.stateMu.Unlock()
			if finishErr != nil {
				return finishErr
			}
		case failure := <-mesh.ikeWriteFailures:
			mesh.stateMu.Lock()
			if peer := mesh.findGeneration(failure.generation); peer != nil {
				if peer.tunnel.mobike {
					peer.tunnel.waitForMOBIKEPath(time.Now())
				} else {
					mesh.stopPeer(peer, failure.err.Error())
				}
			}
			mesh.stateMu.Unlock()
		case prepared := <-mesh.ikePrepared:
			mesh.stateMu.Lock()
			mesh.finishIKEStart(prepared)
			mesh.stateMu.Unlock()
		case response := <-mesh.ikeResponded:
			mesh.stateMu.Lock()
			finishErr := mesh.finishIKEResponse(response)
			if finishErr == nil {
				observeReady()
			}
			mesh.stateMu.Unlock()
			if finishErr != nil {
				return finishErr
			}
		case datagram := <-packet.ikePackets:
			if datagram.trace != nil {
				ikeTrace.ingress(time.Now(), "ingress_dequeued", datagram, slog.Int("depth_after", len(packet.ikePackets)))
			}
			mesh.stateMu.Lock()
			handleErr := mesh.handleIKE(datagram)
			if handleErr == nil {
				observeReady()
			}
			mesh.stateMu.Unlock()
			if handleErr != nil {
				return handleErr
			}
		case result := <-mesh.opened:
			mesh.stateMu.Lock()
			openErr := mesh.completeOpen(result)
			mesh.stateMu.Unlock()
			if openErr != nil {
				return openErr
			}
		case scheduled := <-tunnelTicker.C:
			mesh.stateMu.Lock()
			if ikeTrace != nil {
				now := time.Now()
				if delay := now.Sub(scheduled); delay >= 250*time.Millisecond {
					ikeTrace.emit(ikeTrace.event(now, "tick_delayed", 0, netip.AddrPort{},
						slog.Time("scheduled_at", scheduled), slog.Int64("delay_us", delay.Microseconds()),
						slog.Int("ingress_depth", len(packet.ikePackets))))
				}
			}
			tickErr := mesh.tick()
			if tickErr == nil {
				observeReady()
			}
			mesh.stateMu.Unlock()
			if tickErr != nil {
				return tickErr
			}
		case result := <-plans:
			if result.generation != generation || result.plan.Revision != state.Store().VerifiedRevision() {
				continue
			}
			if result.bootstrapErr != nil {
				gossipLog.Warn("gossip_bootstrap_refresh_failed", "error", result.bootstrapErr)
			} else if !reflect.DeepEqual(bootstrap, result.bootstrap) {
				bootstrap = result.bootstrap
				refreshGossip()
			}
			// Revision/time are diagnostic metadata, not a change in the selected
			// target or authorization. Never report a planned target as a live SA.
			comparable, previous := result.plan, lastPlan
			comparable.Revision, previous.Revision = 0, 0
			comparable.EvaluatedAt, previous.EvaluatedAt = time.Time{}, time.Time{}
			if !reflect.DeepEqual(comparable, previous) {
				logger.Info("gateway_plan_changed", "plan", result.plan, "tunnel_ready", false)
			}
			lastPlan = result.plan
			paths := result.paths
			mesh.stateMu.Lock()
			mesh.update(lastPlan)
			// Keep watching authenticated endpoints during a DNS outage or
			// after a fresh lookup returns a different address.
			for _, peer := range mesh.peers {
				if pinned := peer.establishedGateway(); pinned != nil {
					if addr, err := netip.ParseAddr(pinned.Contact.Address); err == nil {
						paths = append(paths, addr.Unmap())
					}
				}
			}
			observeReady()
			mesh.stateMu.Unlock()
			if len(paths) != len(result.paths) {
				slices.SortFunc(paths, netip.Addr.Compare)
				paths = slices.Compact(paths)
			}
			networkTargets.publish(paths)
		case request := <-rebindRequests:
			startRebind(request.ctx, "manual_rebind", request.result)
		case rebindErr := <-replacement.done:
			reason, reply := replacement.reason, replacement.reply
			replacement = socketReplacement{}
			rebindRequests = d.rebind
			if rebindErr == nil && !packet.bound() {
				rebindErr = net.ErrClosed
			}
			if rebindErr != nil {
				rebindPending = reason
				gossipLog.Warn("gossip_rebind_failed", "reason", reason, "error", rebindErr)
			} else {
				gossipLog.Info("gossip_rebound", "reason", reason, "address", packet.LocalAddr().String())
			}
			requestPlan()
			refreshGossip()
			if reply != nil {
				reply <- rebindErr
			}
		case <-packet.failed:
			if ctx.Err() == nil && !packet.bound() {
				startRebind(ctx, "socket_failed", nil)
			}
		case _, ok := <-powerResumes:
			if !ok {
				powerResumes = nil
				continue
			}
			if ctx.Err() == nil {
				logger.Info("power_resumed")
				packet.outboundRoutes.invalidate()
				preserved, err := roam("system_resumed")
				if err != nil {
					return err
				}
				if preserved {
					refreshGossip()
				}
			}
		case _, ok := <-networkChanges:
			if !ok {
				networkChanges = nil
				continue
			}
			if ctx.Err() == nil {
				preserved, err := roam("outer_path_changed")
				if err != nil {
					return err
				}
				if preserved {
					refreshGossip()
				}
			}
		case <-ticker.C:
			if rebindPending != "" {
				startRebind(ctx, rebindPending, nil)
			}
			requestPlan()
		case <-gossipPublished:
			mesh.stateMu.Lock()
			invalidateErr := mesh.invalidate()
			if invalidateErr == nil {
				observeReady()
			}
			mesh.stateMu.Unlock()
			if invalidateErr != nil {
				return invalidateErr
			}
			requestPlan()
		case err := <-gossipDone:
			gossipExited = true
			return err
		}
	}
}

type objectPullClient struct{ routes *outboundRouteResolver }

func (c objectPullClient) Exchange(ctx context.Context, addr string, request *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	dialCtx, cancel := context.WithTimeout(ctx, 1500*time.Millisecond)
	conn, err := c.routes.dialObjectPull(dialCtx, net.Dialer{}, addr)
	cancel()
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}
	return gossip.ExchangeObjectPull(conn, request)
}
