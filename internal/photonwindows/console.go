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
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
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

// Daemon owns one run of the Windows composition. Rebind is serialized with
// gossip event processing; it does not recreate state or the protocol driver.
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
	planGateway      func(context.Context, *Config, corestate.View, time.Time) GatewayPlan
	deviceFactory    packetDeviceFactory
	watchResume      func(context.Context) (<-chan struct{}, func() error, error)
	resolveBootstrap func(context.Context, *Config, netip.AddrPort) (map[string]*net.UDPAddr, error)
}

type rebindRequest struct {
	ctx    context.Context
	result chan error
}

func NewDaemon(config *Config, logger *slog.Logger) *Daemon {
	return &Daemon{instanceID: rand.Text(), config: config, logger: logger, ready: make(chan struct{}), observations: make(chan meshObservationRequest), rebind: make(chan rebindRequest), serviceInputs: make(chan chan serviceInputs), done: make(chan struct{}), planGateway: PlanGateway, deviceFactory: openConfiguredPacketDevice, watchResume: watchPowerResume, resolveBootstrap: resolveGossipBootstrap}
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
	ctx = context.WithValue(ctx, outboundDNSKey{}, newControlDNS())
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
	var plannerWG sync.WaitGroup
	plannerWG.Add(1)
	go func() {
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
		for {
			select {
			case <-plannerCtx.Done():
				return
			case request := <-planRequests:
				bootstrap, bootstrapErr := d.resolveBootstrap(request.ctx, config, listenAddr)
				view := state.Store().ReadView()
				now := time.Now()
				observeGateways(view, now)
				plan := d.planGateway(request.ctx, config, view, now)
				plan = RevalidateGatewayPlan(config, view, plan, time.Now())
				paths := networkRouteTargets{splitRoutes: config.Overlay.SplitRoutes}
				paths.update(plan, bootstrap, gossipRouteTargets(view, time.Now())...)
				select {
				case plans <- planResult{request.generation, plan, bootstrap, bootstrapErr, paths.load()}:
				case <-plannerCtx.Done():
				}
			}
		}
	}()
	var generation uint64
	cancelPlan := func() {}
	defer func() { cancelPlan(); stopPlanner(); plannerWG.Wait() }()
	requestPlan := func() {
		cancelPlan()
		generation++
		var requestCtx context.Context
		// Finish before the five-second periodic refresh, including slow DNS.
		requestCtx, cancelPlan = context.WithTimeout(plannerCtx, 3*time.Second)
		request := planRequest{requestCtx, generation}
		select {
		case <-planRequests:
		default:
		}
		planRequests <- request
	}
	var lastPlan GatewayPlan
	mesh := newMeshRuntime(ctx, config, state, packet, d.deviceFactory, logger, requestPlan)
	defer func() { err = errors.Join(err, mesh.close()) }()
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
	rebind := func(rebindCtx context.Context, reason string) error {
		rebindCtx, cancelRebind := context.WithCancel(rebindCtx)
		stopCancel := context.AfterFunc(ctx, cancelRebind)
		defer stopCancel()
		defer cancelRebind()
		mesh.stateMu.Lock()
		mesh.reset(reason)
		observeReady()
		mesh.stateMu.Unlock()
		err := packet.Rebind(rebindCtx)
		lastPlan = GatewayPlan{}
		rebindPending = ""
		if err != nil {
			if ctx.Err() == nil {
				rebindPending = reason
			}
			gossipLog.Warn("gossip_rebind_failed", "reason", reason, "error", err)
		} else {
			gossipLog.Info("gossip_rebound", "reason", reason, "address", packet.LocalAddr().String())
		}
		requestPlan()
		return err
	}
	roam := func(reason string) error {
		mesh.stateMu.Lock()
		preserved := rebindPending == "" && mesh.roam(time.Now())
		var err error
		if preserved {
			err = mesh.tick()
			observeReady()
		}
		mesh.stateMu.Unlock()
		if preserved {
			requestPlan()
		} else {
			_ = rebind(ctx, reason)
		}
		return err
	}
	gossipCtx, stopGossip := context.WithCancel(ctx)
	gossipRefresh := make(chan map[string]*net.UDPAddr, 1)
	gossipPublished := make(chan struct{}, 1)
	gossipDone := make(chan error, 1)
	go func(initial map[string]*net.UDPAddr) {
		gossipDone <- runMeshGossip(gossipCtx, config, state, driver, transport, logger, initial, gossipRefresh, mesh.leafIntents, gossipPublished)
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
		case <-tunnelTicker.C:
			mesh.stateMu.Lock()
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
			networkTargets.publish(result.paths)
			mesh.stateMu.Lock()
			mesh.update(lastPlan)
			observeReady()
			mesh.stateMu.Unlock()
		case request := <-d.rebind:
			request.result <- rebind(request.ctx, "manual_rebind")
			refreshGossip()
		case <-packet.failed:
			if ctx.Err() == nil {
				_ = rebind(ctx, "socket_failed")
				refreshGossip()
			}
		case _, ok := <-powerResumes:
			if !ok {
				powerResumes = nil
				continue
			}
			if ctx.Err() == nil {
				logger.Info("power_resumed")
				packet.outboundRoutes.invalidate()
				if err := roam("system_resumed"); err != nil {
					return err
				}
				refreshGossip()
			}
		case _, ok := <-networkChanges:
			if !ok {
				networkChanges = nil
				continue
			}
			if ctx.Err() == nil {
				if err := roam("outer_path_changed"); err != nil {
					return err
				}
				refreshGossip()
			}
		case <-ticker.C:
			if rebindPending != "" {
				if err := rebind(ctx, rebindPending); err == nil {
					refreshGossip()
				}
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
