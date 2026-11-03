package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
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
	config           *Config
	logger           *slog.Logger
	started          atomic.Bool
	ready            chan struct{}
	observations     chan meshObservationRequest
	lifecycle        sync.Mutex
	runCancel        context.CancelFunc
	runErr           error
	rebind           chan rebindRequest
	plans            chan chan gatewayPlanSample
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
	return &Daemon{config: config, logger: logger, ready: make(chan struct{}), observations: make(chan meshObservationRequest), rebind: make(chan rebindRequest), plans: make(chan chan gatewayPlanSample), done: make(chan struct{}), planGateway: PlanGateway, deviceFactory: openConfiguredPacketDevice, watchResume: watchPowerResume, resolveBootstrap: resolveGossipBootstrap}
}

type gatewayPlanSample struct {
	plan  GatewayPlan
	store *corestate.Store
}

// GatewayPlan returns a detached, freshly revalidated connection plan. It does
// not report an established tunnel or authorize route installation.
func (d *Daemon) GatewayPlan(ctx context.Context) (GatewayPlan, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := make(chan gatewayPlanSample, 1)
	select {
	case d.plans <- result:
	case <-d.done:
		return GatewayPlan{}, net.ErrClosed
	case <-ctx.Done():
		return GatewayPlan{}, ctx.Err()
	}
	select {
	case sample := <-result:
		return RevalidateGatewayPlan(d.config, sample.store.ReadView(), sample.plan, time.Now()), nil
	case <-d.done:
		return GatewayPlan{}, net.ErrClosed
	case <-ctx.Done():
		return GatewayPlan{}, ctx.Err()
	}
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
	if !d.started.CompareAndSwap(false, true) {
		d.lifecycle.Unlock()
		return errors.New("Windows daemon already started")
	}
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
	bootstrap, err := d.resolveBootstrap(ctx, config, listenAddr)
	if err != nil {
		if ctx.Err() != nil {
			return ctx.Err()
		}
		// Offline startup must retain IPC and the join request. The existing
		// planner refreshes these address hints; peer IDs remain configured.
		logger.Warn("gossip_bootstrap_refresh_failed", "error", err)
		bootstrap = make(map[string]*net.UDPAddr)
	}
	var peers []string
	for _, hint := range config.Gateway.BootstrapHints {
		peers = append(peers, string(hint.Peer))
	}
	driver := corehost.NewGossipDriver(nil, 0, state.Store(), corehost.GossipDriverConfig{
		PeerID: string(config.ManagedZone), Limits: corestate.DefaultSyncLimits(),
		Discovery: corehost.GossipDiscoveryConfig{Bootstrap: bootstrap, BootstrapPeers: peers},
		Log: func(record corehost.GossipDriverLog) {
			level := slog.LevelDebug
			switch record.Level {
			case "info":
				level = slog.LevelInfo
			case "warn":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			}
			attrs := []any{"peer", record.PeerID, "phase", record.Phase}
			if record.Err != nil {
				attrs = append(attrs, "error", record.Err)
			}
			for key, value := range record.Fields {
				attrs = append(attrs, key, value)
			}
			logger.Log(ctx, level, record.Event, attrs...)
		},
	})
	defer driver.Stop()
	packet, err := openPacketSockets(ctx, config.GossipListen)
	if err != nil {
		return fmt.Errorf("listen gossip UDP: %w", err)
	}
	defer packet.Close()
	transport, err := gossip.NewTransport(gossip.Config{PeerID: string(config.ManagedZone), KnownPeers: bootstrap}, packet)
	if err != nil {
		return err
	}
	if err := driver.StartGossipObjectPullServer(ctx, gossipListener{packet}, 0, 0); err != nil {
		return err
	}
	executor := corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{
		Client: objectPullClient{}, Discovery: func() corehost.GossipDiscoveryInput { return driver.GossipDiscoveryInput(nil) },
	})
	if err := driver.StartGossipObjectPullWorkers(ctx, executor, 0, 0); err != nil {
		return err
	}
	if err := driver.RefreshGossipDiscovery(ctx, nil, time.Now(), transport); err != nil {
		return err
	}
	if err := driver.StartGossipTransport(ctx, transport, func(err error) { logger.Warn("gossip_receive_failed", "error", err) }); err != nil {
		return err
	}
	networkChanges, stopNetworkChanges, err := watchNetworkChanges(ctx)
	if err != nil {
		return fmt.Errorf("watch network changes: %w", err)
	}
	defer func() { err = errors.Join(err, stopNetworkChanges()) }()
	powerResumes, stopPowerResumes, err := d.watchResume(ctx)
	if err != nil {
		return fmt.Errorf("watch power resume: %w", err)
	}
	defer func() { err = errors.Join(err, stopPowerResumes()) }()
	logger.Info("gossip_started", "address", packet.LocalAddr().String(), "zone", config.ManagedZone, "tunnel_ready", false)
	type planRequest struct {
		ctx        context.Context
		generation uint64
	}
	type planResult struct {
		generation   uint64
		plan         GatewayPlan
		bootstrap    map[string]*net.UDPAddr
		bootstrapErr error
	}
	planRequests := make(chan planRequest, 1)
	plans := make(chan planResult, 1)
	plannerCtx, stopPlanner := context.WithCancel(ctx)
	var plannerWG sync.WaitGroup
	plannerWG.Add(1)
	go func() {
		defer plannerWG.Done()
		for {
			select {
			case <-plannerCtx.Done():
				return
			case request := <-planRequests:
				bootstrap, bootstrapErr := d.resolveBootstrap(request.ctx, config, listenAddr)
				view := state.Store().ReadView()
				plan := d.planGateway(request.ctx, config, view, time.Now())
				plan = RevalidateGatewayPlan(config, view, plan, time.Now())
				select {
				case plans <- planResult{request.generation, plan, bootstrap, bootstrapErr}:
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
	ikeDone := make(chan struct{})
	go func() {
		defer close(ikeDone)
		mesh.runIKEStarts(ikeCtx)
	}()
	ikeWritesDone := make(chan struct{})
	go func() {
		defer close(ikeWritesDone)
		mesh.runIKEWrites(ikeCtx)
	}()
	ikeResponsesDone := make(chan struct{})
	go func() {
		defer close(ikeResponsesDone)
		mesh.runIKEResponses(ikeCtx)
	}()
	defer func() {
		stopIKE()
		<-ikeDone
		<-ikeResponsesDone
		<-ikeWritesDone
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
	rebindPending := false
	rebind := func(rebindCtx context.Context) error {
		rebindCtx, cancelRebind := context.WithCancel(rebindCtx)
		stopCancel := context.AfterFunc(ctx, cancelRebind)
		defer stopCancel()
		defer cancelRebind()
		mesh.reset()
		observeReady()
		err := packet.Rebind(rebindCtx)
		lastPlan = GatewayPlan{}
		rebindPending = err != nil && ctx.Err() == nil
		if err != nil {
			logger.Warn("gossip_rebind_failed", "error", err)
		} else {
			logger.Info("gossip_rebound", "address", packet.LocalAddr().String())
		}
		requestPlan()
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
	close(d.ready)
	for {
		select {
		case <-ctx.Done():
			return nil
		case result := <-d.plans:
			result <- gatewayPlanSample{lastPlan, state.Store()}
		case sampled := <-observationSnapshots:
			sampled <- mesh.observationSnapshot(lastPlan)
		case result := <-mesh.policy.results:
			mesh.policy.finish(result, state.Store().VerifiedRevision(), time.Now())
			if held := result.request.peer.heldResponse; held != nil {
				if err := mesh.finishIKEResponse(*held); err != nil {
					return err
				}
			}
		case failure := <-mesh.ikeWriteFailures:
			if peer := mesh.findGeneration(failure.generation); peer != nil {
				mesh.stopPeer(peer, failure.err.Error())
			}
		case prepared := <-mesh.ikePrepared:
			mesh.finishIKEStart(prepared)
		case response := <-mesh.ikeResponded:
			if err := mesh.finishIKEResponse(response); err != nil {
				return err
			}
			observeReady()
		case datagram := <-packet.ikePackets:
			if err := mesh.handleIKE(datagram); err != nil {
				return err
			}
			observeReady()
		case datagram := <-packet.espPackets:
			// Give a receive burst a bounded turn before competing again with
			// host sends and control work. Keep ESP processing in FIFO order
			// on this owner so replay state and SA lifetimes stay serialized.
			mesh.handleESPBatch(ctx, packet.espPackets, datagram)
		case job := <-mesh.jobs:
			if job.ctx.Err() == nil {
				mesh.complete(executeDataplaneJob(job))
			}
		case result := <-mesh.opened:
			if err := mesh.completeOpen(result); err != nil {
				return err
			}
		case event := <-mesh.device.packets:
			mesh.handleHost(event)
		case <-tunnelTicker.C:
			if err := mesh.tick(); err != nil {
				return err
			}
			observeReady()
		case result := <-plans:
			if result.generation != generation || result.plan.Revision != state.Store().VerifiedRevision() {
				continue
			}
			if result.bootstrapErr != nil {
				logger.Warn("gossip_bootstrap_refresh_failed", "error", result.bootstrapErr)
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
			mesh.update(lastPlan)
			observeReady()
		case request := <-d.rebind:
			request.result <- rebind(request.ctx)
			refreshGossip()
		case <-packet.failed:
			if ctx.Err() == nil {
				_ = rebind(ctx)
				refreshGossip()
			}
		case _, ok := <-powerResumes:
			if !ok {
				powerResumes = nil
				continue
			}
			if ctx.Err() == nil {
				logger.Info("power_resumed")
				_ = rebind(ctx)
				refreshGossip()
			}
		case _, ok := <-networkChanges:
			if !ok {
				networkChanges = nil
				continue
			}
			if ctx.Err() == nil {
				_ = rebind(ctx)
				refreshGossip()
			}
		case <-ticker.C:
			if rebindPending {
				_ = rebind(ctx)
			}
			requestPlan()
			refreshGossip()
		case <-gossipPublished:
			if err := mesh.invalidate(); err != nil {
				return err
			}
			requestPlan()
			observeReady()
		case err := <-gossipDone:
			gossipExited = true
			return err
		}
	}
}

type objectPullClient struct{}

func (objectPullClient) Exchange(ctx context.Context, addr string, request *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	conn, err := (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, "tcp", addr)
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
