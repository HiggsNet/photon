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
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

// RunConsole owns the common state and gossip resources until cancellation.
// It restores an existing database; initial identity admission remains explicit.
func RunConsole(ctx context.Context, config *Config, logger *slog.Logger) error {
	if config == nil {
		return errors.New("Windows config is required")
	}
	return RunControlled(ctx, NewDaemon(config, logger), config.State.Path)
}

// Daemon owns one run of the Windows composition. Rebind is serialized with
// gossip event processing; it does not recreate state or the protocol driver.
type Daemon struct {
	config        *Config
	logger        *slog.Logger
	started       atomic.Bool
	ready         chan struct{}
	observations  chan chan Observation
	lifecycle     sync.Mutex
	runCancel     context.CancelFunc
	runErr        error
	rebind        chan rebindRequest
	plans         chan chan GatewayPlan
	done          chan struct{}
	planGateway   func(context.Context, *Config, corestate.View, time.Time) GatewayPlan
	deviceFactory packetDeviceFactory
	watchResume   func(context.Context) (<-chan struct{}, func() error, error)
}

type rebindRequest struct {
	ctx    context.Context
	result chan error
}

func NewDaemon(config *Config, logger *slog.Logger) *Daemon {
	return &Daemon{config: config, logger: logger, ready: make(chan struct{}), observations: make(chan chan Observation), rebind: make(chan rebindRequest), plans: make(chan chan GatewayPlan), done: make(chan struct{}), planGateway: PlanGateway, deviceFactory: openConfiguredPacketDevice, watchResume: watchPowerResume}
}

// GatewayPlan returns a detached, freshly revalidated connection plan. It does
// not report an established tunnel or authorize route installation.
func (d *Daemon) GatewayPlan(ctx context.Context) (GatewayPlan, error) {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := make(chan GatewayPlan, 1)
	select {
	case d.plans <- result:
	case <-d.done:
		return GatewayPlan{}, net.ErrClosed
	case <-ctx.Done():
		return GatewayPlan{}, ctx.Err()
	}
	select {
	case plan := <-result:
		return plan, nil
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
	state, err := OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, state.Close()) }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	bootstrap, err := resolveGossipBootstrap(ctx, config, listenAddr)
	if err != nil {
		return err
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
		view       corestate.View
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
				bootstrap, bootstrapErr := resolveGossipBootstrap(request.ctx, config, listenAddr)
				plan := d.planGateway(request.ctx, config, request.view, time.Now())
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
		request := planRequest{requestCtx, generation, state.Store().ReadView()}
		select {
		case <-planRequests:
		default:
		}
		planRequests <- request
	}
	var lastPlan GatewayPlan
	data := newSerialGatewayDataplane(ctx)
	defer data.close()
	tunnel := &gatewayTunnel{socket: packet, data: data}
	defer tunnel.stop()
	leaf := newLeafRuntime(d.deviceFactory)
	defer func() { err = errors.Join(err, leaf.close()) }()
	var leafID [8]byte
	var nextLeafIntent time.Time
	var leafRejected string
	var lastReady bool
	initialBackoff, maxBackoff := config.Reconnect.InitialBackoff, config.Reconnect.MaxBackoff
	if initialBackoff <= 0 {
		initialBackoff = time.Second
	}
	if maxBackoff < initialBackoff {
		maxBackoff = 30 * time.Second
	}
	backoff := initialBackoff
	var nextTunnel time.Time
	var packetView packetStateView
	freshPlanFrom := func(view corestate.View, now time.Time) GatewayPlan {
		// The pipeline and this transport gate have the same serial owner.
		// Its immutable snapshot policy stops at the next exact transition;
		// current time, attachment and SA checks still run in every event.
		var verifier *photoncrypto.Verifier
		if leaf.pipeline != nil {
			verifier = leaf.pipeline.verifier
		}
		if tunnel.phase == 3 && leaf.pipeline != nil {
			var facts packetAuthorization
			if leaf.pipeline.prepareSnapshotInto(config, view, lastPlan, now, &facts) {
				return facts.plan
			}
		}
		if view.State == nil || verifier.VerifyChain(view.State.Network, config.ManagedZone, now) != nil {
			return GatewayPlan{Rejected: "local authority is absent or expired"}
		}
		if tunnel.phase != 0 {
			binding, err := localTransportAuthorizationWithVerifier(config, view, now, verifier)
			if err != nil || binding != tunnel.localAuthorization {
				return GatewayPlan{Rejected: "local transport authorization changed"}
			}
			current := revalidateActiveGatewaySelection(config, view, lastPlan, now, verifier)
			if current.Selected != nil {
				current.Routes = authorizedGatewayRoutesFromSet(config, currentAuthorizedRouteSetWithVerifier(config, view, now, verifier))
			}
			return current
		}
		return RevalidateGatewayPlan(config, view, lastPlan, now)
	}
	freshPlan := func() GatewayPlan {
		return freshPlanFrom(packetView.read(state.Store()), time.Now())
	}
	observeReady := func() {
		ready := leaf.readySnapshot(config, packetView.read(state.Store()), lastPlan, time.Now())
		if ready != lastReady {
			lastReady = ready
			logger.Info("tunnel_ready_changed", "tunnel_ready", ready)
		}
	}
	stopTunnel := func(reason string) {
		if err := leaf.stop(); err != nil {
			logger.Warn("leaf_cleanup_failed", "error", err)
		}
		observeReady()
		tunnel.stop()
		nextTunnel = time.Now().Add(backoff)
		backoff = min(backoff*2, maxBackoff)
		logger.Info("tunnel_stopped", "reason", reason, "retry_at", nextTunnel, "tunnel_ready", false)
	}
	reconcileLeaf := func() error {
		now := time.Now()
		if tunnel.phase != 3 {
			return nil
		}
		var intentErr error
		if leafID == [8]byte{} || !now.Before(nextLeafIntent) {
			nextLeafIntent = now.Add(5 * time.Second)
			before := state.Store().VerifiedRevision()
			intentErr = state.EnsureLocalLeafRoutes(ctx, config, now)
			if intentErr == nil {
				leafID, intentErr = state.EnsureLocalBabelIdentity(ctx, config, now)
			}
			if before != state.Store().VerifiedRevision() {
				requestPlan()
			}
		}
		if intentErr == nil {
			intentErr = leaf.reconcile(ctx, config, state.Store().ReadView(), lastPlan, tunnel, leafID, now)
		} else {
			intentErr = errors.Join(intentErr, leaf.stop())
		}
		rejected := ""
		if intentErr != nil {
			rejected = intentErr.Error()
		}
		if rejected != leafRejected {
			leafRejected = rejected
			if rejected != "" {
				logger.Info("leaf_unavailable", "reason", rejected, "tunnel_ready", false)
			}
		}
		if errors.Is(intentErr, errPacketDeviceRecoveryExpired) {
			return intentErr
		}
		return nil
	}
	attemptTunnel := func() {
		if tunnel.phase != 0 || time.Now().Before(nextTunnel) {
			return
		}
		plan := freshPlan()
		if plan.Selected == nil {
			return
		}
		before := state.Store().VerifiedRevision()
		local, err := state.EnsureLocalTransport(ctx, config, time.Now(), plan, packet.LocalAddr().AddrPort())
		if err != nil {
			nextTunnel = time.Now().Add(backoff)
			backoff = min(backoff*2, maxBackoff)
			logger.Warn("tunnel_local_identity_unavailable", "error", err)
			return
		}
		defer clear(local.PrivateKey)
		if state.Store().VerifiedRevision() != before {
			requestPlan()
			return
		}
		binding, err := localTransportAuthorization(config, state.Store().ReadView(), time.Now())
		if err != nil {
			stopTunnel(err.Error())
			return
		}
		if err := tunnel.start(plan, local.ID, local.PrivateKey, time.Now()); err != nil {
			stopTunnel(err.Error())
		} else {
			tunnel.localAuthorization = binding
		}
	}
	rebindPending := false
	rebind := func(rebindCtx context.Context) error {
		rebindCtx, cancelRebind := context.WithCancel(rebindCtx)
		stopCancel := context.AfterFunc(ctx, cancelRebind)
		defer stopCancel()
		defer cancelRebind()
		if err := leaf.stop(); err != nil {
			logger.Warn("leaf_cleanup_failed", "error", err)
		}
		observeReady()
		tunnel.stop() // deny old packets before replacing the shared endpoint
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
	var lastGateways []GatewayCandidate
	observeGateways := func() {
		view := state.Store().ReadView()
		now := time.Now()
		candidates := GatewayCandidates(config, view, now)
		if !reflect.DeepEqual(lastGateways, candidates) {
			logger.Info("gateway_candidates_changed", "revision", view.Revision, "evaluated_at", now,
				"candidates", candidates, "tunnel_ready", false, "route_authorized", false)
			lastGateways = candidates
		}
	}
	observeGateways()
	requestPlan()
	syncPeers := func() {
		if _, err := driver.SyncGossipPeers(ctx, time.Now(), nil, false); err != nil && ctx.Err() == nil {
			logger.Warn("gossip_sync_failed", "error", err)
		}
	}
	syncPeers()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	tunnelTicker := time.NewTicker(250 * time.Millisecond)
	defer tunnelTicker.Stop()
	// Both queued control jobs and direct packet crypto finish at this gate.
	// Read publication and time again after AES, then observe CHILD cutover and
	// authorize delivery in the same serial owner turn.
	completePacket := func(completion dataplaneCompletion) {
		view, now := packetView.read(state.Store()), time.Now()
		var facts packetAuthorization
		haveFacts := leaf.pipeline != nil && leaf.pipeline.prepareSnapshotInto(config, view, lastPlan, now, &facts)
		var plan GatewayPlan
		if haveFacts {
			plan = facts.plan
		} else {
			// Transport cutover remains independent of Babel/device readiness.
			plan = freshPlanFrom(view, now)
		}
		tunnel.observeData(completion, plan, now)
		if haveFacts {
			if _, err := leaf.pipeline.acceptPrepared(&facts, completion); err != nil {
				logger.Warn("leaf_packet_failed", "error", errors.Join(err, leaf.stop()))
			}
		} else {
			data.accept(completion, plan, nil)
		}
	}
	close(d.ready)
	for {
		select {
		case <-ctx.Done():
			err := leaf.stop()
			observeReady()
			return err
		case result := <-d.plans:
			result <- RevalidateGatewayPlan(config, state.Store().ReadView(), lastPlan, time.Now())
		case result := <-d.observations:
			result <- observeRuntime(config, state.Store().ReadView(), lastPlan, time.Now(), packet, tunnel, leaf, driver)
		case packet := <-packet.ikePackets:
			before := tunnel.phase
			if err := tunnel.handle(packet, freshPlan(), time.Now()); err != nil {
				logger.Debug("tunnel_packet_rejected", "error", err)
			} else if before != 3 && tunnel.phase == 3 {
				backoff = initialBackoff
				logger.Info("tunnel_authenticated", "gateway", tunnel.plan.Selected.Zone, "tunnel_ready", false, "child_installed", true)
				if err := reconcileLeaf(); err != nil {
					return err
				}
			}
			observeReady()
		case packet := <-packet.espPackets:
			if completion, ok := data.processInbound(packet.generation, freshPlan(), packet.peer, packet.packet); ok {
				completePacket(completion)
			}
		case job := <-data.jobs:
			if job.ctx.Err() == nil {
				completePacket(executeDataplaneJob(job))
			}
			// Readiness transition logging runs on the 250 ms lifecycle tick and
			// authority/IKE events. Packet delivery above still revalidates now;
			// IPC observations also evaluate readiness at their own read time.
		case result := <-leaf.opened:
			if err := leaf.complete(ctx, config, state.Store().ReadView(), lastPlan, tunnel, leafID, time.Now(), result); err != nil {
				logger.Warn("leaf_device_failed", "error", err)
				if errors.Is(err, errPacketDeviceConflict) || errors.Is(err, errPacketDeviceRecoveryExpired) {
					return fmt.Errorf("leaf device cannot acquire its configured OS resources: %w", err)
				}
			}
		case devicePacket := <-leaf.packets:
			if devicePacket.err != nil {
				logger.Warn("leaf_read_failed", "error", errors.Join(devicePacket.err, leaf.stop()))
				observeReady()
				continue
			}
			if leaf.pipeline != nil && devicePacket.generation == tunnel.generation {
				// A host packet cannot impersonate the daemon's Babel control.
				if _, _, ok := businessEndpoints(devicePacket.packet); !ok {
					continue
				}
				pipeline := leaf.pipeline
				var facts packetAuthorization
				if pipeline.prepareSnapshotInto(config, packetView.read(state.Store()), lastPlan, time.Now(), &facts) {
					completion, ok := data.processOutbound(pipeline.generation, facts.plan, devicePacket.packet,
						func(packet []byte, outbound bool) bool { return pipeline.authorize(&facts, packet, outbound) })
					if ok {
						completePacket(completion)
					}
				}
			}
		case <-tunnelTicker.C:
			if err := tunnel.tick(freshPlan(), time.Now()); err != nil {
				stopTunnel(err.Error())
			}
			attemptTunnel()
			if err := reconcileLeaf(); err != nil {
				return err
			}
			if leaf.pipeline != nil {
				leaf.pipeline.tickSnapshot(config, packetView.read(state.Store()), lastPlan, time.Now())
			}
			observeReady()
		case result := <-plans:
			if result.generation != generation || result.plan.Revision != state.Store().VerifiedRevision() {
				continue
			}
			if result.bootstrapErr != nil {
				logger.Warn("gossip_bootstrap_refresh_failed", "error", result.bootstrapErr)
			} else if !reflect.DeepEqual(bootstrap, result.bootstrap) {
				if err := driver.UpdateGossipBootstrap(result.bootstrap); err != nil {
					return err
				}
				bootstrap = result.bootstrap
				if err := driver.RefreshGossipDiscovery(ctx, nil, time.Now(), transport); err != nil {
					return err
				}
				syncPeers()
			}
			result.plan = RevalidateGatewayPlan(config, state.Store().ReadView(), result.plan, time.Now())
			// Revision/time are diagnostic metadata, not a change in the selected
			// target or authorization. Never report a planned target as a live SA.
			comparable, previous := result.plan, lastPlan
			comparable.Revision, previous.Revision = 0, 0
			comparable.EvaluatedAt, previous.EvaluatedAt = time.Time{}, time.Time{}
			if !reflect.DeepEqual(comparable, previous) {
				logger.Info("gateway_plan_changed", "plan", result.plan, "tunnel_ready", false)
			}
			lastPlan = result.plan
			attemptTunnel()
			observeReady()
		case request := <-d.rebind:
			request.result <- rebind(request.ctx)
		case <-packet.failed:
			if ctx.Err() == nil {
				_ = rebind(ctx)
				syncPeers()
			}
		case _, ok := <-powerResumes:
			if !ok {
				powerResumes = nil
				continue
			}
			if ctx.Err() == nil {
				logger.Info("power_resumed")
				_ = rebind(ctx)
				syncPeers()
			}
		case _, ok := <-networkChanges:
			if !ok {
				networkChanges = nil
				continue
			}
			if ctx.Err() == nil {
				_ = rebind(ctx)
				syncPeers()
			}
		case <-ticker.C:
			if rebindPending {
				_ = rebind(ctx)
			}
			observeGateways()
			requestPlan()
			if err := driver.RefreshGossipDiscovery(ctx, nil, time.Now(), transport); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("refresh gossip discovery: %w", err)
			}
			syncPeers()
		case event := <-driver.Events():
			before := state.Store().VerifiedRevision()
			if _, err := driver.HandleGossipHostEvent(ctx, event, time.Now(), nil); err != nil && !errors.Is(err, corehost.ErrGossipSessionNotFound) && ctx.Err() == nil {
				logger.Warn("gossip_event_failed", "error", err)
			}
			if state.Store().VerifiedRevision() != before {
				if tunnel.phase != 0 && !tunnel.current(freshPlan()) {
					stopTunnel("verified authorization withdrawn")
				}
				observeGateways()
				requestPlan()
				if err := reconcileLeaf(); err != nil {
					return err
				}
				observeReady()
			}
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
