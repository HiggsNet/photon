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
// It restores an existing database; it does not provision identity or a tunnel.
func RunConsole(ctx context.Context, config *Config, logger *slog.Logger) error {
	return NewDaemon(config, logger).Run(ctx)
}

// Daemon owns one run of the Windows composition. Rebind is serialized with
// gossip event processing; it does not recreate state or the protocol driver.
type Daemon struct {
	config      *Config
	logger      *slog.Logger
	started     atomic.Bool
	rebind      chan rebindRequest
	plans       chan chan GatewayPlan
	done        chan struct{}
	planGateway func(context.Context, *Config, corestate.View, time.Time) GatewayPlan
}

type rebindRequest struct {
	ctx    context.Context
	result chan error
}

func NewDaemon(config *Config, logger *slog.Logger) *Daemon {
	return &Daemon{config: config, logger: logger, rebind: make(chan rebindRequest), plans: make(chan chan GatewayPlan), done: make(chan struct{}), planGateway: PlanGateway}
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
	if !d.started.CompareAndSwap(false, true) {
		return errors.New("Windows daemon already started")
	}
	defer close(d.done)
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
	packet, err := openGossipSockets(ctx, config.GossipListen)
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
	rebindPending := false
	rebind := func(rebindCtx context.Context) error {
		rebindCtx, cancelRebind := context.WithCancel(rebindCtx)
		stopCancel := context.AfterFunc(ctx, cancelRebind)
		defer stopCancel()
		defer cancelRebind()
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
	for {
		select {
		case <-ctx.Done():
			return nil
		case result := <-d.plans:
			result <- RevalidateGatewayPlan(config, state.Store().ReadView(), lastPlan, time.Now())
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
		case request := <-d.rebind:
			request.result <- rebind(request.ctx)
		case <-packet.failed:
			if ctx.Err() == nil {
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
				observeGateways()
				requestPlan()
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
