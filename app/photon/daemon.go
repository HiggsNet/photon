package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/HiggsNet/photon/internal/observability"
	"github.com/HiggsNet/photon/internal/observer"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type DaemonService struct {
	Sync                   *SyncRuntime
	Interval               time.Duration
	ControlSocketPath      string
	Events                 chan daemonEvent
	Hooks                  DaemonHooks
	StateStore             *DaemonStateStore
	PeerObservability      *observability.PeerObservabilityStore
	IPsecDriver            ipsec.IPsecDriver
	XFRMDriver             ipsec.XFRMDriver
	ipsecDNSResolver       ipsec.DNSResolver
	closeIPsecDriver       func() error
	health                 *health.Manager
	healthUpdates          <-chan struct{}
	healthSpoolMu          sync.Mutex
	observerHub            *observer.Hub
	Log                    *appLogger
	LogLimiter             *repeatedLogLimiter
	drainingEvents         bool
	ipsecDirty             bool
	ipsecPrepareStandby    bool
	ipsecTakeoverNotBefore time.Time
	routingDirty           bool
	routingForceReload     bool
	routingLastRunUnix     atomic.Int64
	firewallDirty          bool
	metadataCheckpointMu   sync.Mutex
	metadataCheckpoint     metadataCheckpointState
	metadataCheckpointSave func() error

	syncSessions      map[string]*SyncSession
	syncIngressRoutes map[string]syncIngressRoute
	pendingSyncHints  map[string]bool
	syncEvents        chan SyncEvent
	objectPullResults chan ObjectPullResult
	objectPullPool    *objectPullPool
	timerManager      *TimerManager

	// Test overrides for BIRD routing reconcile.
	birdProcessManager   birdProcessManager
	birdProcessManagers  map[string]birdProcessManager
	birdClientFactory    func(socketPath string, timeout time.Duration) birdClient
	vethManager          vethManager
	upstreamRouteManager upstreamRouteManager
	firewallDriver       firewallDriver
}

type DaemonHooks struct {
	OnStateChanged   func(*stateFile)
	OnReconcileFlush func(layer string)
}

type daemonEventType string

const (
	controlConnDeadline                              = 10 * time.Second
	defaultReconcileOperationTimeout                 = 20 * time.Second
	defaultDaemonInterval                            = 60 * time.Second
	defaultIPsecReconcileInterval                    = time.Minute
	rawICMPFallbackLogInterval                       = 10 * time.Minute
	ipsecLifecycleSubscribeTimeout                   = 10 * time.Second
	defaultPeerObservabilityTTL                      = 24 * time.Hour
	defaultPeerObservabilityLimit                    = 2048
	daemonEventRecordPut             daemonEventType = "record_put"
	daemonEventIPAMMutation          daemonEventType = "ipam_mutate"
	daemonEventRouteMutation         daemonEventType = "route_mutate"
	daemonEventServiceMutation       daemonEventType = "service_mutate"
	daemonEventDelegateIssue         daemonEventType = "delegate_issue"
	daemonEventDelegateRevoke        daemonEventType = "delegate_revoke"
	daemonEventDelegateGrant         daemonEventType = "delegate_grant"
	daemonEventRecoveryImportZone    daemonEventType = "recovery_import_zone"
	daemonEventRecoveryPurgeRevoked  daemonEventType = "recovery_purge_revoked"
	daemonEventJoinAccept            daemonEventType = "join_accept"
	daemonEventPacket                daemonEventType = "packet"
	daemonEventSyncTimer             daemonEventType = "timer_sync"
	daemonEventEndpointTimer         daemonEventType = "timer_endpoint_publish"
	daemonEventSyncTrigger           daemonEventType = "sync_trigger"
	daemonEventReloadConfig          daemonEventType = "reload_config"
	daemonEventRoutingReload         daemonEventType = "routing_reload"
	daemonEventIPsecCleanup          daemonEventType = "ipsec_cleanup"
	daemonEventStateGC               daemonEventType = "state_gc"
	daemonEventIPsecPortRotate       daemonEventType = "ipsec_port_rotate"
	daemonEventIPsecLifecycle        daemonEventType = "ipsec_lifecycle"
	daemonEventEndpointACLApply      daemonEventType = "endpoint_acl_apply"
	daemonEventEndpointACLRemove     daemonEventType = "endpoint_acl_remove"
	daemonEventShutdown              daemonEventType = "shutdown"
)

type daemonEvent struct {
	Type        daemonEventType
	RecordPut   *daemonRecordPut
	JoinRequest *joinRequest
	JoinBundle  *joinBundle
	PrivateKey  *privateKeyFile
	Permissions []zone.Permission
	Snapshot    *gossip.ZoneSnapshot
	Zone        zone.ZonePath
	Reason      string
	Key         string
	Apply       bool
	Orphans     bool
	Packet      *gossip.Packet
	VICIEvent   ipsec.VICIEvent
	ForceSync   bool
	EndpointACL *endpointACL
	IPAM        *ipamMutationRequest
	Route       *routeMutationRequest
	Service     *serviceMutationRequest
	Context     context.Context
	Reply       chan daemonEventResult
}

type daemonRecordPut struct {
	Zone  zone.ZonePath
	Key   string
	Value []byte
	Type  string
}

type daemonEventResult struct {
	Version        uint64
	StateCommitted bool
	CleanedLinks   int
	CleanedOrphans int
	Zone           zone.ZonePath
	RootPublicKey  []byte
	JoinBundle     *joinBundle
	PortRotate     *manualPortRotateResult
	Records        int
	Delegations    int
	Revocations    int
	NetworkChanged bool
	Purge          *purgePlan
	StateGC        *stateGCPlan
	Error          error
}

func newDaemonService(rt *Runtime, state *stateFile, config *syncConfigFile, interval time.Duration) *DaemonService {
	if interval <= 0 {
		interval = defaultDaemonInterval
	}
	var socketPath string
	if rt != nil {
		socketPath = controlSocketPath(rt.Config)
	}
	if state != nil && state.Network != nil && state.Network.RecordVerifier == nil {
		configureValidation(state.Network)
	}
	peerObservability := observability.NewPeerObservabilityStore(defaultPeerObservabilityLimit, defaultPeerObservabilityTTL)
	syncRuntime := newSyncRuntime(config, nil, rt)
	syncRuntime.Observability = peerObservability
	d := &DaemonService{
		Sync:              syncRuntime,
		Interval:          interval,
		ControlSocketPath: socketPath,
		Events:            make(chan daemonEvent, 64),
		Log:               newAppLogger(config),
		LogLimiter:        newRepeatedLogLimiter(30 * time.Second),
		StateStore:        NewDaemonStateStore(state),
		PeerObservability: peerObservability,
	}
	d.ipsecDNSResolver = ipsec.NewDNSFamilyHoldDownResolver(net.DefaultResolver, ipsec.DNSFamilyHoldDownOptions{
		Now: d.Sync.now,
	})
	if state != nil && state.RoutingReconcile != nil {
		d.routingLastRunUnix.Store(state.RoutingReconcile.LastRunUnix)
	}
	d.ipsecTakeoverNotBefore = d.Sync.now().Add(2 * time.Minute)
	d.syncSessions = make(map[string]*SyncSession)
	d.syncIngressRoutes = make(map[string]syncIngressRoute)
	d.pendingSyncHints = make(map[string]bool)
	d.syncEvents = make(chan SyncEvent, 64)
	d.objectPullResults = make(chan ObjectPullResult, 64)
	d.objectPullPool = newObjectPullPool(d.objectPullResults, 0)
	d.timerManager = NewTimerManager(NewRealClock(), d.syncEvents)
	d.configureHealthManager()
	return d
}

// configureHealthManager initializes the health probe manager from app config.
// When health probing is disabled (the default), d.health remains nil and all
// health-related operations become no-ops.
func (d *DaemonService) configureHealthManager() {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return
	}
	cfg := d.Sync.App.Config.Health
	if !cfg.Enabled {
		return
	}
	// Prefer the in-process raw-ICMP prober. It keeps one locked OS thread per
	// network namespace and reuses raw sockets, avoiding the steady-state
	// fork/exec and mount work of `ip netns exec ping`. When the service lacks
	// the required capabilities it automatically falls back to the portable
	// exec prober.
	fallbackLogLimiter := newRepeatedLogLimiter(rawICMPFallbackLogInterval)
	reportFallback := func(target health.ProbeTarget, rawErr error) {
		netns := strings.TrimSpace(target.NetNS)
		if netns == "" {
			netns = "host"
		}
		key := netns
		if rawErr != nil {
			key += "\x00" + rawErr.Error()
		}
		suppressed, ok := fallbackLogLimiter.Allow(key, time.Now())
		if !ok {
			return
		}
		fields := map[string]any{
			"netns":     netns,
			"interface": target.InterfaceName,
			"fallback":  "exec_ping",
			"error":     rawErr,
		}
		if suppressed > 0 {
			fields["suppressed"] = suppressed
		}
		d.logWarn("health", "raw_icmp_fallback", fields)
	}
	d.health = newHealthManager(cfg, health.NewRawICMProber(
		health.NewICMProber(nil, health.NewUDPProber(nil)),
		reportFallback,
	))
}

func (d *DaemonService) Run(ctx context.Context) error {
	if d == nil || d.Sync == nil || d.StateStore == nil || d.Sync.Config == nil {
		return errors.New("daemon service is not initialized")
	}
	initialState, _ := d.StateStore.Snapshot()
	if initialState == nil {
		return errors.New("daemon committed state is not initialized")
	}
	if d.IPsecDriver == nil && d.XFRMDriver == nil {
		if err := d.configureIPsecDriversFromConfig(); err != nil {
			return err
		}
	}
	if d.timerManager != nil {
		defer func() {
			if d.timerManager != nil {
				d.timerManager.Stop()
			}
		}()
	}
	defer d.closeConfiguredIPsecDriver()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.stopManagedBirdInstances(shutdownCtx, false); err != nil {
			d.logWarn("routing", "bird_shutdown_failed", map[string]any{"error": err})
		}
	}()
	transport, err := d.Sync.openTransport(initialState)
	if err != nil {
		return err
	}
	packetCh, stopRecv := startGossipPacketReceiver(ctx, transport, func(c, e string, f map[string]any) { d.logWarn(c, e, f) })
	defer stopRecv()
	objectPullListener, err := startObjectPullServer(d)
	if err != nil {
		d.logError("object_pull", "server_start_failed", map[string]any{"error": err})
	}
	if objectPullListener != nil {
		defer objectPullListener.Close()
	}
	d.objectPullPool.Start(ctx)
	stopControl, err := d.startControlServer(ctx)
	if err != nil {
		return err
	}
	defer stopControl()
	stopObserver, err := d.startObserverServer(ctx)
	if err != nil {
		return err
	}
	defer stopObserver()
	stopIPsecEvents := d.startIPsecLifecycleEventWatcher(ctx)
	defer stopIPsecEvents()
	if d.health != nil {
		d.healthUpdates = d.startHealthProbeLoop(ctx)
		defer func() { d.healthUpdates = nil }()
	}
	startFields := map[string]any{
		"peer_id":  d.Sync.Config.PeerID,
		"addr":     transport.LocalAddr(),
		"interval": d.Interval,
	}
	if d.Sync.App != nil {
		startFields["config_path"] = configPath()
		startFields["state_path"] = d.Sync.App.StatePath
	}
	maps.Copy(startFields, buildInfoFields())
	d.logInfo("daemon", "started", startFields)
	d.logDebug("daemon", "startup_publish_begin", nil)
	if _, err := d.prepareStartupState(); err != nil {
		d.logWarn("daemon", "startup_publish_failed", map[string]any{"error": err})
	}
	d.logDebug("daemon", "startup_publish_done", nil)
	logAutoJoinPendingProjection(d.Log, d.StateStore.autoJoinLogProjection())

	nextSync := d.Sync.now()
	nextEndpointPublish := d.Sync.now()
	ipsecReconcileInterval := d.ipsecReconcileInterval()
	nextIPsecReconcile := nextIPsecReconcileTime(d.Sync.now(), ipsecReconcileInterval)
	routingReconcileInterval := d.routingReconcileInterval()
	nextRoutingReconcile := nextRoutingReconcileTime(d.Sync.now(), routingReconcileInterval)
	lastObservedDigests := d.zoneDigests()
	d.updateDiscoveredPeers()
	// Apply persisted lifecycle policy before startup recovery so stale signed
	// records cannot recreate links that already exceeded cleanup_after.
	d.flushRevocationCleanup()
	d.flushPeerLifecycleCleanup()
	d.logDebug("daemon", "startup_recovery_begin", nil)
	d.logDebug("daemon", "startup_recovery_layer_begin", map[string]any{"layer": "ipsec"})
	d.recoverIPsecLinksOnStart(ctx)
	d.logDebug("daemon", "startup_recovery_layer_done", map[string]any{"layer": "ipsec"})
	d.logDebug("daemon", "startup_recovery_layer_begin", map[string]any{"layer": "routing"})
	d.recoverRoutingOnStart(ctx)
	d.logDebug("daemon", "startup_recovery_layer_done", map[string]any{"layer": "routing"})
	d.logDebug("daemon", "startup_recovery_layer_begin", map[string]any{"layer": "firewall"})
	d.recoverFirewallOnStart(ctx)
	d.logDebug("daemon", "startup_recovery_layer_done", map[string]any{"layer": "firewall"})
	d.logDebug("daemon", "startup_recovery_done", nil)
	defer d.flushMetadataCheckpointOnShutdown()
	var forceSync bool
	for {
		if ctx.Err() != nil {
			return nil
		}
		now := d.Sync.now()
		syncNow, shutdown, ipsecFlushed, routingFlushed, firewallFlushed := d.processEvents(ctx)
		if shutdown {
			return nil
		}
		if d.drainHealthUpdates() {
			d.handleHealthUpdate(d.Sync.now())
		}
		_ = firewallFlushed
		if syncNow {
			nextSync = now
			forceSync = true
		}
		if ipsecFlushed {
			nextIPsecReconcile = nextIPsecReconcileTime(now, ipsecReconcileInterval)
		}
		if interval := d.ipsecReconcileInterval(); interval != ipsecReconcileInterval {
			ipsecReconcileInterval = interval
			nextIPsecReconcile = nextIPsecReconcileTime(now, ipsecReconcileInterval)
		}
		if routingFlushed {
			nextRoutingReconcile = nextRoutingReconcileTime(now, routingReconcileInterval)
		}
		if interval := d.routingReconcileInterval(); interval != routingReconcileInterval {
			routingReconcileInterval = interval
			nextRoutingReconcile = nextRoutingReconcileTime(now, routingReconcileInterval)
		}
		if latest, changed, err := d.Sync.reloadStateIfChanged(lastObservedDigests); err != nil {
			d.logWarn("daemon", "reload_failed", map[string]any{"error": err})
		} else if changed {
			rebasedPeerMetadata := d.rebasePendingPeerMetadata(latest)
			d.replaceCommittedState(latest)
			if rebasedPeerMetadata {
				d.advanceMetadataCheckpointRevision(d.StateStore.Meta().Revision)
			}
			lastObservedDigests = gossip.ZoneDigests(latest.Network)
			nextSync = now
			forceSync = true
			d.updateDiscoveredPeers()
			d.notifyStateChanged()
		}
		if !now.Before(nextEndpointPublish) {
			result, triggerSync, _ := d.handleEvent(daemonEvent{Type: daemonEventEndpointTimer, Context: ctx})
			if result.Error != nil {
				d.logWarn("endpoint", "publish_failed", map[string]any{"error": result.Error})
			}
			if triggerSync {
				nextSync = now
				forceSync = true
				lastObservedDigests = d.zoneDigests()
			}
			interval := d.Sync.Config.ReflectorInterval
			if interval <= 0 {
				interval = 5 * time.Minute
			}
			nextEndpointPublish = now.Add(interval)
		}
		if !now.Before(nextSync) {
			if d.flushPeerLifecycleCleanup() {
				d.updateDiscoveredPeers()
				d.notifyStateChanged()
			}
			result, _, _ := d.handleEvent(daemonEvent{Type: daemonEventSyncTimer, ForceSync: forceSync, Context: ctx})
			if result.Error != nil {
				d.logDebug("sync", "timer_completed_with_error", map[string]any{"error": result.Error})
			}
			// Starting an asynchronous sync session is not itself a data-plane
			// input change. Applied sync results call notifyStateChanged, while
			// the independent reconcile timers remain the safety net.
			nextSync = now.Add(d.Interval)
			forceSync = false
		}
		if !nextIPsecReconcile.IsZero() && !now.Before(nextIPsecReconcile) {
			d.ipsecDirty = true
			if d.flushIPsecReconcile(ctx) {
				nextIPsecReconcile = nextIPsecReconcileTime(now, ipsecReconcileInterval)
			}
		}
		if !nextRoutingReconcile.IsZero() && !now.Before(nextRoutingReconcile) {
			d.routingDirty = true
			if d.flushRoutingReconcile(ctx) {
				nextRoutingReconcile = nextRoutingReconcileTime(now, routingReconcileInterval)
			}
		}
		if err := d.flushMetadataCheckpoint(false); err != nil {
			d.logWarn("state", "metadata_checkpoint_failed", map[string]any{"error": err})
		}
		// Wait for the next event. Use a dedicated receiver goroutine so UDP
		// reads block until a packet arrives instead of polling every 250 ms.
		wait := d.nextTimerWait(nextSync, nextEndpointPublish, nextIPsecReconcile, nextRoutingReconcile, d.metadataCheckpointDue())
		if wait <= 0 {
			continue
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil
		case event := <-d.Events:
			timer.Stop()
			result, triggerSync, stop := d.handleEvent(event)
			if event.Reply != nil {
				event.Reply <- result
			}
			if stop {
				return nil
			}
			if triggerSync {
				nextSync = d.Sync.now()
				forceSync = true
				lastObservedDigests = d.zoneDigests()
			}
		case packet := <-packetCh:
			timer.Stop()
			result, _, _ := d.handleEvent(daemonEvent{Type: daemonEventPacket, Packet: packet, Context: ctx})
			if result.Error != nil {
				d.logWarn("gossip", "packet_failed", addGossipErrorFields(map[string]any{
					"peer_id": packet.Message.PeerID,
					"type":    packet.Message.Type,
					"error":   result.Error,
					"reason":  gossip.RejectReason(result.Error),
				}, result.Error))
			}
		case event := <-d.syncEvents:
			timer.Stop()
			if d.handleSyncEvent(ctx, event) {
				lastObservedDigests = d.zoneDigests()
			}
		case result := <-d.objectPullResults:
			timer.Stop()
			d.observeObjectPullResult(result)
			d.enqueueObjectPullResult(result)
		case <-d.healthUpdates:
			timer.Stop()
			d.handleHealthUpdate(d.Sync.now())
		case <-timer.C:
			// Continue the loop; timers will be checked and fired at the top.
		}
	}
}

func (d *DaemonService) startControlServer(ctx context.Context) (func(), error) {
	if d.ControlSocketPath == "" {
		return func() {}, nil
	}
	if err := os.MkdirAll(filepath.Dir(d.ControlSocketPath), 0o700); err != nil {
		return nil, fmt.Errorf("create control socket directory: %w", err)
	}
	if err := prepareControlSocketPath(d.ControlSocketPath); err != nil {
		return nil, err
	}
	listener, err := net.Listen("unix", d.ControlSocketPath)
	if err != nil {
		return nil, fmt.Errorf("listen on control socket %s: %w", d.ControlSocketPath, err)
	}
	if err := os.Chmod(d.ControlSocketPath, 0o600); err != nil {
		_ = listener.Close()
		_ = os.Remove(d.ControlSocketPath)
		return nil, err
	}
	done := make(chan struct{})
	go d.serveControl(controlContext(ctx), listener, done)
	return func() {
		_ = listener.Close()
		<-done
		_ = os.Remove(d.ControlSocketPath)
	}, nil
}

// prepareControlSocketPath removes a socket left behind by a daemon that is no
// longer listening. It deliberately refuses to unlink live sockets or other
// filesystem objects: both cases require operator intervention rather than
// silently taking over the path.
func prepareControlSocketPath(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("inspect control socket %s: %w", path, err)
	}
	if info.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("control socket path %s exists and is not a Unix socket", path)
	}

	conn, dialErr := net.DialTimeout("unix", path, 250*time.Millisecond)
	if dialErr == nil {
		_ = conn.Close()
		return fmt.Errorf("control socket %s is already in use; another daemon may be running", path)
	}
	if errors.Is(dialErr, os.ErrNotExist) {
		return nil
	}
	if !errors.Is(dialErr, syscall.ECONNREFUSED) {
		return fmt.Errorf("control socket %s could not be checked; refusing to remove it: %w", path, dialErr)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove stale control socket %s: %w", path, err)
	}
	return nil
}

func (d *DaemonService) serveControl(ctx context.Context, listener net.Listener, done chan<- struct{}) {
	defer close(done)
	for {
		conn, err := listener.Accept()
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				return
			}
			d.logWarn("daemon", "control_accept_failed", map[string]any{"error": err})
			continue
		}
		go d.handleControlConn(ctx, conn)
	}
}

func (d *DaemonService) handleControlConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	var request controlRequest
	_ = conn.SetReadDeadline(time.Now().Add(controlConnDeadline))
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		writeControlResponse(conn, controlError(err))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	switch request.Method {
	case "status":
		projection := d.StateStore.statusProjection()
		response := controlResponse{
			OK:            true,
			PeerID:        d.Sync.Config.PeerID,
			LinkInstances: projection.linkInstances,
			DesiredLinks:  projection.desiredLinks,
			LastLinkError: projection.lastLinkError,
			Message:       "daemon online",
		}
		applyStateStoreMeta(&response, projection.meta)
		writeControlResponse(conn, response)
	case "record_put":
		if err := validateControlRecordPut(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type: daemonEventRecordPut,
			RecordPut: &daemonRecordPut{
				Zone:  zone.ZonePath(request.Zone),
				Key:   request.Key,
				Value: parseControlRecordValue(request),
				Type:  request.Type,
			},
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Version: result.Version})
	case "ipam_mutate":
		if request.IPAM == nil {
			writeControlResponse(conn, controlError(errors.New("ipam_mutate requires ipam request")))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventIPAMMutation, IPAM: request.IPAM})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Version: result.Version})
	case "route_mutate":
		if request.Route == nil {
			writeControlResponse(conn, controlError(errors.New("route_mutate requires route request")))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventRouteMutation, Route: request.Route})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Version: result.Version})
	case "service_mutate":
		if request.Service == nil {
			writeControlResponse(conn, controlError(errors.New("service_mutate requires service request")))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventServiceMutation, Service: request.Service})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Version: result.Version})
	case "record_get":
		if err := validateControlRecordGet(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		record, meta, err := d.StateStore.recordDetailProjection(zone.ZonePath(request.Zone), request.Key, request.History)
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		response := controlResponse{OK: true, Record: record}
		applyStateStoreMeta(&response, meta)
		writeControlResponse(conn, response)
	case "endpoint_acl_apply":
		if request.EndpointACL == nil {
			writeControlResponse(conn, controlError(errors.New("endpoint_acl is required")))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventEndpointACLApply, EndpointACL: request.EndpointACL})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Message: "endpoint ACL applied"})
	case "endpoint_acl_remove":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventEndpointACLRemove, Key: request.Key})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Message: "endpoint ACL removed"})
	case "endpoint_acl_list":
		acls, meta := d.StateStore.endpointACLProjection()
		response := controlResponse{OK: true, EndpointACLs: acls, Message: "endpoint ACL list"}
		applyStateStoreMeta(&response, meta)
		writeControlResponse(conn, response)
	case "delegate_issue":
		if err := validateControlDelegateIssue(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:        daemonEventDelegateIssue,
			JoinRequest: request.JoinRequest,
			Permissions: request.Permissions,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Zone: result.Zone, JoinBundle: result.JoinBundle})
	case "delegate_grant":
		if err := validateControlDelegateGrant(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:        daemonEventDelegateGrant,
			Zone:        zone.ZonePath(request.Zone),
			Permissions: request.Permissions,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Zone: result.Zone, JoinBundle: result.JoinBundle})
	case "recovery_import_zone":
		if err := validateControlRecoveryImportZone(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:     daemonEventRecoveryImportZone,
			Snapshot: request.Snapshot,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{
			OK:             true,
			Zone:           result.Zone,
			RecordsApplied: result.Records,
			Delegations:    result.Delegations,
			Revocations:    result.Revocations,
			NetworkChanged: result.NetworkChanged,
		})
	case "delegate_revoke":
		if err := validateControlDelegateRevoke(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:   daemonEventDelegateRevoke,
			Zone:   zone.ZonePath(request.Zone),
			Reason: request.Reason,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Zone: result.Zone})
	case "recovery_purge_revoked":
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:  daemonEventRecoveryPurgeRevoked,
			Zone:  zone.ZonePath(request.Zone),
			Apply: request.Apply,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, PurgePlan: result.Purge})
	case "join_accept":
		if err := validateControlJoinAccept(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type:       daemonEventJoinAccept,
			JoinBundle: request.JoinBundle,
			PrivateKey: request.PrivateKey,
		})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Zone: result.Zone, RootPublicKey: result.RootPublicKey})
	case "root_init":
		writeControlResponse(conn, controlError(errors.New("root init via daemon is only valid before a daemon has loaded state; stop the daemon and run root init as recovery/direct initialization")))
	case "sync_trigger":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventSyncTrigger})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Message: "sync scheduled"})
	case "reload":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventReloadConfig})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Message: "config reloaded"})
	case "routing_reload":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventRoutingReload})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Message: "routing reloaded"})
	case "ipsec_cleanup":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventIPsecCleanup, Orphans: request.Orphans})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, CleanedLinks: result.CleanedLinks, CleanedOrphans: result.CleanedOrphans, Message: "ipsec links cleaned"})
	case "state_gc":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventStateGC, Apply: request.Apply})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		message := "state GC preview"
		if request.Apply {
			message = "state GC applied"
		}
		writeControlResponse(conn, controlResponse{OK: true, StateGC: result.StateGC, Message: message})
	case "ipsec_rotate_port":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventIPsecPortRotate})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, PortRotate: result.PortRotate, Message: "ipsec port rotate scheduled"})
	case "shutdown":
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventShutdown})
		if result.Error != nil {
			writeControlResponse(conn, controlError(result.Error))
			return
		}
		writeControlResponse(conn, controlResponse{OK: true, Message: "shutdown scheduled"})
	case "bird_status":
		projection := d.StateStore.birdStatusProjection()
		response := controlResponse{
			OK:               true,
			BirdInstances:    projection.instances,
			LastRoutingError: projection.lastRoutingError,
			Message:          "bird status",
		}
		applyStateStoreMeta(&response, projection.meta)
		writeControlResponse(conn, response)
	case "bird_dump":
		dump, err := d.birdDumpForControl(ctx, request.NetNS, birdDebugView(request.BirdView))
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeControlResponse(conn, controlResponse{
			OK:       true,
			BirdDump: dump,
			Message:  "bird dump",
		})
	case "routes_dump":
		projection := d.StateStore.routesProjection(d.Sync.now())
		var routingInstances []RoutingInstance
		if d.Sync != nil && d.Sync.App != nil && d.Sync.App.Config != nil {
			routingInstances = append([]RoutingInstance(nil), d.Sync.App.Config.Routing.Instances...)
		}
		if !projection.loaded {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		if projection.err != nil {
			writeControlResponse(conn, controlError(projection.err))
			return
		}
		routesDump := projection.routes
		routesDump.BIRD = d.birdRoutesForControl(ctx, routesDump, routingInstances, projection.bird)
		response := controlResponse{
			OK:         true,
			RoutesDump: routesDump,
			Message:    "routes dump",
		}
		applyStateStoreMeta(&response, projection.meta)
		writeControlResponse(conn, response)
	case "admission_status":
		diagnosis, meta, loaded := d.StateStore.admissionProjection(d.Sync.now())
		if !loaded {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		response := controlResponse{
			OK:        true,
			PeerID:    d.Sync.Config.PeerID,
			Admission: &diagnosis,
			Message:   "admission status",
		}
		applyStateStoreMeta(&response, meta)
		writeControlResponse(conn, response)
	case "firewall_status":
		fwSnapshot, meta, loaded := d.StateStore.firewallStatusProjection()
		if !loaded {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		response := controlResponse{
			OK:                true,
			FirewallReconcile: fwSnapshot,
			Message:           "firewall status",
		}
		applyStateStoreMeta(&response, meta)
		writeControlResponse(conn, response)
	case "links_status":
		projection := d.StateStore.linksStatusProjection(observerRuntime(d), d.healthStatusResponse())
		if !projection.loaded {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		links := linkInspectionControlFromBuild(projection.build)
		links.ActualSAs = projection.actualSAs
		response := controlResponse{
			OK:      true,
			PeerID:  d.Sync.Config.PeerID,
			Links:   links,
			Message: "links status",
		}
		applyStateStoreMeta(&response, projection.meta)
		writeControlResponse(conn, response)
	case "peers_status":
		peerStatuses, meta, loaded := d.peerStatusSnapshotForControl()
		if !loaded {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		response := controlResponse{
			OK:           true,
			PeerID:       d.Sync.Config.PeerID,
			PeerStatuses: peerStatuses,
			Message:      "peers status",
		}
		applyStateStoreMeta(&response, meta)
		writeControlResponse(conn, response)
	case "revoke_status":
		impacts, meta, loaded := d.StateStore.revocationImpactProjection(d.Sync.Config, d.Sync.now())
		if !loaded {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		response := controlResponse{
			OK:               true,
			PeerID:           d.Sync.Config.PeerID,
			RevocationImpact: impacts,
			Message:          "revoke status",
		}
		applyStateStoreMeta(&response, meta)
		writeControlResponse(conn, response)
	case "health_status":
		writeControlResponse(conn, controlResponse{
			OK:      true,
			PeerID:  d.Sync.Config.PeerID,
			Health:  d.healthStatusResponse(),
			Message: "health status",
		})
	default:
		writeControlResponse(conn, controlError(fmt.Errorf("unknown control method: %s", request.Method)))
	}
}

func (d *DaemonService) enqueueEvent(ctx context.Context, event daemonEvent) daemonEventResult {
	if ctx == nil {
		ctx = context.Background()
	}
	event.Reply = make(chan daemonEventResult, 1)
	select {
	case d.Events <- event:
	case <-ctx.Done():
		return daemonEventResult{Error: ctx.Err()}
	}
	select {
	case result := <-event.Reply:
		return result
	case <-ctx.Done():
		return daemonEventResult{Error: ctx.Err()}
	}
}

func (d *DaemonService) processEvents(ctx context.Context) (syncNow bool, shutdown bool, ipsecFlushed bool, routingFlushed bool, firewallFlushed bool) {
	d.drainingEvents = true
	defer func() {
		d.drainingEvents = false
		// Phase 6.5 deny-first order: revocation cleanup → firewall → routing
		// → IPsec → revocation cleanup again. This ensures revoked prefixes
		// and peer entries are removed from allow sets before any layer can
		// re-accept traffic from the revoked subtree.
		d.flushRevocationCleanup()
		firewallFlushed = d.flushFirewallReconcile(ctx)
		routingFlushed = d.flushRoutingReconcile(ctx)
		ipsecFlushed = d.flushIPsecReconcile(ctx) || ipsecFlushed
		d.flushRevocationCleanup()
	}()
	for {
		select {
		case event := <-d.Events:
			result, triggerSync, stop := d.handleEvent(event)
			if event.Type == daemonEventIPsecCleanup && result.Error == nil {
				ipsecFlushed = d.flushIPsecReconcile(ctx) || ipsecFlushed
			}
			routingMutationCommitted := (event.Type == daemonEventIPAMMutation && event.IPAM != nil && !event.IPAM.DryRun) ||
				(event.Type == daemonEventRouteMutation && event.Route != nil && !event.Route.DryRun)
			if routingMutationCommitted && result.Error == nil {
				flushed, err := d.flushRoutingReconcileResult(ctx)
				routingFlushed = flushed || routingFlushed
				if err != nil {
					result.Error = err
				}
			}
			if (event.Type == daemonEventEndpointACLApply || event.Type == daemonEventEndpointACLRemove) && result.Error == nil && result.StateCommitted {
				flushed, err := d.flushFirewallReconcileResult(ctx)
				firewallFlushed = flushed || firewallFlushed
				if err != nil {
					result.Error = err
				}
			}
			if event.Reply != nil {
				event.Reply <- result
			}
			syncNow = syncNow || triggerSync
			shutdown = shutdown || stop
			if shutdown {
				return syncNow, shutdown, ipsecFlushed, routingFlushed, firewallFlushed
			}
		default:
			return syncNow, shutdown, ipsecFlushed, routingFlushed, firewallFlushed
		}
	}
}

func (d *DaemonService) handleEvent(event daemonEvent) (daemonEventResult, bool, bool) {
	if event.Type == daemonEventPacket {
		return daemonEventResult{Error: d.handlePacketEvent(event.Packet, controlContext(event.Context))}, false, false
	}
	switch event.Type {
	case daemonEventRecordPut:
		version, err := d.handleRecordPutEvent(event.RecordPut)
		return daemonEventResult{Version: version, Error: err}, err == nil, false
	case daemonEventIPAMMutation:
		if event.IPAM == nil {
			return daemonEventResult{Error: errors.New("ipam mutation event is nil")}, false, false
		}
		result, err := d.handleRecordMutationEvent(event.IPAM.Zone, func(state *stateFile) (*recordMutationResult, error) {
			return applyIPAMMutation(state, *event.IPAM, d.Sync.now())
		})
		return daemonEventResult{Version: recordMutationVersion(result), Error: err}, err == nil && result != nil && !result.DryRun, false
	case daemonEventRouteMutation:
		if event.Route == nil {
			return daemonEventResult{Error: errors.New("route mutation event is nil")}, false, false
		}
		result, err := d.handleRecordMutationEvent(event.Route.Zone, func(state *stateFile) (*recordMutationResult, error) {
			return applyRouteMutation(state, *event.Route, d.Sync.now())
		})
		return daemonEventResult{Version: recordMutationVersion(result), Error: err}, err == nil && result != nil && !result.DryRun, false
	case daemonEventServiceMutation:
		if event.Service == nil {
			return daemonEventResult{Error: errors.New("service mutation event is nil")}, false, false
		}
		result, err := d.handleRecordMutationEvent("", func(state *stateFile) (*recordMutationResult, error) {
			return applyServiceMutation(state, *event.Service, d.Sync.now())
		})
		return daemonEventResult{Version: recordMutationVersion(result), Error: err}, err == nil && result != nil && !result.DryRun, false
	case daemonEventDelegateIssue:
		result, err := d.handleDelegateIssueEvent(event.JoinRequest, event.Permissions)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		return daemonEventResult{Zone: result.Zone, JoinBundle: result.Bundle}, true, false
	case daemonEventDelegateGrant:
		bundle, err := d.handleDelegateGrantEvent(event.Zone, event.Permissions)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		return daemonEventResult{Zone: event.Zone, JoinBundle: bundle}, true, false
	case daemonEventRecoveryImportZone:
		result, revocations, err := d.handleRecoveryImportZoneEvent(event.Snapshot)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		return daemonEventResult{
			Zone:           result.Zone,
			Records:        result.Records,
			Delegations:    result.Delegation,
			Revocations:    revocations,
			NetworkChanged: result.NetworkChanged,
		}, result.NetworkChanged, false
	case daemonEventDelegateRevoke:
		err := d.handleDelegateRevokeEvent(event.Zone, event.Reason)
		return daemonEventResult{Zone: event.Zone, Error: err}, err == nil, false
	case daemonEventRecoveryPurgeRevoked:
		plan, err := d.handleRecoveryPurgeRevokedEvent(controlContext(event.Context), event.Zone, event.Apply)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		// State only changes when applying; dry-run just reports the plan.
		return daemonEventResult{Purge: plan}, event.Apply, false
	case daemonEventJoinAccept:
		result, err := d.handleJoinAcceptEvent(event.JoinBundle, event.PrivateKey)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		return daemonEventResult{Zone: result.Zone, RootPublicKey: result.RootPublicKey}, true, false
	case daemonEventSyncTimer:
		return daemonEventResult{Error: d.handleSyncTimerEvent(controlContext(event.Context), event.ForceSync)}, false, false
	case daemonEventEndpointTimer:
		changed, err := d.handleEndpointTimerEvent()
		return daemonEventResult{Error: err}, changed, false
	case daemonEventSyncTrigger:
		return daemonEventResult{}, true, false
	case daemonEventReloadConfig:
		err := d.handleReloadConfigEvent()
		return daemonEventResult{Error: err}, err == nil, false
	case daemonEventRoutingReload:
		d.routingForceReload = true
		d.routingDirty = true
		d.flushRoutingReconcile(controlContext(event.Context))
		return daemonEventResult{}, false, false
	case daemonEventIPsecCleanup:
		cleaned, orphans, err := d.handleIPsecCleanupEvent(controlContext(event.Context), event.Orphans)
		if err == nil {
			d.ipsecDirty = true
		}
		return daemonEventResult{CleanedLinks: cleaned, CleanedOrphans: orphans, Error: err}, false, false
	case daemonEventStateGC:
		plan, err := d.handleStateGCEvent(event.Apply)
		return daemonEventResult{StateGC: plan, Error: err}, false, false
	case daemonEventIPsecPortRotate:
		result, err := d.handleIPsecPortRotateEvent()
		return daemonEventResult{PortRotate: result, Error: err}, err == nil, false
	case daemonEventIPsecLifecycle:
		d.handleIPsecLifecycleEvent(event.VICIEvent)
		return daemonEventResult{}, false, false
	case daemonEventEndpointACLApply:
		if event.EndpointACL == nil {
			return daemonEventResult{Error: errors.New("endpoint ACL is required")}, false, false
		}
		committed, err := d.handleEndpointACLApplyEvent(*event.EndpointACL)
		return daemonEventResult{StateCommitted: committed, Error: err}, false, false
	case daemonEventEndpointACLRemove:
		committed, err := d.handleEndpointACLRemoveEvent(event.Key)
		return daemonEventResult{StateCommitted: committed, Error: err}, false, false
	case daemonEventShutdown:
		return daemonEventResult{}, false, true
	default:
		return daemonEventResult{Error: fmt.Errorf("unknown daemon event: %s", event.Type)}, false, false
	}
}

func (d *DaemonService) handleReloadConfigEvent() error {
	if d == nil || d.Sync == nil || d.Sync.App == nil {
		return errors.New("daemon service is not initialized")
	}
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	statePath := config.StatePath
	if override := statePathOverride(); override != "" {
		statePath = override
	}
	if d.Sync.App.StatePath != "" && statePath != d.Sync.App.StatePath {
		return fmt.Errorf("reload would change state path from %s to %s; restart daemon to switch state", d.Sync.App.StatePath, statePath)
	}
	socketPath := controlSocketPath(config)
	if d.ControlSocketPath != "" && socketPath != d.ControlSocketPath {
		return fmt.Errorf("reload would change control socket path from %s to %s; restart daemon to switch control socket", d.ControlSocketPath, socketPath)
	}
	latest, err := loadStateAtWithConfig(statePath, config)
	if err != nil {
		return err
	}
	currentIdentityKeyPath := d.StateStore.identityKeyPathProjection()
	if currentIdentityKeyPath != "" && latest.IdentityKeyPath != "" && latest.IdentityKeyPath != currentIdentityKeyPath {
		return fmt.Errorf("reload would change identity.key_path from %s to %s; identity is immutable, use a new data_dir/state_path to create a different node", currentIdentityKeyPath, latest.IdentityKeyPath)
	}
	syncConfig := syncConfigFromAppConfig(config, latest)
	var ipsecDrivers configuredIPsecDrivers
	refreshIPsecDrivers := (d.IPsecDriver == nil && d.XFRMDriver == nil) || d.closeIPsecDriver != nil
	if refreshIPsecDrivers {
		var err error
		ipsecDrivers, err = newConfiguredIPsecDrivers(config.IPsec, func(event string, fields map[string]any) {
			d.logDebug("ipsec", event, fields)
		})
		if err != nil {
			return err
		}
	}
	d.Sync.App.Config = config
	d.Sync.App.StatePath = statePath
	d.Sync.Config = syncConfig
	if refreshIPsecDrivers {
		if err := d.installConfiguredIPsecDrivers(ipsecDrivers); err != nil {
			return err
		}
	}
	d.Log = newAppLogger(syncConfig)
	d.ControlSocketPath = socketPath
	d.replaceCommittedState(latest)
	if d.Sync.Transport != nil {
		d.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	d.recoverRoutingOnStart(context.Background())
	return nil
}

func (d *DaemonService) handleDelegateIssueEvent(request *joinRequest, permissions []zone.Permission) (*delegationIssueResult, error) {
	var result *delegationIssueResult
	err := d.runStateStoreWrite(func(state *stateFile) error {
		var err error
		result, err = issueDelegationInState(d.Sync.App, state, request, permissions)
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (d *DaemonService) handleDelegateGrantEvent(path zone.ZonePath, permissions []zone.Permission) (*joinBundle, error) {
	var bundle *joinBundle
	err := d.runStateStoreWrite(func(state *stateFile) error {
		var err error
		bundle, err = grantDelegationPermissionsInState(d.Sync.App, state, path, permissions)
		return err
	})
	if err != nil {
		return nil, err
	}
	return bundle, nil
}

func (d *DaemonService) handleRecoveryImportZoneEvent(snapshot *gossip.ZoneSnapshot) (*gossip.ApplyResult, int, error) {
	var result *gossip.ApplyResult
	var revocations int
	_, err := d.runStateStoreWriteIfChanged(func(state *stateFile) (bool, error) {
		var err error
		result, err = applyRecoveryZoneSnapshot(d.Sync.App, state, snapshot)
		if err != nil {
			return false, err
		}
		revocations = 0
		if zs := state.Network.Zones[result.Zone]; zs != nil {
			revocations = len(zs.Revocations)
		}
		return result.NetworkChanged, nil
	})
	if err != nil {
		return nil, 0, err
	}
	return result, revocations, nil
}

func (d *DaemonService) handleDelegateRevokeEvent(path zone.ZonePath, reason string) error {
	return d.runStateStoreWrite(func(state *stateFile) error {
		return revokeDelegationInState(d.Sync.App, state, path, reason)
	})
}

func (d *DaemonService) runStateStoreWrite(fn func(*stateFile) error) error {
	if d == nil || d.Sync == nil || d.StateStore == nil || fn == nil {
		return errors.New("daemon service is not initialized")
	}
	if _, err := d.StateStore.Update(fn); err != nil {
		return err
	}
	if err := d.saveCommittedState(); err != nil {
		return err
	}
	if d.Sync.Transport != nil {
		d.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return nil
}

// runStateStoreWriteIfChanged is like runStateStoreWrite, but the update
// function reports whether the state actually changed. When it reports false,
// the detached workspace is discarded without replacing the committed
// snapshot, incrementing the revision, or notifying downstream layers. This avoids
// duplicate IPsec/routing/firewall flushes when the endpoint timer (or similar
// periodic writer) produces a no-op publish.
func (d *DaemonService) runStateStoreWriteIfChanged(fn func(*stateFile) (bool, error)) (bool, error) {
	if d == nil || d.Sync == nil || d.StateStore == nil || fn == nil {
		return false, errors.New("daemon service is not initialized")
	}
	update, err := d.StateStore.BeginUpdate()
	if err != nil {
		return false, err
	}
	changed, err := fn(update.Workspace())
	if err != nil {
		return false, err
	}
	if !changed {
		return false, nil
	}
	if _, committed, err := update.Commit(); err != nil {
		return false, err
	} else if !committed {
		return false, errDaemonStateRevisionStale
	}
	if err := d.saveCommittedState(); err != nil {
		return false, err
	}
	if d.Sync.Transport != nil {
		d.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return true, nil
}

// handleRecoveryPurgeRevokedEvent runs the manual revoked-zone GC. It always
// computes the plan (returned for reporting); when apply is true it also
// executes the deletions, persists, and notifies subsystems so the running node
// reconciles (e.g. tears down orphaned IPsec for removed link instances).
func (d *DaemonService) handleRecoveryPurgeRevokedEvent(ctx context.Context, target zone.ZonePath, apply bool) (*purgePlan, error) {
	if d.StateStore == nil {
		return nil, errors.New("daemon service is not initialized")
	}
	if !apply {
		return d.StateStore.purgePlanProjection(d.Sync.App.Now(), target)
	}
	var plan *purgePlan
	if _, err := d.StateStore.Update(func(state *stateFile) error {
		var err error
		plan, err = planPurgeRevokedZones(state, d.Sync.App.Now(), target)
		if err != nil {
			return err
		}
		if err := d.cleanupPurgePlanIPsecLinks(ctx, state, plan); err != nil {
			return err
		}
		executePurgePlan(state, plan)
		return nil
	}); err != nil {
		return nil, err
	}
	if err := d.saveCommittedState(); err != nil {
		return nil, err
	}
	for _, peerID := range plan.SyncPeers {
		d.PeerObservability.Delete(peerID)
	}
	if d.Sync.Transport != nil {
		d.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return plan, nil
}

func (d *DaemonService) cleanupPurgePlanIPsecLinks(ctx context.Context, state *stateFile, plan *purgePlan) error {
	if plan == nil || len(plan.LinkInstances) == 0 {
		return nil
	}
	if d == nil || d.Sync == nil || state == nil || d.Sync.App == nil {
		return errors.New("daemon service is not initialized")
	}
	ipsecDriver := d.IPsecDriver
	xfrmDriver := d.XFRMDriver
	var closeFn func() error
	if ipsecDriver == nil || xfrmDriver == nil {
		drivers, err := newIPsecCleanupDrivers(d.Sync.App.Config)
		if err != nil {
			return err
		}
		ipsecDriver = drivers.ipsecDriver
		xfrmDriver = drivers.xfrmDriver
		closeFn = drivers.close
	}
	if closeFn != nil {
		defer func() { _ = closeFn() }()
	}
	_, err := cleanupIPsecLinkInstancesByID(ctx, state, plan.LinkInstances, ipsecDriver, xfrmDriver, d.Sync.now())
	return err
}

func (d *DaemonService) handleJoinAcceptEvent(bundle *joinBundle, key *privateKeyFile) (*joinAcceptResult, error) {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.StateStore == nil {
		return nil, errors.New("daemon service is not initialized")
	}
	var result *joinAcceptResult
	if _, err := d.StateStore.Update(func(state *stateFile) error {
		candidate, prepared, err := prepareJoinAcceptedState(d.Sync.App, state, bundle, key)
		if err != nil {
			return err
		}
		installPreparedState(state, candidate)
		result = prepared
		return nil
	}); err != nil {
		return nil, err
	}
	if err := d.saveCommittedState(); err != nil {
		return nil, err
	}
	if d.Sync.Transport != nil {
		d.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return result, nil
}

// processPacketEvent dispatches packet handling without a mutable stateFile
// lock. Packet fast-path updates are serialized by the daemon event loop and
// commit through StateStore.
func (d *DaemonService) processPacketEvent(packet *gossip.Packet, ctx context.Context) error {
	return d.handlePacketEvent(packet, ctx)
}

func (d *DaemonService) handlePacketEvent(packet *gossip.Packet, ctx context.Context) error {
	if packet == nil || packet.Message == nil {
		return errors.New("packet event is nil")
	}
	return d.handlePacketEventSyncSession(packet, ctx)
}

func (d *DaemonService) handleSyncTimerEvent(ctx context.Context, force bool) error {
	latest, err := d.Sync.loadState()
	if err != nil {
		return fmt.Errorf("daemon reload: %w", err)
	}
	d.replaceCommittedState(latest)
	d.updateDiscoveredPeers()
	return d.handleSyncTimerEventLoop(ctx, force)
}

func (d *DaemonService) zoneDigests() []gossip.ZoneDigest {
	if d == nil || d.StateStore == nil {
		return nil
	}
	return d.StateStore.ZoneDigests()
}

func (d *DaemonService) handleEndpointTimerEvent() (bool, error) {
	d.logDebug("endpoint", "timer_begin", nil)
	changed, err := d.runStateStoreWriteIfChanged(func(state *stateFile) (bool, error) {
		endpointChanged, err := d.Sync.publishEndpointRecordInState(state)
		if err != nil {
			return false, err
		}
		ipsecChanged, err := d.Sync.publishIPsecRecordsInState(state)
		if err != nil {
			return false, err
		}
		routingChanged, err := d.publishRoutingNetnsRecordInState(state)
		if err != nil {
			return false, err
		}
		return endpointChanged || ipsecChanged || routingChanged, nil
	})
	if err != nil {
		return false, err
	}
	d.logDebug("endpoint", "timer_done", map[string]any{"changed": changed})
	return changed, nil
}

// prepareStartupState folds admission diagnostics and all startup record
// publishers into one isolated workspace. A changed startup performs one
// commit and one save instead of one transaction per publisher.
func (d *DaemonService) prepareStartupState() (bool, error) {
	if d == nil || d.Sync == nil || d.StateStore == nil {
		return false, errors.New("daemon service is not initialized")
	}
	update, err := d.StateStore.BeginUpdate()
	if err != nil {
		return false, err
	}
	state := update.Workspace()
	if state == nil {
		return false, errors.New("daemon startup state is nil")
	}
	authorityRefreshed, err := tryRefreshManagedZoneAuthority(state, d.Sync.now())
	if err != nil {
		return false, fmt.Errorf("refresh managed zone authority at startup: %w", err)
	}

	var previousAdmission *admissionState
	if state.Admission != nil {
		value := *state.Admission
		previousAdmission = &value
	}
	updateAdmissionOnPending(state, d.Sync.now())
	changed := authorityRefreshed || !sameAdmissionState(previousAdmission, state.Admission)

	endpointChanged, err := d.Sync.publishEndpointRecordInState(state)
	if err != nil {
		return false, fmt.Errorf("publish startup endpoint record: %w", err)
	}
	ipsecChanged, err := d.Sync.publishIPsecRecordsInState(state)
	if err != nil {
		return false, fmt.Errorf("publish startup IPsec records: %w", err)
	}
	routingChanged, err := d.publishRoutingNetnsRecordInState(state)
	if err != nil {
		return false, fmt.Errorf("publish startup routing record: %w", err)
	}
	changed = changed || endpointChanged || ipsecChanged || routingChanged
	if !changed {
		return false, nil
	}

	if _, committed, err := update.Commit(); err != nil {
		return false, err
	} else if !committed {
		return false, errDaemonStateRevisionStale
	}
	if err := d.saveCommittedState(); err != nil {
		return false, err
	}
	if authorityRefreshed {
		d.logInfo("authority", "managed_zone_refreshed", map[string]any{
			"zone": state.ManagedZone,
			"via":  "startup",
		})
	}
	return true, nil
}

func sameAdmissionState(a, b *admissionState) bool {
	if a == nil || b == nil {
		return a == nil && b == nil
	}
	return *a == *b
}

func (d *DaemonService) handleRecordPutEvent(event *daemonRecordPut) (uint64, error) {
	if event == nil {
		return 0, errors.New("record_put event is nil")
	}
	if err := validateGenericRecordPut(event.Key, event.Type); err != nil {
		return 0, err
	}
	if d.StateStore == nil {
		return 0, errors.New("daemon service is not initialized")
	}
	workspace, rev := d.StateStore.networkZoneSnapshot(event.Zone)
	if workspace == nil || workspace.Network == nil {
		return 0, errors.New("daemon state network is nil")
	}
	var version uint64
	var recordCount int
	record, err := buildSignedRecordAt(workspace, event.Zone, event.Key, event.Value, event.Type, d.Sync.now())
	if err != nil {
		return 0, err
	}
	if err := workspace.Network.Put(record); err != nil {
		return 0, err
	}
	version = record.Version
	if zs := workspace.Network.Zones[event.Zone]; zs != nil {
		recordCount = len(zs.Records)
	}
	if _, committed := d.StateStore.commitNetworkCandidateIfRevision(rev, workspace.Network); !committed {
		return 0, errDaemonStateRevisionStale
	}
	d.logInfo("daemon", "record_put_persist", map[string]any{
		"zone":         event.Zone,
		"key":          event.Key,
		"record_count": recordCount,
	})
	if err := d.saveCommittedState(); err != nil {
		return 0, err
	}
	if d.Sync.Transport != nil {
		d.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return version, nil
}

func recordMutationVersion(result *recordMutationResult) uint64 {
	if result == nil {
		return 0
	}
	return result.Version
}

func (d *DaemonService) handleRecordMutationEvent(targetZone zone.ZonePath, apply func(*stateFile) (*recordMutationResult, error)) (*recordMutationResult, error) {
	if d == nil || d.Sync == nil || d.StateStore == nil || apply == nil {
		return nil, errors.New("daemon service is not initialized")
	}
	workspace, rev := d.StateStore.networkZoneSnapshot(targetZone)
	if workspace == nil || workspace.Network == nil {
		return nil, errors.New("daemon state network is nil")
	}
	result, err := apply(workspace)
	if err != nil {
		return nil, err
	}
	if result == nil {
		return nil, errors.New("authoritative mutation returned no result")
	}
	if result.DryRun {
		return result, nil
	}
	if _, committed := d.StateStore.commitNetworkCandidateIfRevision(rev, workspace.Network); !committed {
		return nil, errDaemonStateRevisionStale
	}
	if err := d.saveCommittedState(); err != nil {
		return nil, err
	}
	if d.Sync.Transport != nil {
		d.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	return result, nil
}

func (d *DaemonService) handleIPsecPortRotateEvent() (*manualPortRotateResult, error) {
	var result *manualPortRotateResult
	err := d.runStateStoreWrite(func(state *stateFile) error {
		var err error
		result, err = forceLocalIPsecPortRotate(d.Sync.App.Config, state, d.Sync.now())
		return err
	})
	if err != nil {
		return nil, err
	}
	return result, nil
}

func (d *DaemonService) currentState() *stateFile {
	if d == nil || d.StateStore == nil {
		return nil
	}
	state, _ := d.StateStore.Snapshot()
	return state
}

func applyStateStoreMeta(response *controlResponse, meta daemonStateStoreMeta) {
	if response == nil {
		return
	}
	response.StateRevision = meta.Revision
	if !meta.SnapshotTime.IsZero() {
		response.SnapshotTimeUnix = meta.SnapshotTime.Unix()
	}
	response.Dirty = meta.Dirty
	response.ReconcileProgress = meta.ReconcileProgress
}

func (d *DaemonService) replaceCommittedState(state *stateFile) {
	if d == nil || d.StateStore == nil {
		return
	}
	d.StateStore.ReplaceCommitted(state)
	d.publishStateStoreRuntimeFlags()
}

func (d *DaemonService) notifyStateChanged() {
	if d.Hooks.OnStateChanged != nil {
		state, _ := d.StateStore.Snapshot()
		d.Hooks.OnStateChanged(state)
	}
	// Phase 6.7: notify the read-only observer so it can push SSE events.
	d.notifyObserver("state_changed", nil)
	// Phase 6.5: clean gossip peer cache for revoked zones before triggering
	// layer reconciles. This ensures revoked peers don't appear as discovered
	// endpoints, observed paths or object-pull candidates when the downstream
	// layers recompute desired state. The deny-first cleanup happens before
	// firewall/routing/IPsec flush so that allow sets and desired links are
	// computed without revoked entries.
	d.flushRevocationCleanup()
	// Long-offline peers use a separate persisted local marker: their cache is
	// removed here and IPsec planning excludes them until a successful sync.
	d.flushPeerLifecycleCleanup()

	if d.drainingEvents {
		d.ipsecDirty = true
		d.routingDirty = true
		d.firewallDirty = true
		d.publishStateStoreRuntimeFlags()
		return
	}
	d.ipsecDirty = true
	d.routingDirty = true
	d.firewallDirty = true
	d.publishStateStoreRuntimeFlags()
	d.flushFirewallReconcile(context.Background())
	d.notifyObserver("route_changed", nil)
	d.notifyObserver("bird_updated", nil)
	d.flushRoutingReconcile(context.Background())
	d.flushIPsecReconcile(context.Background())
	d.notifyObserver("link_updated", d.observerLinkIDsPayload())
	// Gossip peer cache cleanup runs again after teardown to ensure observed
	// paths discovered/refreshed during the flush are cleared.
	d.flushRevocationCleanup()
	d.notifyObserver("peer_updated", d.observerPeerIDsPayload())
	d.notifyObserver("health_updated", d.observerHealthLinkIDsPayload())
}

func (d *DaemonService) publishStateStoreRuntimeFlags() {
	if d == nil || d.StateStore == nil {
		return
	}
	d.StateStore.SetDirty(daemonDirtyFlags{
		IPsec:    d.ipsecDirty,
		Routing:  d.routingDirty,
		Firewall: d.firewallDirty,
	})
}

func (d *DaemonService) noteReconcileFlush(layer string) {
	if d != nil && d.Hooks.OnReconcileFlush != nil {
		d.Hooks.OnReconcileFlush(layer)
	}
}

// flushRevocationCleanup clears runtime-relevant fields from SyncPeers entries
// whose zone is currently revoked. This implements Phase 6.5.5 gossip peer
// cache cleanup: revoked peers must not maintain discovered endpoints,
// observed paths, backoff or object-pull candidates. The entry itself is
// retained with a "revoked" marker for diagnostics; it is removed via the
// normal offline cleanup policy after the cleanup_after retention window.
func (d *DaemonService) flushRevocationCleanup() {
	if d == nil || d.StateStore == nil || d.Sync == nil {
		return
	}
	// This function is called after every sync-state update. Most calls have no
	// revocations, so check the immutable committed state first and avoid the
	// copy-on-write transaction (which deep-copies the whole state through JSON).
	projection := d.StateStore.revocationCleanupProjection(d.Sync.now())
	if len(projection.revokedZones) == 0 {
		return
	}
	d.noteReconcileFlush("revocation_cleanup")
	if projection.needsStateCleanup {
		if _, err := d.StateStore.Update(func(state *stateFile) error {
			// Recompute inside the transaction in case a newer state was committed
			// after the read-only fast-path check.
			d.flushRevocationCleanupLocked(state)
			return nil
		}); err != nil {
			d.logWarn("sync", "revocation_cleanup_commit_failed", map[string]any{"error": err})
			return
		}
	}
	for peerID := range d.peerObservabilitySnapshots() {
		if projection.revokedZones[zone.ZonePath(peerID)] {
			d.PeerObservability.Delete(peerID)
		}
	}
}

func (d *DaemonService) flushRevocationCleanupLocked(state *stateFile) {
	if d == nil || d.Sync == nil || state == nil || state.Network == nil {
		return
	}
	now := d.Sync.now()
	revokedZones := CollectAllRevokedZones(state, now)
	if len(revokedZones) == 0 {
		return
	}
	CleanupRevokedPeerCache(state, revokedZones)
}

func (d *DaemonService) recoverIPsecLinksOnStart(ctx context.Context) {
	if d == nil {
		return
	}
	d.ipsecPrepareStandby = true
	defer func() { d.ipsecPrepareStandby = false }()
	d.ipsecDirty = true
	d.flushIPsecReconcile(ctx)
}

func (d *DaemonService) recoverRoutingOnStart(ctx context.Context) {
	if d == nil {
		return
	}
	d.routingDirty = true
	d.flushRoutingReconcile(ctx)
}

func (d *DaemonService) flushRoutingReconcile(ctx context.Context) bool {
	flushed, err := d.flushRoutingReconcileResult(ctx)
	if err != nil {
		d.logWarn("routing", "reconcile_failed", map[string]any{"error": err})
	}
	return flushed
}

func (d *DaemonService) flushRoutingReconcileResult(ctx context.Context) (bool, error) {
	if d == nil || !d.routingDirty {
		return false, nil
	}
	d.routingDirty = false
	d.noteReconcileFlush("routing")
	reconcileCtx, cancel := boundedReconcileContext(ctx)
	defer cancel()
	err := d.reconcileRouting(reconcileCtx)
	return true, err
}

func (d *DaemonService) routingReconcileInterval() time.Duration {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return 0
	}
	instances := routingInstancesEnabled(d.Sync.App.Config)
	if len(instances) == 0 {
		return 0
	}
	return defaultRoutingReconcileInterval
}

func nextRoutingReconcileTime(now time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return time.Time{}
	}
	return now.Add(interval)
}

func boundedReconcileContext(ctx context.Context) (context.Context, context.CancelFunc) {
	if ctx == nil {
		ctx = context.Background()
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultReconcileOperationTimeout)
}

func (d *DaemonService) flushIPsecReconcile(ctx context.Context) bool {
	if d == nil || !d.ipsecDirty {
		return false
	}
	d.ipsecDirty = false
	d.noteReconcileFlush("ipsec")
	reconcileCtx, cancel := boundedReconcileContext(ctx)
	defer cancel()
	if err := d.reconcileIPsecLinks(reconcileCtx); err != nil {
		d.logWarn("ipsec", "reconcile_failed", map[string]any{"error": err})
	}
	// Phase 6.6: after IPsec reconcile, refresh health probe targets and
	// dispatch any due probes. This keeps the probe scheduler in sync with
	// link create/update/teardown without adding a separate timer path.
	d.reconcileHealth(reconcileCtx)
	return true
}

type ipsecLifecycleEventSubscriber interface {
	SubscribeLifecycleEvents(context.Context) (<-chan ipsec.VICIEvent, func(), error)
}

func (d *DaemonService) startIPsecLifecycleEventWatcher(ctx context.Context) func() {
	subscriber, ok := d.IPsecDriver.(ipsecLifecycleEventSubscriber)
	if !ok || subscriber == nil {
		return func() {}
	}
	watchCtx, cancel := context.WithCancel(ctx)
	go d.runIPsecLifecycleEventWatcher(watchCtx, subscriber)
	return cancel
}

// runIPsecLifecycleEventWatcher subscribes to StrongSwan lifecycle events in
// the background and forwards them to the daemon event loop. Each subscribe
// attempt is bounded by a timeout and retried with backoff: a wedged VICI
// daemon (accepting connections but never answering) must degrade to warning
// logs instead of blocking daemon startup, which a synchronous subscribe did.
func (d *DaemonService) runIPsecLifecycleEventWatcher(ctx context.Context, subscriber ipsecLifecycleEventSubscriber) {
	backoff := time.Second
	for {
		subscribeCtx, cancelSubscribe := context.WithTimeout(ctx, ipsecLifecycleSubscribeTimeout)
		events, stop, err := subscriber.SubscribeLifecycleEvents(subscribeCtx)
		cancelSubscribe()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			d.logWarn("ipsec", "vici_event_subscribe_failed", map[string]any{"error": err})
			if !sleepBeforeRetry(ctx, backoff) {
				return
			}
			backoff = nextRetryBackoff(backoff)
			continue
		}
		backoff = time.Second
		shutdown := d.forwardIPsecLifecycleEvents(ctx, events)
		if stop != nil {
			stop()
		}
		if shutdown {
			return
		}
		d.logWarn("ipsec", "vici_event_stream_closed", map[string]any{"retry_in": backoff.String()})
		if !sleepBeforeRetry(ctx, backoff) {
			return
		}
	}
}

// forwardIPsecLifecycleEvents pumps lifecycle events into the daemon event
// loop until ctx ends (returns true) or the event stream closes (returns
// false, caller should resubscribe).
func (d *DaemonService) forwardIPsecLifecycleEvents(ctx context.Context, events <-chan ipsec.VICIEvent) bool {
	for {
		select {
		case <-ctx.Done():
			return true
		case ev, ok := <-events:
			if !ok {
				return false
			}
			select {
			case d.Events <- daemonEvent{Type: daemonEventIPsecLifecycle, VICIEvent: ev}:
			default:
				d.logWarn("ipsec", "vici_event_dropped", map[string]any{
					"reason":     "daemon_events_full",
					"event_name": ev.Name,
					"connection": ev.Connection,
					"child":      ev.ChildSA,
				})
			}
		}
	}
}

func sleepBeforeRetry(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func nextRetryBackoff(current time.Duration) time.Duration {
	next := min(current*2, time.Minute)
	return next
}

func (d *DaemonService) handleIPsecLifecycleEvent(ev ipsec.VICIEvent) {
	d.ipsecDirty = true
	d.logDebug("ipsec", "vici_lifecycle_event", map[string]any{
		"event_name": ev.Name,
		"connection": ev.Connection,
		"child":      ev.ChildSA,
		"up":         ev.Up,
		"xfrm_if_id": ev.XFRMIfID,
		"reqid":      ev.ReqID,
		"local_id":   ev.LocalIdentity,
		"remote_id":  ev.RemoteIdentity,
		"local_ep":   ev.LocalEndpoint,
		"remote_ep":  ev.RemoteEndpoint,
	})
}

func (d *DaemonService) ipsecReconcileInterval() time.Duration {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return 0
	}
	groups := d.Sync.App.Config.IPsec.LinkGroups
	if len(groups) == 0 {
		if d.StateStore.hasLinkInstancesProjection() {
			return defaultIPsecReconcileInterval
		}
		return 0
	}
	var interval time.Duration
	for _, group := range groups {
		groupInterval := defaultIPsecReconcileInterval
		if group.Reconcile.IntervalSeconds > 0 {
			groupInterval = time.Duration(group.Reconcile.IntervalSeconds) * time.Second
		}
		if interval == 0 || groupInterval < interval {
			interval = groupInterval
		}
	}
	return interval
}

func nextIPsecReconcileTime(now time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return time.Time{}
	}
	return now.Add(interval)
}

func daemonRun(ctx context.Context, interval time.Duration) error {
	rt, err := NewRuntime()
	if err != nil {
		return err
	}
	state, err := rt.LoadState()
	if err != nil {
		return err
	}
	config, err := rt.SyncConfig(state)
	if err != nil {
		return err
	}
	service := newDaemonService(rt, state, config, interval)
	if err := service.configureIPsecDriversFromConfig(); err != nil {
		return err
	}
	return service.Run(ctx)
}

func (d *DaemonService) configureIPsecDriversFromConfig() error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil
	}
	drivers, err := newConfiguredIPsecDrivers(d.Sync.App.Config.IPsec, func(event string, fields map[string]any) {
		d.logDebug("ipsec", event, fields)
	})
	if err != nil {
		return err
	}
	return d.installConfiguredIPsecDrivers(drivers)
}

type configuredIPsecDrivers struct {
	ipsecDriver ipsec.IPsecDriver
	xfrmDriver  ipsec.XFRMDriver
	close       func() error
}

func newConfiguredIPsecDrivers(config ipsecConfig, logConfig func(event string, fields map[string]any)) (configuredIPsecDrivers, error) {
	driver := config.Driver
	if driver == "" {
		driver = ipsecDriverStrongSwan
	}
	switch driver {
	case ipsecDriverDryRun:
		return configuredIPsecDrivers{}, nil
	case ipsecDriverStrongSwan:
		if len(config.LinkGroups) == 0 {
			return configuredIPsecDrivers{}, nil
		}
		client, err := ipsec.NewReconnectingGoviciClient(config.VICISocket)
		if err != nil {
			return configuredIPsecDrivers{}, fmt.Errorf("initialize strongswan vici client: %w", err)
		}
		initiateClientFactory := func() (ipsec.VICIClient, func() error, error) {
			client, err := ipsec.NewGoviciClient(config.VICISocket)
			if err != nil {
				return nil, nil, err
			}
			return client, client.Close, nil
		}
		return configuredIPsecDrivers{
			ipsecDriver: &ipsec.StrongSwanDriver{
				VICI:                  client,
				LogConfig:             logConfig,
				InitiateAsync:         true,
				InitiateClientFactory: initiateClientFactory,
				XFRMBackend:           ipsec.XFRMBackend(config.XFRMBackend),
			},
			xfrmDriver: newXFRMDriverForBackend(config),
			close:      client.Close,
		}, nil
	default:
		return configuredIPsecDrivers{}, fmt.Errorf("unsupported ipsec driver %q", driver)
	}
}

func newXFRMDriverForBackend(config ipsecConfig) ipsec.SystemXFRMDriver {
	driver := ipsec.NewSystemXFRMDriver(config.DefaultNetNS)
	backend, err := ipsec.NormalizeXFRMBackend(config.XFRMBackend)
	if err != nil {
		backend = ipsec.XFRMBackendInterface
	}
	driver.Backend = backend
	return driver
}

func (d *DaemonService) installConfiguredIPsecDrivers(drivers configuredIPsecDrivers) error {
	if err := d.closeConfiguredIPsecDriver(); err != nil {
		if drivers.close != nil {
			_ = drivers.close()
		}
		return err
	}
	d.IPsecDriver = drivers.ipsecDriver
	d.XFRMDriver = drivers.xfrmDriver
	d.closeIPsecDriver = drivers.close
	return nil
}

func (d *DaemonService) closeConfiguredIPsecDriver() error {
	if d == nil || d.closeIPsecDriver == nil {
		return nil
	}
	closeFn := d.closeIPsecDriver
	d.closeIPsecDriver = nil
	err := closeFn()
	if err != nil {
		return err
	}
	return nil
}

func (d *DaemonService) logDebug(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Debug(component, event, fields)
	}
}

func (d *DaemonService) logInfo(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Info(component, event, fields)
	}
}

func (d *DaemonService) logWarn(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Warn(component, event, fields)
	}
}

func (d *DaemonService) logError(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Error(component, event, fields)
	}
}

// nextTimerWait returns the duration until the earliest non-zero deadline.
// If no deadline is set, it returns a large value so the caller can wait
// indefinitely for packets, events, or context cancellation. If a deadline is
// already due, it returns 0 or a negative duration.
func (d *DaemonService) nextTimerWait(deadlines ...time.Time) time.Duration {
	now := d.Sync.now()
	var earliest time.Time
	for _, t := range deadlines {
		if t.IsZero() {
			continue
		}
		if earliest.IsZero() || t.Before(earliest) {
			earliest = t
		}
	}
	if earliest.IsZero() {
		return 24 * time.Hour
	}
	if !earliest.After(now) {
		return 0
	}
	return earliest.Sub(now)
}
