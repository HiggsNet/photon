package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"os"
	"path/filepath"
	"sort"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/internal/observability/healthspool"
	"github.com/HiggsNet/photon/internal/observer"
	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/internal/photonlinux/linkstate"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type Daemon struct {
	App                    *AppContext
	Interval               time.Duration
	ControlSocketPath      string
	Events                 chan daemonEvent
	Hooks                  DaemonHooks
	StateStore             *DaemonStateStore
	linuxDriver            *photonlinux.LinuxDriver
	ipsecDNSResolver       ipsec.DNSResolver
	health                 *healthDriver
	observerHub            *observer.Hub
	Log                    *appLogger
	LogLimiter             *repeatedLogLimiter
	drainingEvents         bool
	linuxObservation       linuxObservation
	ipsecDirty             bool
	ipsecPrepareStandby    bool
	ipsecTakeoverNotBefore time.Time
	routingDirty           bool
	routingForceReload     bool
	routingLastRunUnix     atomic.Int64
	firewallDirty          bool
	daemonTimers           *corehost.Scheduler
	daemonTimerEvents      chan corehost.Event

	gossipDriver       *corehost.GossipDriver
	objectPullExecutor *corehost.GossipObjectPullExecutor
}

type DaemonHooks struct {
	OnStateChanged   func()
	OnReconcileFlush func(layer string)
}

type daemonEventType string

const (
	controlConnDeadline                              = 10 * time.Second
	defaultReconcileOperationTimeout                 = 20 * time.Second
	defaultDaemonInterval                            = 60 * time.Second
	defaultIPsecReconcileInterval                    = time.Minute
	ipsecLifecycleSubscribeTimeout                   = 10 * time.Second
	daemonRuntimeNamespace                           = "daemon"
	daemonTimerOwner                                 = "periodic"
	daemonTimerSync                                  = "sync"
	daemonTimerEndpoint                              = "endpoint_publish"
	daemonTimerIPsec                                 = "ipsec_reconcile"
	daemonTimerRouting                               = "routing_reconcile"
	daemonTimerFirewall                              = "firewall_reconcile"
	daemonTimerHealth                                = "health_probe"
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
	Snapshot    *corestate.ZoneSnapshot
	Zone        zone.ZonePath
	Reason      string
	Key         string
	Apply       bool
	Orphans     bool
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

func newDaemonWithStore(rt *AppContext, stateStore *DaemonStateStore, config *gossipStartupConfig, interval time.Duration) *Daemon {
	if interval <= 0 {
		interval = defaultDaemonInterval
	}
	var socketPath string
	if rt != nil {
		socketPath = controlSocketPath(rt.Config)
	}
	_, runtime := stateStore.readCommonAndRuntime()
	spoolConfig := healthspool.Config{}
	if rt != nil && rt.Config != nil {
		spoolConfig = rt.Config.Health.spoolConfig()
	}
	clock := time.Now
	if rt != nil {
		clock = rt.Now
	}
	var loggerConfig *appConfig
	if rt != nil {
		loggerConfig = rt.Config
	}
	logger := newAppLogger(loggerConfig)
	gossipDriver := corehost.NewGossipDriver(corehost.NewClock(clock), corehost.DefaultEventBuffer, stateStore.common, gossipDriverConfig(config, loggerConfig, logger))
	d := &Daemon{
		App:               rt,
		Interval:          interval,
		ControlSocketPath: socketPath,
		Events:            make(chan daemonEvent, 64),
		Log:               logger,
		LogLimiter:        newRepeatedLogLimiter(30 * time.Second),
		StateStore:        stateStore,
		health:            &healthDriver{spool: healthspool.New(spoolConfig)},
	}
	d.ipsecDNSResolver = ipsec.NewDNSFamilyHoldDownResolver(net.DefaultResolver, ipsec.DNSFamilyHoldDownOptions{
		Now: d.now,
	})
	if runtime != nil && runtime.RoutingReconcile != nil {
		d.routingLastRunUnix.Store(runtime.RoutingReconcile.LastRunUnix)
	}
	d.ipsecTakeoverNotBefore = d.now().Add(2 * time.Minute)
	d.gossipDriver = gossipDriver
	d.objectPullExecutor = newDaemonObjectPullExecutor(d)
	return d
}

func openDaemon(rt *AppContext, interval time.Duration) (*Daemon, *corestate.BoltStore, error) {
	if rt == nil {
		return nil, nil, errors.New("daemon runtime is nil")
	}
	boltStore, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		return nil, nil, err
	}
	stateStore, err := newPersistedDaemonStateStore(startup.Common, startup.Runtime, boltStore)
	if err != nil {
		_ = boltStore.Close()
		return nil, nil, err
	}
	common := startup.Common.ReadView()
	if common.State == nil {
		_ = boltStore.Close()
		return nil, nil, errors.New("daemon common state is not initialized")
	}
	config := gossipStartupConfigFromAppConfig(rt.Config, common.State)
	return newDaemonWithStore(rt, stateStore, config, interval), boltStore, nil
}

// configureHealthManager initializes the health probe manager from app config.
// When probing is disabled (the default), the optional subsystem has no
// Manager and therefore creates no scheduler, goroutine or platform probe.
func (d *Daemon) configureHealthManager() {
	if d != nil && d.health != nil {
		d.health.Manager = nil
		d.health.driverManaged = false
	}
	if d == nil || d.App == nil || d.App.Config == nil {
		return
	}
	cfg := d.App.Config.Health
	if !cfg.Enabled {
		return
	}
	if d.linuxDriver == nil {
		return
	}
	if d.health == nil {
		d.health = &healthDriver{}
	}
	d.health.Manager = newHealthManager(cfg, d.linuxDriver.HealthProber())
	d.health.driverManaged = d.health.Manager != nil
}

func (d *Daemon) Run(ctx context.Context) error {
	if d == nil || d.StateStore == nil || d.currentGossipConfig() == nil {
		return errors.New("daemon service is not initialized")
	}
	if initial := d.StateStore.common.ReadView(); initial.State == nil {
		return errors.New("daemon committed state is not initialized")
	}
	if d.linuxDriver == nil {
		if err := d.configureLinuxDriverFromConfig(); err != nil {
			return err
		}
	}
	if d.gossipDriver != nil {
		defer d.gossipDriver.Stop()
	}
	d.daemonTimerEvents = make(chan corehost.Event, corehost.DefaultEventBuffer)
	d.daemonTimers = corehost.NewScheduler(corehost.NewClock(d.now), d.daemonTimerEvents)
	defer func() {
		d.daemonTimers.Stop()
		d.daemonTimers = nil
		d.daemonTimerEvents = nil
	}()
	defer d.closeLinuxDriver()
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := d.stopManagedBirdInstances(shutdownCtx, false); err != nil {
			d.logWarn("routing", "bird_shutdown_failed", map[string]any{"error": err})
		}
	}()
	transport, err := d.openGossipTransport()
	if err != nil {
		return err
	}
	d.updateDiscoveredPeers()
	err = d.gossipDriver.StartGossipTransport(ctx, transport, func(err error) {
		d.logWarn("transport", "receive_failed", map[string]any{"error": err})
	})
	if err != nil {
		return err
	}
	err = startObjectPullServer(ctx, d)
	if err != nil {
		d.logError("object_pull", "server_start_failed", map[string]any{"error": err})
	}
	if err := d.gossipDriver.StartGossipObjectPullWorkers(ctx, d.objectPullExecutor, 0, 0); err != nil {
		return err
	}
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
	subsystemCtx, stopSubsystems := context.WithCancel(ctx)
	stopIPsecEvents := d.startIPsecLifecycleEventWatcher(subsystemCtx)
	var healthUpdates <-chan struct{}
	if d.health != nil && d.health.Manager != nil {
		healthUpdates = d.health.StartAsync(subsystemCtx)
		d.health.asyncRunning = true
		defer func() { d.health.asyncRunning = false }()
	}
	// This defer is registered after closeLinuxDriver, so the worker owners are
	// canceled and joined before their injected Linux capabilities are closed.
	defer func() {
		stopSubsystems()
		stopIPsecEvents()
		if d.health != nil && d.health.Manager != nil {
			d.health.WaitAsync()
		}
	}()
	startFields := map[string]any{
		"peer_id":  d.currentGossipConfig().PeerID,
		"addr":     transport.LocalAddr(),
		"interval": d.Interval,
	}
	if d.App != nil {
		startFields["config_path"] = configPath()
		startFields["state_path"] = d.App.StatePath
	}
	maps.Copy(startFields, buildInfoFields())
	d.logInfo("daemon", "started", startFields)
	d.logDebug("daemon", "startup_publish_begin", nil)
	if _, err := d.prepareStartupState(); err != nil {
		d.logWarn("daemon", "startup_publish_failed", map[string]any{"error": err})
	}
	d.logDebug("daemon", "startup_publish_done", nil)
	logAutoJoinPending(d.Log, d.StateStore.common.ReadView().State)

	startupNow := d.now()
	ipsecReconcileInterval := d.ipsecReconcileInterval()
	routingReconcileInterval := d.routingReconcileInterval()
	firewallReconcileInterval := d.firewallReconcileInterval()
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
	if err := d.scheduleDaemonTimer(daemonTimerEndpoint, startupNow); err != nil {
		return err
	}
	if err := d.scheduleDaemonTimer(daemonTimerSync, startupNow); err != nil {
		return err
	}
	if err := d.scheduleDaemonTimer(daemonTimerIPsec, nextIPsecReconcileTime(startupNow, ipsecReconcileInterval)); err != nil {
		return err
	}
	if err := d.scheduleDaemonTimer(daemonTimerRouting, nextRoutingReconcileTime(startupNow, routingReconcileInterval)); err != nil {
		return err
	}
	if err := d.scheduleDaemonTimer(daemonTimerFirewall, nextFirewallReconcileTime(startupNow, firewallReconcileInterval)); err != nil {
		return err
	}
	if d.health != nil && d.health.Manager != nil {
		if err := d.scheduleDaemonTimer(daemonTimerHealth, startupNow); err != nil {
			return err
		}
	}
	var forceSync bool
	for {
		if ctx.Err() != nil {
			return nil
		}
		now := d.now()
		syncNow, shutdown, ipsecFlushed, routingFlushed, firewallFlushed := d.processEvents(ctx)
		if shutdown {
			return nil
		}
		if syncNow {
			forceSync = true
			if err := d.scheduleDaemonTimer(daemonTimerSync, now); err != nil {
				return err
			}
		}
		if ipsecFlushed {
			if err := d.scheduleDaemonTimer(daemonTimerIPsec, nextIPsecReconcileTime(now, ipsecReconcileInterval)); err != nil {
				return err
			}
		}
		if interval := d.ipsecReconcileInterval(); interval != ipsecReconcileInterval {
			ipsecReconcileInterval = interval
			if err := d.scheduleDaemonTimer(daemonTimerIPsec, nextIPsecReconcileTime(now, interval)); err != nil {
				return err
			}
		}
		if routingFlushed {
			if err := d.scheduleDaemonTimer(daemonTimerRouting, nextRoutingReconcileTime(now, routingReconcileInterval)); err != nil {
				return err
			}
		}
		if interval := d.routingReconcileInterval(); interval != routingReconcileInterval {
			routingReconcileInterval = interval
			if err := d.scheduleDaemonTimer(daemonTimerRouting, nextRoutingReconcileTime(now, interval)); err != nil {
				return err
			}
		}
		if firewallFlushed {
			if err := d.scheduleDaemonTimer(daemonTimerFirewall, nextFirewallReconcileTime(now, firewallReconcileInterval)); err != nil {
				return err
			}
		}
		if interval := d.firewallReconcileInterval(); interval != firewallReconcileInterval {
			firewallReconcileInterval = interval
			if err := d.scheduleDaemonTimer(daemonTimerFirewall, nextFirewallReconcileTime(now, interval)); err != nil {
				return err
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case event := <-d.Events:
			result, triggerSync, stop := d.handleEvent(event)
			if event.Reply != nil {
				event.Reply <- result
			}
			if stop {
				return nil
			}
			if triggerSync {
				forceSync = true
				if err := d.scheduleDaemonTimer(daemonTimerSync, d.now()); err != nil {
					return err
				}
			}
		case _, ok := <-healthUpdates:
			if !ok {
				healthUpdates = nil
				continue
			}
			d.handleHealthUpdate(d.now())
		case timerEvent := <-d.daemonTimerEvents:
			if fired, ok := timerEvent.(corehost.TimerFired); ok {
				if !d.daemonTimers.Accept(fired) {
					continue
				}
				now := d.now()
				switch fired.ID.Key {
				case daemonTimerEndpoint:
					result, triggerSync, _ := d.handleEvent(daemonEvent{Type: daemonEventEndpointTimer, Context: ctx})
					if result.Error != nil {
						d.logWarn("endpoint", "publish_failed", map[string]any{"error": result.Error})
					}
					if triggerSync {
						forceSync = true
						if err := d.scheduleDaemonTimer(daemonTimerSync, now); err != nil {
							return err
						}
					}
					interval := d.App.Config.ReflectorInterval
					if interval <= 0 {
						interval = 5 * time.Minute
					}
					if err := d.scheduleDaemonTimer(daemonTimerEndpoint, now.Add(interval)); err != nil {
						return err
					}
				case daemonTimerSync:
					if d.flushPeerLifecycleCleanup() {
						d.updateDiscoveredPeers()
						d.notifyStateChanged()
					}
					result, _, _ := d.handleEvent(daemonEvent{Type: daemonEventSyncTimer, ForceSync: forceSync, Context: ctx})
					if result.Error != nil {
						d.logDebug("sync", "timer_completed_with_error", map[string]any{"error": result.Error})
					}
					forceSync = false
					if err := d.scheduleDaemonTimer(daemonTimerSync, now.Add(d.Interval)); err != nil {
						return err
					}
				case daemonTimerIPsec:
					d.ipsecDirty = true
					if d.flushIPsecReconcile(ctx) {
						if err := d.scheduleDaemonTimer(daemonTimerIPsec, nextIPsecReconcileTime(now, ipsecReconcileInterval)); err != nil {
							return err
						}
					}
				case daemonTimerRouting:
					d.routingDirty = true
					if d.flushRoutingReconcile(ctx) {
						if err := d.scheduleDaemonTimer(daemonTimerRouting, nextRoutingReconcileTime(now, routingReconcileInterval)); err != nil {
							return err
						}
					}
				case daemonTimerFirewall:
					d.firewallDirty = true
					if d.flushFirewallReconcile(ctx) {
						if err := d.scheduleDaemonTimer(daemonTimerFirewall, nextFirewallReconcileTime(now, firewallReconcileInterval)); err != nil {
							return err
						}
					}
				case daemonTimerHealth:
					d.health.TickAsync(ctx, now)
					if err := d.scheduleDaemonTimer(daemonTimerHealth, now.Add(time.Second)); err != nil {
						return err
					}
				}
				continue
			}
		case hostEvent := <-d.gossipDriver.Events():
			_, _ = d.handleGossipDriverEvent(ctx, hostEvent)
		}
	}
}

func (d *Daemon) startControlServer(ctx context.Context) (func(), error) {
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

func (d *Daemon) serveControl(ctx context.Context, listener net.Listener, done chan<- struct{}) {
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

func (d *Daemon) handleControlConn(ctx context.Context, conn net.Conn) {
	defer conn.Close()
	var request controlRequest
	_ = conn.SetReadDeadline(time.Now().Add(controlConnDeadline))
	if err := json.NewDecoder(conn).Decode(&request); err != nil {
		writeControlResponse(conn, controlError(err))
		return
	}
	_ = conn.SetReadDeadline(time.Time{})
	switch request.Method {
	case "daemon_status_view":
		writeCanonicalView(conn, daemonStatusView(d))
	case "root_public_key":
		common := d.StateStore.common.ReadView()
		var rootPublicKey ed25519.PublicKey
		if common.State != nil && common.State.Network != nil {
			if root := common.State.Network.Zones[zone.RootZone]; root != nil && root.Authority != nil && len(root.Authority.Keys) > 0 {
				rootPublicKey = append(ed25519.PublicKey(nil), root.Authority.Keys[0].Key...)
			}
		}
		if len(rootPublicKey) == 0 {
			writeControlResponse(conn, controlError(errors.New("root authority has no public key")))
			return
		}
		writeCanonicalView(conn, rootPublicKey)
	case "status_view":
		common, runtime := d.StateStore.readCommonAndRuntime()
		links, reconcile := d.linuxObservation.ipsecSnapshot()
		writeCanonicalView(conn, statusViewFromOwners(d.App, common, runtime, links, reconcile, d.healthStatusResponse(), true))
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
		view := d.StateStore.common.ReadView()
		var network *zone.NetworkState
		if view.State != nil {
			network = view.State.Network
		}
		record, err := lookupRecordDetailFromNetwork(network, zone.ZonePath(request.Zone), request.Key, request.History)
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, record)
	case "records_view":
		view := d.StateStore.common.ReadView()
		var network *zone.NetworkState
		if view.State != nil {
			network = view.State.Network
		}
		records, err := buildRecordsInspection(network, zone.ZonePath(request.Zone), request.Key)
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, records)
	case "zones_view":
		view := d.StateStore.common.ReadView()
		if view.State == nil || view.State.Network == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		writeCanonicalView(conn, buildZoneDetails(view.State.Network, d.now()))
	case "services_view":
		view := d.StateStore.common.ReadView()
		if view.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		services := inspect.BuildServiceInspection(view.State, d.now())
		writeCanonicalView(conn, services)
	case "route_view":
		view := d.StateStore.common.ReadView()
		if view.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		report, err := buildRouteShowReportFromState(view.State, d.now(), zone.ZonePath(request.Zone), request.IncludeAll)
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, *report)
	case "ipam_assignments_view":
		view := d.StateStore.common.ReadView()
		rows, err := buildIPAMAssignmentRows(view.State, d.now(), zone.ZonePath(request.Zone))
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, rows)
	case "ipam_mine_view":
		view := d.StateStore.common.ReadView()
		report, err := buildIPAMMineReportFromState(view.State, d.now())
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, *report)
	case "ipam_get_view":
		view := d.StateStore.common.ReadView()
		report, err := buildIPAMGetReportFromState(view.State, d.now(), request.ValueText)
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, *report)
	case "endpoints_view":
		view := d.StateStore.common.ReadView()
		if view.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		endpoints := inspect.BuildEndpointDebug(view.State, d.now())
		writeCanonicalView(conn, endpoints)
	case "ping_targets":
		common, _ := d.StateStore.readCommonAndRuntime()
		if common.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		links, reconcile := d.linuxObservation.ipsecSnapshot()
		targets := linkstate.HealthTargets(buildLinkOutputs(links, reconcile), string(common.State.ManagedZone))
		writeCanonicalView(conn, inspectHealthProbeTargets(targets))
	case "sync_view":
		common, _ := d.StateStore.readCommonAndRuntime()
		if common.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		view := inspect.BuildSyncStatus(common, syncStatusOptions(d.currentGossipConfig(), d.now(), request.Verbose))
		writeCanonicalView(conn, view)
	case "peer_debug":
		common, _ := d.StateStore.readCommonAndRuntime()
		if common.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		view, ok := inspect.BuildGossipPeerDebugView(common, gossipPeersOptions(d.currentGossipConfig(), d.peerObservabilitySnapshots(), d.now()), request.Zone)
		if !ok {
			writeControlResponse(conn, controlError(fmt.Errorf("%w: %s", zone.ErrZoneNotFound, request.Zone)))
			return
		}
		writeCanonicalView(conn, view)
	case "zone_debug":
		common := d.StateStore.common.ReadView()
		if common.State == nil || common.State.Network == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		path := zone.ZonePath(request.Zone)
		configureValidation(common.State.Network)
		inspection, ok := inspect.BuildZoneInspection(common.State.Network, path, d.now(), request.History > 0)
		if !ok {
			writeControlResponse(conn, controlError(fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)))
			return
		}
		writeCanonicalView(conn, inspection)
	case "verify_chain":
		view := d.StateStore.common.ReadView()
		if view.State == nil || view.State.Network == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		configureValidation(view.State.Network)
		if err := photoncrypto.VerifyChain(view.State.Network, zone.ZonePath(request.Zone), d.now()); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, true)
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
		d.StateStore.mu.RLock()
		acls := make([]endpointACL, 0, len(d.StateStore.runtime.EndpointACLs))
		for _, acl := range d.StateStore.runtime.EndpointACLs {
			acl.Selectors = append([]string(nil), acl.Selectors...)
			acls = append(acls, acl)
		}
		d.StateStore.mu.RUnlock()
		sort.Slice(acls, func(i, j int) bool { return acls[i].Name < acls[j].Name })
		writeCanonicalView(conn, acls)
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
	case "babel_view":
		d.StateStore.mu.RLock()
		lastRoutingError := ""
		if d.StateStore.runtime.RoutingReconcile != nil {
			lastRoutingError = d.StateStore.runtime.RoutingReconcile.LastError
		}
		view := buildBabelDebugView(d.App, d.StateStore.runtime.BirdInstances, lastRoutingError)
		d.StateStore.mu.RUnlock()
		writeCanonicalView(conn, view)
	case "bird_dump":
		dump, err := d.birdDumpForControl(ctx, request.NetNS, birdDebugView(request.BirdView))
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, *dump)
	case "routes_view":
		var routingInstances []RoutingInstance
		if d.App != nil && d.App.Config != nil {
			routingInstances = append([]RoutingInstance(nil), d.App.Config.Routing.Instances...)
		}
		d.StateStore.writeMu.Lock()
		view := d.StateStore.common.ReadView()
		d.StateStore.mu.RLock()
		birdInstances := photonstate.CloneBirdInstances(d.StateStore.runtime.BirdInstances)
		d.StateStore.mu.RUnlock()
		d.StateStore.writeMu.Unlock()
		if view.State == nil || view.State.Network == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		ars, err := routing.BuildAuthorizedRouteSet(view.State.Network, d.now())
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		routesDump := inspect.RoutesFromAuthorizedSet(view.State.ManagedZone, ars)
		routesDump.BIRD = d.birdRoutesForControl(ctx, routesDump, routingInstances, birdInstances)
		writeCanonicalView(conn, *routesDump)
	case "admission_status":
		view := d.StateStore.common.ReadView()
		if view.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		var bootstrap []syncConfigPeer
		if d.App != nil && d.App.Config != nil {
			bootstrap = d.App.Config.Bootstrap
		}
		diagnosis := diagnoseAutoJoinAdmission(view.State, view.Gossip, bootstrap, d.now())
		writeCanonicalView(conn, diagnosis)
	case "firewall_view":
		d.StateStore.mu.RLock()
		fwSnapshot := photonstate.CloneFirewallReconcileState(d.StateStore.runtime.FirewallReconcile)
		d.StateStore.mu.RUnlock()
		instances := []FirewallInstanceConfig(nil)
		var appCfg *appConfig
		if d.App != nil && d.App.Config != nil {
			appCfg = d.App.Config
			instances = appCfg.Firewall.Instances
		}
		instances = filterFirewallDebugInstances(instances, request.NetNS, request.Host)
		writeCanonicalView(conn, buildFirewallDebugView(appCfg, instances, fwSnapshot))
	case "links_view":
		health := d.healthStatusResponse()
		links, reconcile := d.linuxObservation.ipsecSnapshot()
		d.StateStore.mu.RLock()
		bird := photonstate.CloneBirdInstances(d.StateStore.runtime.BirdInstances)
		d.StateStore.mu.RUnlock()
		view := buildStoredLinkInspection(observerRuntime(d), links, reconcile, bird, health)
		if d.linuxDriver != nil && d.App != nil && d.App.Config != nil && d.App.Config.IPsec.Driver != ipsecDriverDryRun {
			sas, err := d.linuxDriver.ListIPsecSAs(ctx)
			if err != nil {
				view.LiveSAError = err.Error()
			} else {
				view.LiveSAs = inspectLinkSAs(linkSAStatesFromIPsecSAs(sas))
			}
		}
		writeCanonicalView(conn, view)
	case "peer_lifecycle_view":
		common, runtime := d.StateStore.readCommonAndRuntime()
		if common.State == nil || runtime == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		links, reconcile := d.linuxObservation.ipsecSnapshot()
		writeCanonicalView(conn, buildPeerLifecycleDebugView(d.App, common, runtime, links, reconcile))
	case "gossip_peers_view":
		writeCanonicalView(conn, d.gossipPeerSnapshotForControl())
	case "revocation_view":
		observedLinks, _ := d.linuxObservation.ipsecSnapshot()
		linkStates := observedLinks
		d.StateStore.writeMu.Lock()
		view := d.StateStore.common.ReadView()
		d.StateStore.mu.RLock()
		if view.State == nil || d.StateStore.runtime == nil {
			d.StateStore.mu.RUnlock()
			d.StateStore.writeMu.Unlock()
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		var impacts []inspect.RevocationImpact
		if request.Zone != "" {
			impacts = []inspect.RevocationImpact{ComputeRevocationImpact(view.State.Network, linkStates, view.Gossip, zone.ZonePath(request.Zone), d.now())}
		} else {
			impacts = AllRevocationImpact(view.State.Network, linkStates, view.Gossip, d.currentGossipConfig(), d.now())
		}
		d.StateStore.mu.RUnlock()
		d.StateStore.writeMu.Unlock()
		writeCanonicalView(conn, impacts)
	case "health_status":
		common, _ := d.StateStore.readCommonAndRuntime()
		links, reconcile := d.linuxObservation.ipsecSnapshot()
		writeCanonicalView(conn, healthViewFromOwners(common, links, reconcile, d.healthStatusResponse()))
	default:
		writeControlResponse(conn, controlError(fmt.Errorf("unknown control method: %s", request.Method)))
	}
}

func (d *Daemon) enqueueEvent(ctx context.Context, event daemonEvent) daemonEventResult {
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

func (d *Daemon) processEvents(ctx context.Context) (syncNow bool, shutdown bool, ipsecFlushed bool, routingFlushed bool, firewallFlushed bool) {
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

func (d *Daemon) handleEvent(event daemonEvent) (daemonEventResult, bool, bool) {
	switch event.Type {
	case daemonEventRecordPut:
		version, err := d.handleRecordPutEvent(event.RecordPut)
		return daemonEventResult{Version: version, Error: err}, err == nil, false
	case daemonEventIPAMMutation:
		if event.IPAM == nil {
			return daemonEventResult{Error: errors.New("ipam mutation event is nil")}, false, false
		}
		intent, err := commonIPAMIntent(*event.IPAM)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		result, err := d.handleCommonRecordMutationEvent(intent, event.IPAM.DryRun)
		return daemonEventResult{Version: recordMutationVersion(result), Error: err}, err == nil && result != nil && !result.DryRun, false
	case daemonEventRouteMutation:
		if event.Route == nil {
			return daemonEventResult{Error: errors.New("route mutation event is nil")}, false, false
		}
		result, err := d.handleCommonRecordMutationEvent(commonRouteIntent(*event.Route), event.Route.DryRun)
		return daemonEventResult{Version: recordMutationVersion(result), Error: err}, err == nil && result != nil && !result.DryRun, false
	case daemonEventServiceMutation:
		if event.Service == nil {
			return daemonEventResult{Error: errors.New("service mutation event is nil")}, false, false
		}
		intent, err := commonServiceIntent(*event.Service)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		result, err := d.handleCommonRecordMutationEvent(intent, event.Service.DryRun)
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

func (d *Daemon) handleReloadConfigEvent() error {
	if d == nil || d.App == nil {
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
	if d.App.StatePath != "" && statePath != d.App.StatePath {
		return fmt.Errorf("reload would change state path from %s to %s; restart daemon to switch state", d.App.StatePath, statePath)
	}
	socketPath := controlSocketPath(config)
	if d.ControlSocketPath != "" && socketPath != d.ControlSocketPath {
		return fmt.Errorf("reload would change control socket path from %s to %s; restart daemon to switch control socket", d.ControlSocketPath, socketPath)
	}
	common, runtime := d.StateStore.readCommonAndRuntime()
	if common.State == nil || runtime == nil {
		return errors.New("daemon state is not initialized")
	}
	if err := validateConfiguredIdentityState(common.State, config); err != nil {
		return err
	}
	syncConfig := gossipStartupConfigFromAppConfig(config, common.State)
	nextLogger := newAppLogger(config)
	linuxDriver, err := newConfiguredLinuxDriver(config.IPsec, config.Netns.Names, nextLogger)
	if err != nil {
		return err
	}
	d.App.Config = config
	d.App.StatePath = statePath
	if err := d.gossipDriver.ReplaceGossipConfig(gossipDriverConfig(syncConfig, config, nextLogger)); err != nil {
		_ = linuxDriver.Close()
		return err
	}
	if err := d.installLinuxDriver(linuxDriver); err != nil {
		return err
	}
	d.Log = nextLogger
	d.ControlSocketPath = socketPath
	if d.gossipDriver != nil && d.gossipDriver.Transport() != nil {
		d.updateDiscoveredPeers()
	}
	d.notifyStateChanged()
	d.recoverRoutingOnStart(context.Background())
	return nil
}

func (d *Daemon) handleDelegateIssueEvent(request *joinRequest, permissions []zone.Permission) (*delegationIssueResult, error) {
	if err := validateJoinRequest(request); err != nil {
		return nil, err
	}
	view := d.StateStore.common.ReadView()
	parent := request.Zone.Parent()
	parentState := view.State.Network.Zones[parent]
	if parentState == nil || parentState.Authority == nil {
		return nil, fmt.Errorf("%w: parent %s", zone.ErrZoneNotFound, parent)
	}
	epoch := uint64(1)
	if revoked := parentState.Revocations[request.Zone]; revoked != nil && revoked.RevokedAuthorityEpoch >= epoch {
		epoch = revoked.RevokedAuthorityEpoch + 1
	}
	authority := &zone.ZoneAuthority{Zone: request.Zone, Epoch: epoch, Threshold: photoncrypto.SupportedThreshold,
		Keys: []zone.AuthorizedKey{{Key: append([]byte(nil), request.PublicKey...), Capabilities: delegationCapabilities(permissions)}}}
	result, err := d.StateStore.ApplyCommonLocalIntent(context.Background(), corestate.PutDelegationIntent{
		Parent: parent, Authority: authority,
	}, false, d.now())
	if err != nil {
		return nil, err
	}
	bundle, err := joinBundleFromNetwork(d.StateStore.common.ReadView().State.Network, request.Zone, d.now())
	if err != nil {
		return nil, err
	}
	if result.Committed {
		d.updateDiscoveredPeers()
		d.notifyStateChanged()
	}
	return &delegationIssueResult{Zone: request.Zone, Bundle: bundle}, nil
}

func (d *Daemon) handleDelegateGrantEvent(path zone.ZonePath, permissions []zone.Permission) (*joinBundle, error) {
	if !path.Valid() || len(permissions) == 0 {
		return nil, errors.New("valid delegated zone and at least one permission are required")
	}
	view := d.StateStore.common.ReadView()
	if view.State == nil || view.State.Network == nil || view.State.Network.Zones[path] == nil || view.State.Network.Zones[path].Authority == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	authority := cloneAuthorityForJoinBundle(view.State.Network.Zones[path].Authority)
	grantPermissionsToAuthority(authority, permissions)
	authority.Epoch++
	var intent corestate.LocalIntent
	if path.IsRoot() {
		intent = corestate.UpdateRootAuthorityIntent{Authority: authority}
	} else {
		intent = corestate.PutDelegationIntent{Parent: path.Parent(), Authority: authority}
	}
	result, err := d.StateStore.ApplyCommonLocalIntent(context.Background(), intent, false, d.now())
	if err != nil {
		return nil, err
	}
	if result.Committed {
		d.updateDiscoveredPeers()
		d.notifyStateChanged()
	}
	if path.IsRoot() {
		return nil, nil
	}
	return joinBundleFromNetwork(d.StateStore.common.ReadView().State.Network, path, d.now())
}

func joinBundleFromNetwork(network *zone.NetworkState, path zone.ZonePath, now time.Time) (*joinBundle, error) {
	if network == nil {
		return nil, errors.New("network is nil")
	}
	rootKey, err := rootPublicKey(network)
	if err != nil {
		return nil, err
	}
	bundleNetwork, err := minimalNetworkForJoinBundle(network, path)
	if err != nil {
		return nil, err
	}
	configureValidation(bundleNetwork)
	if err := photoncrypto.VerifyChain(bundleNetwork, path, now); err != nil {
		return nil, err
	}
	return &joinBundle{Version: 1, Zone: path, RootPublicKey: rootKey, Network: bundleNetwork}, nil
}

func (d *Daemon) handleRecoveryImportZoneEvent(snapshot *corestate.ZoneSnapshot) (*corestate.ApplyResult, int, error) {
	result, err := d.StateStore.ImportCommonRecovery(context.Background(), corestate.RecoveryImport{
		Snapshot: snapshot,
		Limits:   syncLimits(d.currentGossipConfig()),
	}, d.now())
	if err != nil {
		return nil, 0, err
	}
	if result.Committed {
		d.updateDiscoveredPeers()
		d.notifyStateChanged()
	}
	revocations := 0
	if result.Apply != nil {
		if current := d.StateStore.common.ReadView(); current.State != nil && current.State.Network != nil {
			if zs := current.State.Network.Zones[result.Apply.Zone]; zs != nil {
				revocations = len(zs.Revocations)
			}
		}
	}
	return result.Apply, revocations, nil
}

func (d *Daemon) handleDelegateRevokeEvent(path zone.ZonePath, reason string) error {
	result, err := d.StateStore.ApplyCommonLocalIntent(context.Background(), corestate.RevokeDelegationIntent{
		Parent: path.Parent(), Child: path, Reason: reason,
	}, false, d.now())
	if err != nil {
		return err
	}
	if result.Committed {
		d.updateDiscoveredPeers()
		d.notifyStateChanged()
	}
	return nil
}

// handleRecoveryPurgeRevokedEvent runs the manual revoked-zone GC. It always
// computes the plan (returned for reporting); when apply is true it also
// executes the deletions, persists, and notifies subsystems so the running node
// reconciles (e.g. tears down orphaned IPsec for removed link instances).
func (d *Daemon) handleRecoveryPurgeRevokedEvent(ctx context.Context, target zone.ZonePath, apply bool) (*purgePlan, error) {
	if d.StateStore == nil {
		return nil, errors.New("daemon service is not initialized")
	}
	now := d.now()
	commonPlan, err := d.StateStore.PlanCommonPurge(now, target)
	if err != nil {
		return nil, err
	}
	common, runtime := d.StateStore.readCommonAndRuntime()
	if common.State == nil || runtime == nil {
		return nil, errors.New("daemon state is not loaded")
	}
	links, reconcile := d.linuxObservation.ipsecSnapshot()
	plan := mergePurgePlan(commonPlan, links)
	if !apply {
		return plan, nil
	}
	if err := d.cleanupPurgePlanIPsecLinks(ctx, links, reconcile, plan); err != nil {
		return nil, err
	}
	if _, _, err := d.StateStore.commitRuntimeIfRevision(uint64(common.Revision), func(candidate *linuxRuntimeState) {
		for _, peerID := range plan.SyncPeers {
			delete(candidate.PeerCleanups, peerID)
		}
	}); err != nil {
		return nil, err
	}
	result, err := d.StateStore.PurgeCommon(ctx, now, target)
	if err != nil {
		return nil, err
	}
	for _, peerID := range plan.SyncPeers {
		d.gossipDriver.Observability.Delete(peerID)
	}
	if d.gossipDriver != nil && d.gossipDriver.Transport() != nil {
		d.updateDiscoveredPeers()
	}
	if result.Committed || len(plan.LinkInstances) > 0 {
		d.notifyStateChanged()
	}
	return plan, nil
}

func (d *Daemon) cleanupPurgePlanIPsecLinks(ctx context.Context, links map[string]linkInstanceState, reconcile *ipsecObservationSummary, plan *purgePlan) error {
	if plan == nil || len(plan.LinkInstances) == 0 {
		return nil
	}
	if d == nil || d.App == nil {
		return errors.New("daemon service is not initialized")
	}
	platformDriver := d.linuxDriver
	if platformDriver == nil {
		return errors.New("linux driver is not initialized")
	}
	remaining, _, err := cleanupIPsecLinkInstanceSet(ctx, links, plan.LinkInstances, platformDriver)
	if err == nil {
		d.linuxObservation.replaceIPsec(remaining, markIPsecCleanupReconcile(reconcile, d.now()))
	}
	return err
}

func (d *Daemon) handleJoinAcceptEvent(bundle *joinBundle, key *privateKeyFile) (*joinAcceptResult, error) {
	if d == nil || d.App == nil || d.StateStore == nil {
		return nil, errors.New("daemon service is not initialized")
	}
	if bundle == nil || bundle.Version != 1 || bundle.Network == nil {
		return nil, errors.New("invalid join bundle")
	}
	if key == nil {
		var err error
		key, err = joinAcceptKeyFromIdentity(d.StateStore.common.ReadView().State, bundle.Zone)
		if err != nil {
			return nil, err
		}
	}
	if err := validatePrivateKeyFile(key); err != nil {
		return nil, err
	}
	commit, err := d.StateStore.InstallCommonIdentity(context.Background(), corestate.IdentityInstall{
		ManagedZone: bundle.Zone, Network: bundle.Network,
		TrustedRootPublicKey: bundle.RootPublicKey, IdentityPrivateKey: key.PrivateKey,
	}, d.now())
	if err != nil {
		return nil, err
	}
	if commit.Committed && d.gossipDriver != nil && d.gossipDriver.Transport() != nil {
		d.updateDiscoveredPeers()
	}
	if commit.Committed {
		d.notifyStateChanged()
	}
	return &joinAcceptResult{Zone: bundle.Zone, RootPublicKey: append([]byte(nil), bundle.RootPublicKey...)}, nil
}

func (d *Daemon) handleEndpointTimerEvent() (bool, error) {
	d.logDebug("endpoint", "timer_begin", nil)
	changed, err := d.publishLocalProtocols()
	if err != nil {
		return false, err
	}
	d.logDebug("endpoint", "timer_done", map[string]any{"changed": changed})
	return changed, nil
}

func (d *Daemon) prepareStartupState() (bool, error) {
	commit, authority, err := d.StateStore.RefreshCommonManagedAuthority(context.Background(), d.now())
	if err != nil {
		return false, err
	}
	if authority.Adopted || authority.Refreshed {
		view := d.StateStore.common.ReadView()
		if view.State != nil {
			d.logInfo("authority", "managed_zone_refreshed", map[string]any{"zone": view.State.ManagedZone})
		}
	}
	published, err := d.publishLocalProtocols()
	return commit.Committed || published, err
}

func (d *Daemon) publishLocalProtocols() (bool, error) {
	if d == nil || d.StateStore == nil {
		return false, errors.New("daemon service is not initialized")
	}
	common, runtime := d.StateStore.readCommonAndRuntime()
	if common.State == nil || common.State.Network == nil || runtime == nil {
		return false, errors.New("daemon state network is nil")
	}
	revision := uint64(common.Revision)
	var intents []corestate.LocalIntent
	endpoint, err := d.endpointProtocolIntent(common.State)
	if err != nil {
		return false, fmt.Errorf("plan endpoint record: %w", err)
	}
	if endpoint != nil {
		intents = append(intents, *endpoint)
	}
	ipsecPlan, err := d.ipsecProtocolPlan(common.State, runtime)
	if err != nil {
		return false, fmt.Errorf("plan IPsec records: %w", err)
	}
	intents = append(intents, ipsecPlan.Intents...)
	if ipsecPlan.TransportKey != nil {
		runtime.IPsecTransportKey = photonstate.CloneIPsecTransportKeyState(ipsecPlan.TransportKey)
	}
	routingIntent, err := d.routingNetnsProtocolIntent(common.State)
	if err != nil {
		return false, fmt.Errorf("plan routing record: %w", err)
	}
	if routingIntent != nil {
		intents = append(intents, *routingIntent)
	}
	result, err := d.StateStore.publishLocalProtocols(context.Background(), revision, intents, runtime, d.now())
	if err != nil {
		return false, err
	}
	changed := result.RuntimeCommitted || result.Common.Committed
	if changed {
		if d.gossipDriver != nil && d.gossipDriver.Transport() != nil {
			d.updateDiscoveredPeers()
		}
		d.notifyStateChanged()
	}
	return changed, nil
}

func (d *Daemon) handleRecordPutEvent(event *daemonRecordPut) (uint64, error) {
	if event == nil {
		return 0, errors.New("record_put event is nil")
	}
	if err := validateGenericRecordPut(event.Key, event.Type); err != nil {
		return 0, err
	}
	if d.StateStore == nil {
		return 0, errors.New("daemon service is not initialized")
	}
	result, err := d.handleCommonRecordMutationEvent(corestate.PutRecordIntent{
		Zone: event.Zone, Key: event.Key, Type: event.Type, Value: append([]byte(nil), event.Value...),
	}, false)
	return recordMutationVersion(result), err
}

func (d *Daemon) handleCommonRecordMutationEvent(intent corestate.LocalIntent, dryRun bool) (*recordMutationResult, error) {
	if d == nil || d.StateStore == nil {
		return nil, errors.New("daemon service is not initialized")
	}
	result, err := d.StateStore.ApplyCommonLocalIntent(context.Background(), intent, dryRun, d.now())
	if err != nil {
		return nil, err
	}
	out := &recordMutationResult{DryRun: dryRun}
	if result.Record != nil {
		out.Zone, out.Key, out.Version = result.Record.Zone, result.Record.Key, result.Record.Version
	}
	if result.Committed {
		if d.gossipDriver != nil && d.gossipDriver.Transport() != nil {
			d.updateDiscoveredPeers()
		}
		d.notifyStateChanged()
	}
	return out, nil
}

func recordMutationVersion(result *recordMutationResult) uint64 {
	if result == nil {
		return 0
	}
	return result.Version
}

func (d *Daemon) handleIPsecPortRotateEvent() (*manualPortRotateResult, error) {
	common, runtime := d.StateStore.readCommonAndRuntime()
	if common.State == nil || runtime == nil {
		return nil, errors.New("daemon state is not initialized")
	}
	revision := uint64(common.Revision)
	record, result, err := planLocalIPsecPortRotation(d.App.Config, common.State, d.now())
	if err != nil {
		return nil, err
	}
	value, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	committed, err := d.StateStore.publishLocalProtocols(context.Background(), revision, []corestate.LocalIntent{
		corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordIPsec, Zone: common.State.ManagedZone, Key: ipsec.RecordKeyPorts, Type: ipsec.RecordTypePorts, Value: value},
	}, runtime, d.now())
	if err != nil {
		return nil, err
	}
	if committed.RuntimeCommitted || committed.Common.Committed {
		d.notifyStateChanged()
	}
	return result, nil
}

func (d *Daemon) notifyStateChanged() {
	if d.Hooks.OnStateChanged != nil {
		d.Hooks.OnStateChanged()
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
	// Gossip-only commands construct the common host driver without a Linux
	// platform driver. Their committed state is still valid, but platform
	// reconciliation belongs to the full daemon that owns those drivers.
	if d.linuxDriver == nil {
		d.notifyObserver("peer_updated", d.observerPeerIDsPayload())
		return
	}

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

func (d *Daemon) publishStateStoreRuntimeFlags() {
	if d == nil || d.StateStore == nil {
		return
	}
	d.StateStore.SetDirty(daemonDirtyFlags{
		IPsec:    d.ipsecDirty,
		Routing:  d.routingDirty,
		Firewall: d.firewallDirty,
	})
}

func (d *Daemon) noteReconcileFlush(layer string) {
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
func (d *Daemon) flushRevocationCleanup() {
	if d == nil || d.StateStore == nil {
		return
	}
	// This function is called after every sync-state update. Most calls have no
	// revocations, so check the immutable committed state first and avoid the
	// copy-on-write transaction (which deep-copies the whole state through JSON).
	now := d.now()
	view := d.StateStore.common.ReadView()
	if view.State == nil {
		return
	}
	revokedZones := collectAllRevokedZones(view.State.Network, now)
	if len(revokedZones) == 0 {
		return
	}
	needsStateCleanup := false
	if view.Gossip != nil {
		for peerID, peer := range view.Gossip.Peers {
			if revokedZones[zone.ZonePath(peerID)] && peerNeedsRevocationCleanup(peer) {
				needsStateCleanup = true
				break
			}
		}
	}
	d.noteReconcileFlush("revocation_cleanup")
	if needsStateCleanup {
		patches := make(map[string]corestate.PeerCheckpointPatch)
		for path := range revokedZones {
			peerID := path.String()
			patches[peerID] = corestate.PeerCheckpointPatch{
				DiscoveredEndpoint: corestate.PatchField[string]{Set: true}, DiscoveredAtUnix: corestate.PatchField[int64]{Set: true},
				ObservedEndpoint: corestate.PatchField[string]{Set: true}, ObservedFirstUnix: corestate.PatchField[int64]{Set: true},
				ObservedLastUnix: corestate.PatchField[int64]{Set: true}, ObservedSyncUnix: corestate.PatchField[int64]{Set: true},
				ObservedUntilUnix: corestate.PatchField[int64]{Set: true}, ObservedFailures: corestate.PatchField[int]{Set: true},
				ObservedGrace:    corestate.PatchField[[]corestate.ObservedGraceEndpoint]{Set: true},
				BackoffUntilUnix: corestate.PatchField[int64]{Set: true}, FailureCount: corestate.PatchField[int]{Set: true},
				LastFailure: corestate.PatchField[*corestate.PeerFailure]{Set: true, Value: &corestate.PeerFailure{
					Code: corestate.PeerFailureLegacy, Message: "zone revoked", AtUnix: d.now().Unix(),
				}},
			}
		}
		if _, err := d.StateStore.common.UpdatePeerCheckpoints(context.Background(), patches); err != nil {
			d.logWarn("sync", "revocation_cleanup_commit_failed", map[string]any{"error": err})
			return
		}
	}
	for peerID := range d.peerObservabilitySnapshots() {
		if revokedZones[zone.ZonePath(peerID)] {
			d.gossipDriver.Observability.Delete(peerID)
		}
	}
}

func (d *Daemon) recoverIPsecLinksOnStart(ctx context.Context) {
	if d == nil {
		return
	}
	d.ipsecPrepareStandby = true
	defer func() { d.ipsecPrepareStandby = false }()
	d.ipsecDirty = true
	d.flushIPsecReconcile(ctx)
}

func (d *Daemon) recoverRoutingOnStart(ctx context.Context) {
	if d == nil {
		return
	}
	d.routingDirty = true
	d.flushRoutingReconcile(ctx)
}

func (d *Daemon) flushRoutingReconcile(ctx context.Context) bool {
	flushed, err := d.flushRoutingReconcileResult(ctx)
	if err != nil {
		d.logWarn("routing", "reconcile_failed", map[string]any{"error": err})
	}
	return flushed
}

func (d *Daemon) flushRoutingReconcileResult(ctx context.Context) (bool, error) {
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

func (d *Daemon) routingReconcileInterval() time.Duration {
	if d == nil || d.App == nil || d.App.Config == nil {
		return 0
	}
	instances := routingInstancesEnabled(d.App.Config)
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

func (d *Daemon) flushIPsecReconcile(ctx context.Context) bool {
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

func (d *Daemon) startIPsecLifecycleEventWatcher(ctx context.Context) func() {
	if d == nil || d.linuxDriver == nil {
		return func() {}
	}
	watchCtx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		d.runIPsecLifecycleEventWatcher(watchCtx, d.linuxDriver)
	}()
	return func() {
		cancel()
		<-done
	}
}

// runIPsecLifecycleEventWatcher subscribes to StrongSwan lifecycle events in
// the background and forwards them to the daemon event loop. Each subscribe
// attempt is bounded by a timeout and retried with backoff: a wedged VICI
// daemon (accepting connections but never answering) must degrade to warning
// logs instead of blocking daemon startup, which a synchronous subscribe did.
func (d *Daemon) runIPsecLifecycleEventWatcher(ctx context.Context, driver *photonlinux.LinuxDriver) {
	backoff := time.Second
	for {
		subscribeCtx, cancelSubscribe := context.WithTimeout(ctx, ipsecLifecycleSubscribeTimeout)
		events, stop, supported, err := driver.SubscribeIPsecLifecycle(subscribeCtx)
		cancelSubscribe()
		if !supported {
			return
		}
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
func (d *Daemon) forwardIPsecLifecycleEvents(ctx context.Context, events <-chan ipsec.VICIEvent) bool {
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

func (d *Daemon) handleIPsecLifecycleEvent(ev ipsec.VICIEvent) {
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

func (d *Daemon) ipsecReconcileInterval() time.Duration {
	if d == nil || d.App == nil || d.App.Config == nil {
		return 0
	}
	groups := d.App.Config.IPsec.LinkGroups
	if len(groups) == 0 {
		links, _ := d.linuxObservation.ipsecSnapshot()
		hasLinkInstances := len(links) > 0
		if hasLinkInstances {
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
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	service, boltStore, err := openDaemon(rt, interval)
	if err != nil {
		return err
	}
	defer boltStore.Close()
	return service.Run(ctx)
}

func (d *Daemon) configureLinuxDriverFromConfig() error {
	if d == nil || d.App == nil || d.App.Config == nil {
		return nil
	}
	driver, err := newConfiguredLinuxDriver(d.App.Config.IPsec, d.App.Config.Netns.Names, d.Log)
	if err != nil {
		return err
	}
	return d.installLinuxDriver(driver)
}

func newConfiguredLinuxDriver(config ipsecConfig, networkNamespaces map[string]ipsec.NetNSSpec, logger photonlinux.Logger) (*photonlinux.LinuxDriver, error) {
	var logConfig func(event string, fields map[string]any)
	if logger != nil {
		logConfig = func(event string, fields map[string]any) {
			logger.Debug("ipsec", event, fields)
		}
	}
	driverName := config.Driver
	if driverName == "" {
		driverName = ipsecDriverStrongSwan
	}
	switch driverName {
	case ipsecDriverDryRun:
		dryRun := &ipsec.DryRunDriver{}
		return photonlinux.NewLinuxDriver(photonlinux.LinuxDriverOptions{
			IPsecDriver:       dryRun,
			XFRMDriver:        dryRun,
			NetworkNamespaces: networkNamespaces,
			Logger:            logger,
		})
	case ipsecDriverStrongSwan:
		if len(config.LinkGroups) == 0 {
			dryRun := &ipsec.DryRunDriver{}
			return photonlinux.NewLinuxDriver(photonlinux.LinuxDriverOptions{
				IPsecDriver:       dryRun,
				XFRMDriver:        dryRun,
				NetworkNamespaces: networkNamespaces,
				Logger:            logger,
			})
		}
		client, err := ipsec.NewReconnectingGoviciClient(config.VICISocket)
		if err != nil {
			return nil, fmt.Errorf("initialize strongswan vici client: %w", err)
		}
		initiateClientFactory := func() (ipsec.VICIClient, func() error, error) {
			client, err := ipsec.NewGoviciClient(config.VICISocket)
			if err != nil {
				return nil, nil, err
			}
			return client, client.Close, nil
		}
		return photonlinux.NewLinuxDriver(photonlinux.LinuxDriverOptions{
			IPsecDriver: &ipsec.StrongSwanDriver{
				VICI:                  client,
				LogConfig:             logConfig,
				InitiateAsync:         true,
				InitiateClientFactory: initiateClientFactory,
			},
			XFRMDriver:        ipsec.NewSystemXFRMDriver(config.DefaultNetNS),
			NetworkNamespaces: networkNamespaces,
			Close:             client.Close,
			Logger:            logger,
		})
	default:
		return nil, fmt.Errorf("unsupported ipsec driver %q", driverName)
	}
}

func (d *Daemon) installLinuxDriver(driver *photonlinux.LinuxDriver) error {
	if d == nil {
		if driver != nil {
			_ = driver.Close()
		}
		return errors.New("daemon service is nil")
	}
	if err := d.closeLinuxDriver(); err != nil {
		if driver != nil {
			_ = driver.Close()
		}
		return err
	}
	d.linuxDriver = driver
	if d.health == nil || d.health.Manager == nil || d.health.driverManaged {
		d.configureHealthManager()
	}
	return nil
}

func (d *Daemon) closeLinuxDriver() error {
	if d == nil || d.linuxDriver == nil {
		return nil
	}
	driver := d.linuxDriver
	d.linuxDriver = nil
	return driver.Close()
}

func (d *Daemon) logDebug(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Debug(component, event, fields)
	}
}

func (d *Daemon) logInfo(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Info(component, event, fields)
	}
}

func (d *Daemon) logWarn(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Warn(component, event, fields)
	}
}

func (d *Daemon) logError(component, event string, fields map[string]any) {
	if d != nil && d.Log != nil {
		d.Log.Error(component, event, fields)
	}
}

func (d *Daemon) scheduleDaemonTimer(key string, deadline time.Time) error {
	if d == nil || d.daemonTimers == nil {
		return corehost.ErrSchedulerStopped
	}
	id := corehost.TimerID{Namespace: daemonRuntimeNamespace, Owner: daemonTimerOwner, Key: key}
	if deadline.IsZero() {
		d.daemonTimers.Cancel(id)
		return nil
	}
	_, err := d.daemonTimers.Schedule(id, deadline)
	return err
}
