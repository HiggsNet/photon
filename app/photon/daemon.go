package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net"
	"time"

	"github.com/HiggsNet/photon/internal/observability/healthspool"
	"github.com/HiggsNet/photon/internal/observer"
	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// Daemon owns the running service. Internal methods require a non-nil receiver;
// optional subsystems may remain unconfigured. Run validates startup state.
type Daemon struct {
	Config                 *appConfig
	clock                  func() time.Time
	Interval               time.Duration
	ControlSocketPath      string
	Events                 chan daemonEvent
	Hooks                  DaemonHooks
	State                  *State
	linuxDriver            *photonlinux.LinuxDriver
	ipsecDNSResolver       ipsec.DNSResolver
	health                 *healthDriver
	observerHub            *observer.Hub
	Log                    *appLogger
	LogLimiter             *repeatedLogLimiter
	linuxObservation       linuxObservation
	ipsecDirty             bool
	ipsecPrepareStandby    bool
	ipsecTakeoverNotBefore time.Time
	routingDirty           bool
	routingForceReload     bool
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
	daemonEventCommonMutation        daemonEventType = "common_mutation"
	daemonEventDelegateIssue         daemonEventType = "delegate_issue"
	daemonEventDelegateRevoke        daemonEventType = "delegate_revoke"
	daemonEventDelegateGrant         daemonEventType = "delegate_grant"
	daemonEventRecoveryImportZone    daemonEventType = "recovery_import_zone"
	daemonEventRecoveryPurgeRevoked  daemonEventType = "recovery_purge_revoked"
	daemonEventJoinAccept            daemonEventType = "join_accept"
	daemonEventSyncTimer             daemonEventType = "timer_sync"
	daemonEventEndpointTimer         daemonEventType = "timer_endpoint_publish"
	daemonEventSyncTrigger           daemonEventType = "sync_trigger"
	daemonEventRoutingReload         daemonEventType = "routing_reload"
	daemonEventIPsecCleanup          daemonEventType = "ipsec_cleanup"
	daemonEventIPsecPortRotate       daemonEventType = "ipsec_port_rotate"
	daemonEventIPsecLifecycle        daemonEventType = "ipsec_lifecycle"
	daemonEventEndpointACLApply      daemonEventType = "endpoint_acl_apply"
	daemonEventEndpointACLRemove     daemonEventType = "endpoint_acl_remove"
	daemonEventShutdown              daemonEventType = "shutdown"
)

type daemonEvent struct {
	Type         daemonEventType
	CommonIntent corestate.LocalIntent
	DryRun       bool
	JoinRequest  *gossip.JoinRequest
	JoinBundle   *joinBundle
	PrivateKey   *privateKeyFile
	Permissions  []zone.Permission
	Snapshot     *corestate.ZoneSnapshot
	Zone         zone.ZonePath
	Reason       string
	Key          string
	Apply        bool
	Orphans      bool
	VICIEvent    ipsec.VICIEvent
	ForceSync    bool
	EndpointACL  *photonstate.EndpointACL
	Context      context.Context
	Reply        chan daemonEventResult
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
	Error          error
}

func newDaemon(config *appConfig, state *State, interval time.Duration, clock func() time.Time) *Daemon {
	if interval <= 0 {
		interval = defaultDaemonInterval
	}
	spoolConfig := healthspool.Config{}
	if config != nil {
		spoolConfig = config.Health.Spool
	}
	logger := newAppLogger(config)
	var commonState *corestate.Store
	if state != nil {
		commonState = state.Common
	}
	var verified *corestate.VerifiedState
	if commonState != nil {
		verified = commonState.ReadView().State
	}
	d := &Daemon{
		Config:            config,
		clock:             clock,
		Interval:          interval,
		ControlSocketPath: controlSocketPath(config),
		Events:            make(chan daemonEvent, 64),
		Log:               logger,
		LogLimiter:        newRepeatedLogLimiter(30 * time.Second),
		State:             state,
		health:            &healthDriver{spool: healthspool.New(spoolConfig)},
	}
	d.ipsecDNSResolver = ipsec.NewDNSFamilyHoldDownResolver(net.DefaultResolver, ipsec.DNSFamilyHoldDownOptions{
		Now: d.now,
	})
	d.ipsecTakeoverNotBefore = d.now().Add(2 * time.Minute)
	d.gossipDriver = corehost.NewGossipDriver(corehost.NewClock(d.now), corehost.DefaultEventBuffer, commonState, gossipDriverConfig(config, verified, logger))
	d.objectPullExecutor = corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{
		Client: photonlinux.GossipObjectPullClient{},
		Discovery: func() corehost.GossipDiscoveryInput {
			return d.gossipDriver.GossipDiscoveryInput(d.gossipSuppressions())
		},
		Now: d.now,
	})
	return d
}

func (d *Daemon) now() time.Time {
	if d.clock != nil {
		return d.clock()
	}
	return time.Now()
}

func openDaemon(config *appConfig, interval time.Duration) (*Daemon, error) {
	if config == nil {
		return nil, errors.New("daemon config is nil")
	}
	state, err := openState(config)
	if err != nil {
		return nil, err
	}
	common := state.Common.ReadView()
	if common.State == nil {
		_ = state.Close()
		return nil, errors.New("daemon common state is not initialized")
	}
	return newDaemon(config, state, interval, time.Now), nil
}

func (d *Daemon) Close() error {
	if d == nil {
		return nil
	}
	if d.State != nil {
		return d.State.Close()
	}
	return nil
}

// configureHealthManager initializes the health probe manager from app config.
// When probing is disabled (the default), the optional subsystem has no
// Manager and therefore creates no scheduler, goroutine or platform probe.
func (d *Daemon) configureHealthManager() {
	if d.health != nil {
		d.health.Manager = nil
		d.health.driverManaged = false
	}
	if d.Config == nil {
		return
	}
	cfg := d.Config.Health
	if !cfg.Enabled {
		return
	}
	if d.linuxDriver == nil {
		return
	}
	if d.health == nil {
		d.health = &healthDriver{}
	}
	d.health.Manager = health.NewManager(cfg.Probe, cfg.Hysteresis, d.linuxDriver.HealthProber())
	d.health.driverManaged = d.health.Manager != nil
}

func (d *Daemon) Run(ctx context.Context) error {
	if d == nil || d.State == nil || d.gossipDriver == nil {
		return errors.New("daemon service is not initialized")
	}
	if initial := d.State.Common.ReadView(); initial.State == nil {
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
	d.refreshGossipDiscovery()
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
		"peer_id":  d.gossipDriver.GossipConfig().PeerID,
		"addr":     transport.LocalAddr(),
		"interval": d.Interval,
	}
	if d.Config != nil {
		startFields["config_path"] = configPath()
		startFields["state_path"] = d.Config.StatePath
	}
	maps.Copy(startFields, buildInfoFields())
	d.logInfo("daemon", "started", startFields)
	d.logDebug("daemon", "startup_publish_begin", nil)
	if _, err := d.prepareStartupState(); err != nil {
		d.logWarn("daemon", "startup_publish_failed", map[string]any{"error": err})
	}
	d.logDebug("daemon", "startup_publish_done", nil)
	logAutoJoinPending(d.Log, d.gossipDriver.AdmissionDiagnosis(d.now()))

	startupNow := d.now()
	ipsecReconcileInterval := d.ipsecReconcileInterval()
	routingReconcileInterval := d.routingReconcileInterval()
	firewallReconcileInterval := d.firewallReconcileInterval()
	d.refreshGossipDiscovery()
	// Clear revoked gossip runtime hints before startup recovery. Offline peer
	// suppression is derived directly from the retained gossip checkpoint.
	d.flushRevocationCleanup()
	d.logDebug("daemon", "startup_recovery_begin", nil)
	d.logDebug("daemon", "startup_recovery_layer_begin", map[string]any{"layer": "ipsec"})
	d.recoverIPsecLinksOnStart(ctx)
	d.logDebug("daemon", "startup_recovery_layer_done", map[string]any{"layer": "ipsec"})
	d.logDebug("daemon", "startup_recovery_layer_begin", map[string]any{"layer": "routing"})
	d.recoverRoutingOnStart(ctx)
	d.logDebug("daemon", "startup_recovery_layer_done", map[string]any{"layer": "routing"})
	d.logDebug("daemon", "startup_recovery_layer_begin", map[string]any{"layer": "firewall"})
	d.firewallDirty = true
	d.flushFirewallReconcile(ctx)
	d.logDebug("daemon", "startup_recovery_layer_done", map[string]any{"layer": "firewall"})
	d.logDebug("daemon", "startup_recovery_done", nil)
	if err := d.scheduleDaemonTimer(daemonTimerEndpoint, startupNow); err != nil {
		return err
	}
	if err := d.scheduleDaemonTimer(daemonTimerSync, startupNow); err != nil {
		return err
	}
	if err := d.scheduleDaemonTimer(daemonTimerIPsec, nextReconcileTime(startupNow, ipsecReconcileInterval)); err != nil {
		return err
	}
	if err := d.scheduleDaemonTimer(daemonTimerRouting, nextReconcileTime(startupNow, routingReconcileInterval)); err != nil {
		return err
	}
	if err := d.scheduleDaemonTimer(daemonTimerFirewall, nextReconcileTime(startupNow, firewallReconcileInterval)); err != nil {
		return err
	}
	if d.health != nil && d.health.Manager != nil {
		if err := d.scheduleDaemonTimer(daemonTimerHealth, startupNow); err != nil {
			return err
		}
	}
	var forceSync bool
	var pendingEvent *daemonEvent
	for {
		if ctx.Err() != nil {
			return nil
		}
		now := d.now()
		syncNow, shutdown, ipsecFlushed, routingFlushed, firewallFlushed := d.processEvents(ctx, pendingEvent)
		pendingEvent = nil
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
			if err := d.scheduleDaemonTimer(daemonTimerIPsec, nextReconcileTime(now, ipsecReconcileInterval)); err != nil {
				return err
			}
		}
		if interval := d.ipsecReconcileInterval(); interval != ipsecReconcileInterval {
			ipsecReconcileInterval = interval
			if err := d.scheduleDaemonTimer(daemonTimerIPsec, nextReconcileTime(now, interval)); err != nil {
				return err
			}
		}
		if routingFlushed {
			if err := d.scheduleDaemonTimer(daemonTimerRouting, nextReconcileTime(now, routingReconcileInterval)); err != nil {
				return err
			}
		}
		if interval := d.routingReconcileInterval(); interval != routingReconcileInterval {
			routingReconcileInterval = interval
			if err := d.scheduleDaemonTimer(daemonTimerRouting, nextReconcileTime(now, interval)); err != nil {
				return err
			}
		}
		if firewallFlushed {
			if err := d.scheduleDaemonTimer(daemonTimerFirewall, nextReconcileTime(now, firewallReconcileInterval)); err != nil {
				return err
			}
		}
		if interval := d.firewallReconcileInterval(); interval != firewallReconcileInterval {
			firewallReconcileInterval = interval
			if err := d.scheduleDaemonTimer(daemonTimerFirewall, nextReconcileTime(now, interval)); err != nil {
				return err
			}
		}
		// Reconcile can publish new records (for example routing auto-announcement).
		// Finish the resulting work before waiting for another external event.
		if d.firewallDirty || d.routingDirty || d.ipsecDirty {
			continue
		}
		select {
		case <-ctx.Done():
			return nil
		case event := <-d.Events:
			// Process this event first in the next batch, using the same
			// reconcile and reply rules as events already queued.
			pendingEvent = &event
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
					interval := d.Config.ReflectorInterval
					if interval <= 0 {
						interval = 5 * time.Minute
					}
					if err := d.scheduleDaemonTimer(daemonTimerEndpoint, now.Add(interval)); err != nil {
						return err
					}
				case daemonTimerSync:
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
						if err := d.scheduleDaemonTimer(daemonTimerIPsec, nextReconcileTime(now, ipsecReconcileInterval)); err != nil {
							return err
						}
					}
				case daemonTimerRouting:
					d.routingDirty = true
					if d.flushRoutingReconcile(ctx) {
						if err := d.scheduleDaemonTimer(daemonTimerRouting, nextReconcileTime(now, routingReconcileInterval)); err != nil {
							return err
						}
					}
				case daemonTimerFirewall:
					d.firewallDirty = true
					if d.flushFirewallReconcile(ctx) {
						if err := d.scheduleDaemonTimer(daemonTimerFirewall, nextReconcileTime(now, firewallReconcileInterval)); err != nil {
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

func (d *Daemon) processEvents(ctx context.Context, first *daemonEvent) (syncNow bool, shutdown bool, ipsecFlushed bool, routingFlushed bool, firewallFlushed bool) {
	// Gossip and timer handlers can mark changes before this batch starts.
	d.flushRevocationCleanup()
	defer func() {
		// Phase 6.5 deny-first order: revocation cleanup → firewall → routing
		// → IPsec → revocation cleanup again. This ensures revoked prefixes
		// and peer entries are removed from allow sets before any layer can
		// re-accept traffic from the revoked subtree.
		firewallFlushed = d.flushFirewallReconcile(ctx) || firewallFlushed
		routingFlushed = d.flushRoutingReconcile(ctx) || routingFlushed
		ipsecFlushed = d.flushIPsecReconcile(ctx) || ipsecFlushed
		d.flushRevocationCleanup()
		if routingFlushed {
			d.notifyObserver("route_changed", nil)
			d.notifyObserver("bird_updated", nil)
		}
		if ipsecFlushed {
			d.notifyObserver("link_updated", d.observerLinkIDsPayload())
			d.notifyObserver("health_updated", d.observerHealthLinkIDsPayload())
		}
	}()
	for {
		var event daemonEvent
		if first != nil {
			event = *first
			first = nil
		} else {
			select {
			case event = <-d.Events:
			default:
				return syncNow, shutdown, ipsecFlushed, routingFlushed, firewallFlushed
			}
		}
		result, triggerSync, stop := d.handleEvent(event)
		// Remove revoked peer hints before any early reconcile or next event.
		d.flushRevocationCleanup()
		if event.Type == daemonEventIPsecCleanup && result.Error == nil {
			ipsecFlushed = d.flushIPsecReconcile(ctx) || ipsecFlushed
		}
		routingMutationCommitted := event.Type == daemonEventCommonMutation && !event.DryRun && commonMutationAffectsRouting(event.CommonIntent)
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
	}
}

func (d *Daemon) handleEvent(event daemonEvent) (daemonEventResult, bool, bool) {
	switch event.Type {
	case daemonEventCommonMutation:
		if event.CommonIntent == nil {
			return daemonEventResult{Error: errors.New("common mutation intent is nil")}, false, false
		}
		result, err := d.handleCommonRecordMutationEvent(event.CommonIntent, event.DryRun)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		return daemonEventResult{Version: result.Version}, !result.DryRun, false
	case daemonEventDelegateIssue:
		result, err := d.handleDelegateIssueEvent(event.JoinRequest, event.Permissions)
		if err != nil {
			return daemonEventResult{Error: err}, false, false
		}
		return daemonEventResult{Zone: result.Zone, JoinBundle: result}, true, false
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

func (d *Daemon) handleDelegateIssueEvent(request *gossip.JoinRequest, permissions []zone.Permission) (*joinBundle, error) {
	if err := gossip.ValidateJoinRequest(request); err != nil {
		return nil, err
	}
	now := d.now()
	view := d.State.Common.ReadView()
	intent, err := planDelegationIssue(view.State.Network, request, permissions, now)
	if err != nil {
		return nil, err
	}
	result, err := d.State.Common.ApplyLocalIntent(context.Background(), intent, now)
	if err != nil {
		return nil, err
	}
	if result.Committed {
		d.refreshGossipDiscovery()
		d.notifyStateChanged()
	}
	return joinBundleFromNetwork(d.State.Common.ReadView().State.Network, request.Zone, now)
}

func (d *Daemon) handleDelegateGrantEvent(path zone.ZonePath, permissions []zone.Permission) (*joinBundle, error) {
	intent := corestate.GrantDelegationIntent{Zone: path, Permissions: permissions}
	result, err := d.State.Common.ApplyLocalIntent(context.Background(), intent, d.now())
	if err != nil {
		return nil, err
	}
	if result.Committed {
		d.refreshGossipDiscovery()
		d.notifyStateChanged()
	}
	return joinBundleFromNetwork(d.State.Common.ReadView().State.Network, path, d.now())
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
	result, err := d.State.Common.ImportRecoverySnapshot(context.Background(), corestate.RecoveryImport{
		Snapshot: snapshot,
		Limits:   d.gossipDriver.GossipConfig().Limits,
	}, d.now())
	if err != nil {
		return nil, 0, err
	}
	if result.Committed {
		d.refreshGossipDiscovery()
		d.notifyStateChanged()
	}
	revocations := 0
	if result.Apply != nil {
		if current := d.State.Common.ReadView(); current.State != nil && current.State.Network != nil {
			if zs := current.State.Network.Zones[result.Apply.Zone]; zs != nil {
				revocations = len(zs.Revocations)
			}
		}
	}
	return result.Apply, revocations, nil
}

func (d *Daemon) handleDelegateRevokeEvent(path zone.ZonePath, reason string) error {
	result, err := d.State.Common.ApplyLocalIntent(context.Background(), corestate.RevokeDelegationIntent{
		Parent: path.Parent(), Child: path, Reason: reason,
	}, d.now())
	if err != nil {
		return err
	}
	if result.Committed {
		d.refreshGossipDiscovery()
		d.notifyStateChanged()
	}
	return nil
}

// handleRecoveryPurgeRevokedEvent runs the manual revoked-zone GC. It always
// computes the plan (returned for reporting); when apply is true it also
// executes the deletions, persists, and notifies subsystems so the running node
// reconciles (e.g. tears down orphaned IPsec for removed link instances).
func (d *Daemon) handleRecoveryPurgeRevokedEvent(ctx context.Context, target zone.ZonePath, apply bool) (*purgePlan, error) {
	if d.State == nil {
		return nil, errors.New("daemon service is not initialized")
	}
	now := d.now()
	commonPlan, err := d.State.Common.PlanPurgeRevoked(now, target)
	if err != nil {
		return nil, err
	}
	common := d.State.Common.ReadView()
	if common.State == nil {
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
	result, err := d.State.Common.PurgeRevoked(ctx, now, target)
	if err != nil {
		return nil, err
	}
	for _, peerID := range plan.SyncPeers {
		d.gossipDriver.Observability.Delete(peerID)
	}
	d.refreshGossipDiscovery()
	if result.Committed || len(plan.LinkInstances) > 0 {
		d.notifyStateChanged()
	}
	return plan, nil
}

func (d *Daemon) cleanupPurgePlanIPsecLinks(ctx context.Context, links map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, plan *purgePlan) error {
	if plan == nil || len(plan.LinkInstances) == 0 {
		return nil
	}
	if d.Config == nil {
		return errors.New("daemon service is not initialized")
	}
	platformDriver := d.linuxDriver
	if platformDriver == nil {
		return errors.New("linux driver is not initialized")
	}
	remaining, _, err := platformDriver.CleanupIPsecLinks(ctx, links, plan.LinkInstances)
	if err == nil {
		d.linuxObservation.replaceIPsec(remaining, markIPsecCleanupReconcile(reconcile, d.now()))
	}
	return err
}

func (d *Daemon) handleJoinAcceptEvent(bundle *joinBundle, key *privateKeyFile) (*joinAcceptResult, error) {
	if d.Config == nil || d.State == nil {
		return nil, errors.New("daemon service is not initialized")
	}
	if bundle == nil || bundle.Version != 1 || bundle.Network == nil {
		return nil, errors.New("invalid join bundle")
	}
	if key == nil {
		var err error
		key, err = joinAcceptKeyFromIdentity(d.State.Common.ReadView().State, bundle.Zone)
		if err != nil {
			return nil, err
		}
	}
	if err := validatePrivateKeyFile(key); err != nil {
		return nil, err
	}
	commit, err := d.State.Common.InstallIdentity(context.Background(), corestate.IdentityInstall{
		ManagedZone: bundle.Zone, Network: bundle.Network,
		TrustedRootPublicKey: bundle.RootPublicKey, IdentityPrivateKey: key.PrivateKey,
	}, d.now())
	if err != nil {
		return nil, err
	}
	if commit.Committed {
		d.refreshGossipDiscovery()
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
	commit, authority, err := d.State.Common.RefreshManagedAuthority(context.Background(), d.now())
	if err != nil {
		return false, err
	}
	if authority.Adopted || authority.Refreshed {
		view := d.State.Common.ReadView()
		if view.State != nil {
			d.logInfo("authority", "managed_zone_refreshed", map[string]any{"zone": view.State.ManagedZone})
		}
	}
	published, err := d.publishLocalProtocols()
	return commit.Committed || published, err
}

func (d *Daemon) publishLocalProtocols() (bool, error) {
	if d.State == nil {
		return false, errors.New("daemon service is not initialized")
	}
	common := d.State.Common.ReadView()
	runtime := d.State.ReadLinux()
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
	routingIntent, err := d.routingNetnsProtocolIntent(common.State)
	if err != nil {
		return false, fmt.Errorf("plan routing record: %w", err)
	}
	if routingIntent != nil {
		intents = append(intents, *routingIntent)
	}
	result, err := commitLocalProtocols(context.Background(), d.State, revision, intents, ipsecPlan.TransportKey, d.now())
	if err != nil {
		return false, err
	}
	changed := result.LinuxStateCommitted || result.Common.Committed
	if changed {
		d.refreshGossipDiscovery()
		d.notifyStateChanged()
	}
	return changed, nil
}

func (d *Daemon) handleCommonRecordMutationEvent(intent corestate.LocalIntent, dryRun bool) (*recordMutationResult, error) {
	if d.State == nil {
		return nil, errors.New("daemon service is not initialized")
	}
	var result corestate.LocalIntentResult
	var err error
	if dryRun {
		result, err = d.State.Common.PreviewLocalIntent(intent, d.now())
	} else {
		result, err = d.State.Common.ApplyLocalIntent(context.Background(), intent, d.now())
	}
	if err != nil {
		return nil, err
	}
	out := &recordMutationResult{DryRun: dryRun}
	if result.Record != nil {
		out.Zone, out.Key, out.Version = result.Record.Zone, result.Record.Key, result.Record.Version
	}
	if result.Committed {
		d.refreshGossipDiscovery()
		d.notifyStateChanged()
	}
	return out, nil
}

func commonMutationAffectsRouting(intent corestate.LocalIntent) bool {
	switch intent.(type) {
	case corestate.PutIPAMPoolIntent,
		corestate.RevokeIPAMPoolIntent,
		corestate.PutIPAMAssignmentIntent,
		corestate.RevokeIPAMAssignmentIntent,
		corestate.AnnounceRouteIntent,
		corestate.WithdrawRouteIntent:
		return true
	default:
		return false
	}
}

func (d *Daemon) handleIPsecPortRotateEvent() (*manualPortRotateResult, error) {
	common := d.State.Common.ReadView()
	runtime := d.State.ReadLinux()
	if common.State == nil || runtime == nil {
		return nil, errors.New("daemon state is not initialized")
	}
	revision := uint64(common.Revision)
	record, result, err := planLocalIPsecPortRotation(d.Config, common.State, d.now())
	if err != nil {
		return nil, err
	}
	value, err := json.Marshal(record)
	if err != nil {
		return nil, err
	}
	committed, err := commitLocalProtocols(context.Background(), d.State, revision, []corestate.LocalIntent{
		corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordIPsec, Zone: common.State.ManagedZone, Key: ipsec.RecordKeyPorts, Type: ipsec.RecordTypePorts, Value: value},
	}, nil, d.now())
	if err != nil {
		return nil, err
	}
	if committed.LinuxStateCommitted || committed.Common.Committed {
		d.notifyStateChanged()
	}
	return result, nil
}

// notifyStateChanged publishes the committed change and marks platform work.
// The event loop owns cleanup and reconciliation, including changes made by
// startup publication, Gossip, and routing auto-announcement.
func (d *Daemon) notifyStateChanged() {
	if d.Hooks.OnStateChanged != nil {
		d.Hooks.OnStateChanged()
	}
	d.notifyObserver("state_changed", nil)
	d.notifyObserver("peer_updated", d.observerPeerIDsPayload())
	if d.linuxDriver != nil {
		d.ipsecDirty = true
		d.routingDirty = true
		d.firewallDirty = true
	}
}

func (d *Daemon) noteReconcileFlush(layer string) {
	if d.Hooks.OnReconcileFlush != nil {
		d.Hooks.OnReconcileFlush(layer)
	}
}

// flushRevocationCleanup clears runtime-relevant fields from SyncPeers entries
// whose zone is currently revoked. This implements Phase 6.5.5 gossip peer
// cache cleanup: revoked peers must not maintain discovered endpoints,
// observed paths, backoff or object-pull candidates. The entry itself is
// retained with a "revoked" failure for diagnostics until explicit purge.
func (d *Daemon) flushRevocationCleanup() {
	if d.State == nil {
		return
	}
	// This function is called after every sync-state update. Most calls have no
	// revocations, so check the immutable committed state first and avoid the
	// copy-on-write transaction (which deep-copies the whole state through JSON).
	now := d.now()
	view := d.State.Common.ReadView()
	if view.State == nil {
		return
	}
	revokedZones := collectAllRevokedZones(view.State.Network, now)
	if len(revokedZones) == 0 {
		return
	}
	patches := make(map[string]corestate.PeerCheckpointPatch)
	if view.Gossip != nil {
		for peerID, peer := range view.Gossip.Peers {
			if revokedZones[zone.ZonePath(peerID)] && peerNeedsRevocationCleanup(peer) {
				patches[peerID] = corestate.PeerCheckpointPatch{
					DiscoveredEndpoint: corestate.PatchField[string]{Set: true}, DiscoveredAtUnix: corestate.PatchField[int64]{Set: true},
					ObservedEndpoint: corestate.PatchField[string]{Set: true}, ObservedFirstUnix: corestate.PatchField[int64]{Set: true},
					ObservedLastUnix: corestate.PatchField[int64]{Set: true}, ObservedSyncUnix: corestate.PatchField[int64]{Set: true},
					ObservedUntilUnix: corestate.PatchField[int64]{Set: true}, ObservedFailures: corestate.PatchField[int]{Set: true},
					ObservedGrace:    corestate.PatchField[[]corestate.ObservedGraceEndpoint]{Set: true},
					BackoffUntilUnix: corestate.PatchField[int64]{Set: true}, FailureCount: corestate.PatchField[int]{Set: true},
					LastFailure: corestate.PatchField[*corestate.PeerFailure]{Set: true, Value: &corestate.PeerFailure{
						Code: corestate.PeerFailureLegacy, Message: "zone revoked", AtUnix: now.Unix(),
					}},
				}
			}
		}
	}
	d.noteReconcileFlush("revocation_cleanup")
	if len(patches) > 0 {
		if _, err := d.State.Common.UpdatePeerCheckpoints(context.Background(), patches); err != nil {
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
	d.ipsecPrepareStandby = true
	defer func() { d.ipsecPrepareStandby = false }()
	d.ipsecDirty = true
	d.flushIPsecReconcile(ctx)
}

func (d *Daemon) recoverRoutingOnStart(ctx context.Context) {
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
	if !d.routingDirty {
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
	if d.Config == nil {
		return 0
	}
	instances := d.Config.Routing.EnabledInstances()
	if len(instances) == 0 {
		return 0
	}
	return defaultRoutingReconcileInterval
}

func nextReconcileTime(now time.Time, interval time.Duration) time.Time {
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
	if !d.ipsecDirty {
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
	if d.linuxDriver == nil {
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
	if d.Config == nil {
		return 0
	}
	groups := d.Config.IPsec.LinkGroups
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

func daemonRun(ctx context.Context, interval time.Duration) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	service, err := openDaemon(config, interval)
	if err != nil {
		return err
	}
	defer service.Close()
	return service.Run(ctx)
}

func (d *Daemon) configureLinuxDriverFromConfig() error {
	if d.Config == nil {
		return nil
	}
	driver, err := photonlinux.NewDaemonDriver(d.Config.IPsec, d.Config.Netns.Names, d.Log)
	if err != nil {
		return err
	}
	return d.installLinuxDriver(driver)
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
	if d.Log != nil {
		d.Log.Debug(component, event, fields)
	}
}

func (d *Daemon) logInfo(component, event string, fields map[string]any) {
	if d.Log != nil {
		d.Log.Info(component, event, fields)
	}
}

func (d *Daemon) logWarn(component, event string, fields map[string]any) {
	if d.Log != nil {
		d.Log.Warn(component, event, fields)
	}
}

func (d *Daemon) logError(component, event string, fields map[string]any) {
	if d.Log != nil {
		d.Log.Error(component, event, fields)
	}
}

func (d *Daemon) scheduleDaemonTimer(key string, deadline time.Time) error {
	if d.daemonTimers == nil {
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
