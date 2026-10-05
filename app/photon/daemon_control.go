package main

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"sort"
	"syscall"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	pingdebug "github.com/HiggsNet/photon/internal/ping"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

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

func (d *Daemon) birdRoutesForControl(ctx context.Context, dump *inspect.RoutesResponse, instances []photonlinux.RoutingInstance, birdStates map[string]*bird.InstanceObservation) []inspect.BirdRoutesView {
	if dump == nil {
		return nil
	}
	views := make([]inspect.BirdRoutesView, 0, len(instances))
	for _, inst := range instances {
		if !inst.Enabled || inst.Bird.Mode == ipsec.RoutingModeDisabled {
			continue
		}
		state := birdStates[inst.Bird.NetNSName]
		view := inspect.BirdRoutesView{
			NetNS:      inst.Bird.NetNSName,
			InstanceID: inst.ID,
		}
		socketPath := inst.Bird.ControlSocketPath
		if state != nil {
			view.State = state.State
			view.Failure = inspect.BuildFailure(inspect.FailureCodeBirdInstance, state.LastFailure)
			if state.ControlSocket != "" {
				socketPath = state.ControlSocket
			}
		}
		if socketPath == "" {
			if view.Failure == nil {
				view.Failure = inspect.BuildFailure(inspect.FailureCodeBirdQuery, errors.New("control socket not configured"))
			}
			views = append(views, view)
			continue
		}
		observed, err := d.linuxDriver.ObserveBird(ctx, socketPath, bird.InternalRouteTableNames(inst.Bird.NetNSName)...)
		if err != nil {
			view.Failure = inspect.BuildFailure(inspect.FailureCodeBirdQuery, err)
			views = append(views, view)
			continue
		}
		if observed != nil {
			view.Routes = inspect.BuildBirdRouteViews(dump, observed.Routes)
		}
		views = append(views, view)
	}
	sort.Slice(views, func(i, j int) bool {
		if views[i].NetNS != views[j].NetNS {
			return views[i].NetNS < views[j].NetNS
		}
		return views[i].InstanceID < views[j].InstanceID
	})
	return views
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
		common := d.State.Common.ReadView()
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
		common := d.State.Common.ReadView()
		links, reconcile := d.linuxObservation.ipsecSnapshot()
		routingObserved := d.linuxObservation.routingSnapshot()
		var birdInstances map[string]*bird.InstanceObservation
		if routingObserved != nil {
			birdInstances = routingObserved.Instances
		}
		writeCanonicalView(conn, statusViewFromOwners(d.Config, common, links, reconcile, birdInstances, d.healthSamples(), true, d.now()))
	case "record_put":
		if err := validateControlRecordPut(request); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{
			Type: daemonEventCommonMutation,
			CommonIntent: corestate.PutRecordIntent{
				Zone: zone.ZonePath(request.Zone), Key: request.Key, Type: request.Type,
				Value: append([]byte(nil), parseControlRecordValue(request)...),
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
		intent, err := commonIPAMIntent(*request.IPAM)
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventCommonMutation, CommonIntent: intent, DryRun: request.IPAM.DryRun})
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
		result := d.enqueueEvent(ctx, daemonEvent{
			Type: daemonEventCommonMutation, CommonIntent: commonRouteIntent(*request.Route), DryRun: request.Route.DryRun,
		})
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
		intent, err := commonServiceIntent(*request.Service)
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		result := d.enqueueEvent(ctx, daemonEvent{Type: daemonEventCommonMutation, CommonIntent: intent, DryRun: request.Service.DryRun})
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
		view := d.State.Common.ReadView()
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
		view := d.State.Common.ReadView()
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
		view := d.State.Common.ReadView()
		if view.State == nil || view.State.Network == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		writeCanonicalView(conn, buildZoneDetails(view.State.Network, d.now()))
	case "services_view":
		view := d.State.Common.ReadView()
		if view.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		services := inspect.BuildServiceInspection(view.State, d.now())
		writeCanonicalView(conn, services)
	case "route_view":
		view := d.State.Common.ReadView()
		if view.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		report := inspect.BuildRouteShowReport(view.State, d.now(), zone.ZonePath(request.Zone), request.IncludeAll)
		writeCanonicalView(conn, *report)
	case "ipam_assignments_view":
		view := d.State.Common.ReadView()
		rows, err := buildIPAMAssignmentRows(view.State, d.now(), zone.ZonePath(request.Zone))
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, rows)
	case "ipam_mine_view":
		view := d.State.Common.ReadView()
		report, err := buildIPAMMineReportFromState(view.State, d.now())
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, *report)
	case "ipam_get_view":
		view := d.State.Common.ReadView()
		report, err := buildIPAMGetReportFromState(view.State, d.now(), request.ValueText)
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, *report)
	case "endpoints_view":
		view := d.State.Common.ReadView()
		if view.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		endpoints := inspect.BuildEndpointDebug(view.State, d.now())
		writeCanonicalView(conn, endpoints)
	case "ping_view":
		// One request per connection: EOF means the caller is no longer
		// waiting. Only this diagnostic follows disconnect cancellation;
		// submitted mutations retain the daemon context.
		pingCtx, cancelPing := context.WithTimeout(ctx, controlPingMaxDuration)
		defer cancelPing()
		go func() {
			_, _ = io.Copy(io.Discard, conn)
			cancelPing()
		}()
		common := d.State.Common.ReadView()
		if common.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		links, reconcile := d.linuxObservation.ipsecSnapshot()
		targets := healthTargets(buildLinkOutputs(links, reconcile), string(common.State.ManagedZone))
		opts := pingdebug.Options{}
		if request.Ping != nil {
			opts = *request.Ping
		}
		if d.Config != nil {
			opts.FallbackCount = d.Config.Health.Probe.Burst
			opts.FallbackTimeout = d.Config.Health.Probe.Timeout
		}
		resolved := pingdebug.ResolveOptions(opts)
		selected := pingdebug.SelectTargetsResolved(targets, request.Zone, resolved)
		var prober health.Prober
		if d.linuxDriver != nil {
			prober = d.linuxDriver.HealthProber()
		}
		outcomes := pingdebug.Run(pingCtx, prober, selected, resolved.ProbeConfig())
		if err := pingCtx.Err(); err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		view := pingdebug.BuildDebugView(request.Zone, outcomes, pingdebug.DistinctPeerZones(targets), resolved.Count, resolved.Timeout)
		writeCanonicalView(conn, view)
	case "sync_view":
		common := d.State.Common.ReadView()
		if common.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		view := inspect.BuildSyncStatus(common, syncStatusOptions(d.Config.ListenAddr, d.gossipDriver.GossipConfig(), d.now(), request.Verbose))
		writeCanonicalView(conn, view)
	case "peer_debug":
		common := d.State.Common.ReadView()
		if common.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state is not initialized")))
			return
		}
		options := gossipPeersOptions(d.gossipDriver.GossipConfig(), d.peerObservabilitySnapshots(), d.now())
		options.Lifecycle = d.Config.PeerLifecycle
		view, ok := inspect.BuildGossipPeerDebugView(common, options, request.Zone)
		if !ok {
			writeControlResponse(conn, controlError(fmt.Errorf("%w: %s", zone.ErrZoneNotFound, request.Zone)))
			return
		}
		writeCanonicalView(conn, view)
	case "zone_debug":
		common := d.State.Common.ReadView()
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
		view := d.State.Common.ReadView()
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
		runtime := d.State.ReadLinux()
		acls := make([]photonstate.EndpointACL, 0, len(runtime.EndpointACLs))
		for _, acl := range runtime.EndpointACLs {
			acls = append(acls, acl)
		}
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
		routingReconcile := d.linuxObservation.routingSnapshot()
		var lastRoutingFailure error
		var birdInstances map[string]*bird.InstanceObservation
		if routingReconcile != nil {
			lastRoutingFailure = routingReconcile.LastFailure
			birdInstances = routingReconcile.Instances
		}
		view := buildBabelDebugView(d.Config, birdInstances, lastRoutingFailure)
		writeCanonicalView(conn, view)
	case "bird_dump":
		dump, err := d.birdDumpForControl(ctx, request.NetNS, bird.DebugView(request.BirdView))
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, *dump)
	case "kernel_routes_view":
		queryCtx, cancel := context.WithTimeout(ctx, controlConnDeadline)
		view, err := d.kernelRoutesView(queryCtx, request.NetNS, request.Family)
		cancel()
		if err != nil {
			writeControlResponse(conn, controlError(err))
			return
		}
		writeCanonicalView(conn, view)
	case "routes_view":
		var routingInstances []photonlinux.RoutingInstance
		if d.Config != nil {
			routingInstances = append([]photonlinux.RoutingInstance(nil), d.Config.Routing.Instances...)
		}
		view := d.State.Common.ReadView()
		var birdInstances map[string]*bird.InstanceObservation
		if routingObserved := d.linuxObservation.routingSnapshot(); routingObserved != nil {
			birdInstances = routingObserved.Instances
		}
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
		view := d.State.Common.ReadView()
		if view.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		diagnosis := d.gossipDriver.AdmissionDiagnosis(d.now())
		writeCanonicalView(conn, diagnosis)
	case "firewall_view":
		fwSnapshot := d.linuxObservation.firewallSnapshot()
		instances := []firewall.FirewallInstanceSpec(nil)
		var appCfg *appConfig
		if d.Config != nil {
			appCfg = d.Config
			instances = appCfg.Firewall.Instances
		}
		instances = filterFirewallDebugInstances(instances, request.NetNS, request.Host)
		writeCanonicalView(conn, buildFirewallDebugView(appCfg, instances, fwSnapshot))
	case "links_view":
		health := d.healthSamples()
		links, reconcile := d.linuxObservation.ipsecSnapshot()
		var birdInstances map[string]*bird.InstanceObservation
		if routingObserved := d.linuxObservation.routingSnapshot(); routingObserved != nil {
			birdInstances = routingObserved.Instances
		}
		view := buildStoredLinkInspection(d.Config, links, reconcile, birdInstances, health)
		if request.LiveSAs && d.linuxDriver != nil && d.Config != nil && d.Config.IPsec.Driver != photonlinux.IPsecDriverDryRun {
			sas, err := d.linuxDriver.ListIPsecSAs(ctx)
			if err != nil {
				view.LiveSAError = err.Error()
			} else {
				view.LiveSAs = photonlinux.ProjectIPsecSAs(sas)
			}
		}
		writeCanonicalView(conn, view)
	case "peer_lifecycle_view":
		common := d.State.Common.ReadView()
		if common.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		links, reconcile := d.linuxObservation.ipsecSnapshot()
		writeCanonicalView(conn, buildPeerLifecycleDebugView(d.Config, common, links, reconcile, d.now()))
	case "gossip_peers_view":
		writeCanonicalView(conn, d.gossipPeerSnapshotForControl())
	case "revocation_view":
		observedLinks, _ := d.linuxObservation.ipsecSnapshot()
		linkStates := observedLinks
		view := d.State.Common.ReadView()
		if view.State == nil {
			writeControlResponse(conn, controlError(errors.New("daemon state not loaded")))
			return
		}
		var impacts []inspect.RevocationImpact
		if request.Zone != "" {
			impacts = []inspect.RevocationImpact{ComputeRevocationImpact(view.State.Network, linkStates, view.Gossip, zone.ZonePath(request.Zone), d.now())}
		} else {
			impacts = AllRevocationImpact(view.State.Network, linkStates, view.Gossip, d.Config, d.now())
		}
		writeCanonicalView(conn, impacts)
	case "health_status":
		common := d.State.Common.ReadView()
		links, reconcile := d.linuxObservation.ipsecSnapshot()
		writeCanonicalView(conn, healthViewFromOwners(common, links, reconcile, d.healthSamples()))
	default:
		writeControlResponse(conn, controlError(fmt.Errorf("unknown control method: %s", request.Method)))
	}
}
