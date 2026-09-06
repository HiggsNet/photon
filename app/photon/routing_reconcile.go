package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/internal/photonlinux/linkstate"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

const (
	defaultRoutingReconcileInterval = 30 * time.Second
	birdHealthObservationTimeout    = 2 * time.Second
	birdInstanceStatePending        = "pending"
	birdInstanceStateRunning        = "running"
	birdInstanceStateDegraded       = "degraded"
	birdInstanceStateError          = "error"
	maxRoutingCrashBackoff          = time.Minute
)

func (d *Daemon) reconcileRouting(ctx context.Context) error {
	if d == nil || d.App == nil || d.App.Config == nil {
		return nil
	}
	common, runtime := d.StateStore.readCommonAndRuntime()
	if common.State == nil || runtime == nil {
		return nil
	}
	rev := uint64(common.Revision)
	verified := common.State
	baseBird := photonstate.CloneBirdInstances(runtime.BirdInstances)
	baseReconcile := photonstate.CloneRoutingReconcileState(runtime.RoutingReconcile)
	config := d.App.Config
	routingInstances := config.Routing.Instances
	if len(routingInstances) == 0 {
		return nil
	}
	if verified.ManagedZone.IsRoot() || !verified.ManagedZone.Valid() {
		return nil
	}
	forceReload := d.routingForceReload
	d.routingForceReload = false

	now := d.now()
	d.routingLastRunUnix.Store(now.Unix())
	if runtime.RoutingReconcile == nil {
		runtime.RoutingReconcile = &routingReconcileState{}
	}
	runtime.RoutingReconcile.LastRunUnix = now.Unix()

	ars, err := routing.BuildAuthorizedRouteSet(verified.Network, now)
	if err != nil {
		runtime.RoutingReconcile.LastError = err.Error()
		_ = d.commitRoutingReconcileResult(rev, baseBird, baseReconcile, runtime.BirdInstances, runtime.RoutingReconcile)
		return fmt.Errorf("build authorized route set: %w", err)
	}

	dataDir := config.DataDir
	if dataDir == "" {
		dataDir = "."
	}
	if abs, err := filepath.Abs(dataDir); err == nil {
		dataDir = abs
	}

	var firstErr error
	autoAnnounceChanged, autoAnnounceErr := d.autoAnnounceAssignedIPsResult(ars)
	if autoAnnounceErr != nil {
		firstErr = autoAnnounceErr
	}

	// Auto-announce changes verified Network through its own common-state
	// transaction. Refresh both detached owners only in that uncommon case.
	if autoAnnounceChanged {
		common, runtime = d.StateStore.readCommonAndRuntime()
		if common.State == nil || runtime == nil {
			return firstErr
		}
		rev = uint64(common.Revision)
		verified = common.State
		baseBird = photonstate.CloneBirdInstances(runtime.BirdInstances)
		baseReconcile = photonstate.CloneRoutingReconcileState(runtime.RoutingReconcile)
		if runtime.RoutingReconcile == nil {
			runtime.RoutingReconcile = &routingReconcileState{}
		}
		runtime.RoutingReconcile.LastRunUnix = now.Unix()
		ars, err = routing.BuildAuthorizedRouteSet(verified.Network, now)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("rebuild authorized route set after auto-announce: %w", err)
		}
	}

	if runtime.BirdInstances == nil {
		runtime.BirdInstances = make(map[string]*BirdInstanceState)
	}

	// Build per-netns overlay groups for interface pattern merging.
	overlayByNetns := groupOverlaysByNetns(config.IPsec.LinkGroups, config.Overlay.DefaultNetNS)

	for _, inst := range routingInstances {
		if err := d.reconcileRoutingForInstance(ctx, verified, runtime, inst, ars, dataDir, overlayByNetns, config, now, forceReload); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {
		runtime.RoutingReconcile.LastError = firstErr.Error()
	} else {
		runtime.RoutingReconcile.LastError = ""
	}

	if err := d.commitRoutingReconcileResult(rev, baseBird, baseReconcile, runtime.BirdInstances, runtime.RoutingReconcile); err != nil {
		return fmt.Errorf("save routing reconcile state: %w", err)
	}
	return firstErr
}

// netnsOverlayGroup holds the overlays sharing a single netns/BIRD instance.
type netnsOverlayGroup struct {
	NetNSName string
	Overlays  []string
	Spec      ipsec.NetNSSpec
}

func groupOverlaysByNetns(groups []ipsec.LinkGroupSpec, defaultNetNS ipsec.NetNSSpec) map[string]*netnsOverlayGroup {
	out := make(map[string]*netnsOverlayGroup)
	for _, group := range groups {
		netnsName := resolveOverlayNetNSName(group, defaultNetNS)
		ng, ok := out[netnsName]
		if !ok {
			ng = &netnsOverlayGroup{NetNSName: netnsName}
			netns := group.NetNS.Normalized()
			if netns.Kind == "" || (netns.Kind == ipsec.NetNSName && netns.Name == "") {
				netns = defaultNetNS.Normalized()
			}
			ng.Spec = netns
			out[netnsName] = ng
		}
		ng.Overlays = append(ng.Overlays, group.ID)
	}
	return out
}

func (d *Daemon) commitRoutingReconcileResult(rev uint64, baseBird map[string]*BirdInstanceState, baseReconcile *routingReconcileState, nextBird map[string]*BirdInstanceState, nextReconcile *routingReconcileState) error {
	if d == nil || d.StateStore == nil {
		return nil
	}
	if routingReconcileResultEqual(baseBird, baseReconcile, nextBird, nextReconcile) {
		return nil
	}
	currentRev, committed, err := d.StateStore.commitRoutingIfRevision(rev, nextBird, nextReconcile)
	if err != nil {
		return err
	}
	if !committed {
		d.routingDirty = true
		d.publishStateStoreRuntimeFlags()
		d.logWarn("routing", "stale_reconcile_result", map[string]any{
			"source_revision":  rev,
			"current_revision": currentRev,
			"changed_netns":    changedBirdInstanceNetNS(baseBird, nextBird),
		})
		return nil
	}
	return nil
}

func routingReconcileResultEqual(baseBird map[string]*BirdInstanceState, baseReconcile *routingReconcileState, nextBird map[string]*BirdInstanceState, nextReconcile *routingReconcileState) bool {
	if len(changedBirdInstanceNetNS(baseBird, nextBird)) != 0 {
		return false
	}
	if baseReconcile == nil || nextReconcile == nil {
		return baseReconcile == nil && nextReconcile == nil
	}
	// LastRunUnix is runtime observability, not durable configuration. A
	// timestamp-only reconcile must not advance the state revision or fsync.
	return baseReconcile.LastError == nextReconcile.LastError
}

func changedBirdInstanceNetNS(base, next map[string]*BirdInstanceState) []string {
	seen := make(map[string]bool, len(base)+len(next))
	var out []string
	for netns, baseInst := range base {
		seen[netns] = true
		nextInst := next[netns]
		if !birdInstanceStatesEqual(baseInst, nextInst) {
			out = append(out, netns)
		}
	}
	for netns := range next {
		if !seen[netns] {
			out = append(out, netns)
		}
	}
	return out
}

func birdInstanceStatesEqual(a, b *BirdInstanceState) bool {
	if a == nil || b == nil {
		return a == b
	}
	if len(a.Overlays) != len(b.Overlays) {
		return false
	}
	if a.NetNSName != b.NetNSName ||
		a.ConfigPath != b.ConfigPath ||
		a.ControlSocket != b.ControlSocket ||
		a.PIDFile != b.PIDFile ||
		a.RouterID != b.RouterID ||
		a.Owner != b.Owner ||
		a.LastConfigHash != b.LastConfigHash ||
		a.LastError != b.LastError ||
		a.LastExit != b.LastExit ||
		a.FailureCount != b.FailureCount ||
		a.BackoffUntilUnix != b.BackoffUntilUnix ||
		a.State != b.State {
		return false
	}
	for i := range a.Overlays {
		if a.Overlays[i] != b.Overlays[i] {
			return false
		}
	}
	return true
}

func (d *Daemon) reconcileRoutingForInstance(ctx context.Context, verified *corestate.VerifiedState, runtime *linuxRuntimeState, inst RoutingInstance, ars *routing.AuthorizedRouteSet, dataDir string, overlayByNetns map[string]*netnsOverlayGroup, config *appConfig, now time.Time, forceReload bool) error {
	netnsName := inst.NetNS
	instState := runtime.BirdInstances[netnsName]
	if instState == nil {
		instState = &BirdInstanceState{NetNSName: netnsName}
		runtime.BirdInstances[netnsName] = instState
	}

	// Record which overlays share this instance.
	overlays := []string{}
	if ng, ok := overlayByNetns[netnsName]; ok {
		overlays = ng.Overlays
	}
	instState.Overlays = overlays

	routerIDLabel := netnsRouterIDLabel(netnsName, config.Netns, inst)
	routerID := bird.StableRouterID(verified.ManagedZone, rootTrustHash(verified.Network), routerIDLabel)
	instState.RouterID = routerID

	spec := buildBirdInstanceSpecForNetns(inst, routerID, dataDir, overlayByNetns[netnsName], config.Netns, ars, verified.ManagedZone)
	spec.InterfacePolicies = birdRotateInterfacePolicies(runtime.LinkInstances, runtime.IPsecReconcile, netnsName, overlays, inst)
	instState.ConfigPath = spec.ConfigPath
	instState.ControlSocket = spec.ControlSocketPath
	instState.PIDFile = spec.PIDFilePath
	instState.Owner = birdOwnerForInstance(inst, netnsName)
	spec.Owner = instState.Owner

	// Ensure veth pair for upstream if configured and create_veth is true.
	if inst.Upstream != nil && inst.Upstream.Enabled && inst.Upstream.CreateVeth {
		vspec := bird.VethSpec{
			MeshInterface: inst.Upstream.MeshInterface,
			PeerInterface: inst.Upstream.ExternalInterface,
			MeshNetns:     netnsName,
			PeerNetns:     inst.Upstream.ExternalNetns,
			MeshIPv4LL:    inst.Upstream.MeshIPv4LL,
			MeshIPv6LL:    inst.Upstream.MeshIPv6LL,
			PeerIPv4LL:    inst.Upstream.ExternalIPv4LL,
			PeerIPv6LL:    inst.Upstream.ExternalIPv6LL,
		}
		if err := d.linuxDriver.EnsureRoutingVeth(ctx, vspec); err != nil {
			instState.State = birdInstanceStateError
			instState.LastError = fmt.Sprintf("ensure veth: %s", err)
			return fmt.Errorf("ensure upstream veth for netns %q: %w", netnsName, err)
		}
	}
	if inst.Upstream != nil && inst.Upstream.Enabled &&
		(inst.Upstream.Mode == upstreamModeStatic || inst.Upstream.InstallSourceAddresses) {
		var routePrefixes []netip.Prefix
		if inst.Upstream.Mode == upstreamModeStatic {
			routePrefixes = externalUpstreamRoutePrefixes(ars, verified.ManagedZone)
		}
		var sourcePrefixes []netip.Prefix
		if inst.Upstream.InstallSourceAddresses {
			sourcePrefixes = externalUpstreamSourcePrefixes(ars, verified.ManagedZone)
		}
		rspec := photonlinux.UpstreamRouteSpec{
			NetNS:          inst.Upstream.ExternalNetns,
			Interface:      inst.Upstream.ExternalInterface,
			Prefixes:       routePrefixes,
			SourcePrefixes: sourcePrefixes,
			MeshIPv4LL:     inst.Upstream.MeshIPv4LL,
			MeshIPv6LL:     inst.Upstream.MeshIPv6LL,
		}
		if err := d.linuxDriver.EnsureUpstreamRoutes(ctx, rspec); err != nil {
			instState.State = birdInstanceStateError
			instState.LastError = fmt.Sprintf("ensure upstream routes: %s", err)
			return fmt.Errorf("ensure upstream routes for netns %q: %w", netnsName, err)
		}
	}

	importSet := authorizedPrefixes(ars, nil)
	// Phase 6.3.4: BIRD export set must use the same forwarding policy as the
	// firewall. A non-transit node only exports its own local assigned prefixes;
	// a transit node exports authorized prefixes filtered by the forwarding
	// policy allow/deny lists. Both BIRD and firewall consume the same policy
	// so they never disagree on which transit paths are allowed.
	exportSet := buildRoutingExportSet(ars, verified.ManagedZone, config, netnsName)

	configBytes, err := bird.DefaultConfigGenerator{}.Generate(spec, importSet, exportSet)
	if err != nil {
		instState.State = birdInstanceStateError
		instState.LastError = err.Error()
		return fmt.Errorf("generate bird config for netns %q: %w", netnsName, err)
	}

	configHash := fmt.Sprintf("%x", sha256.Sum256(configBytes))
	configChanged := forceReload || instState.LastConfigHash == "" || instState.LastConfigHash != configHash

	mode := bird.BirdMode(inst.Mode)
	if mode == "" {
		mode = bird.BirdModeManaged
	}
	if mode == bird.BirdModeDisabled {
		instState.State = birdInstanceStatePending
		instState.LastError = ""
		return nil
	}

	switch mode {
	case bird.BirdModeManaged:
		if configChanged {
			if err := d.linuxDriver.WriteBirdConfig(spec.ConfigPath, configBytes); err != nil {
				instState.State = birdInstanceStateError
				instState.LastError = err.Error()
				return fmt.Errorf("write bird config for netns %q: %w", netnsName, err)
			}
		}

		running, exit := d.linuxDriver.BirdProcessStatus(ctx, netnsName)
		if exit != nil {
			instState.LastExit = formatBirdProcessExit(exit)
			instState.FailureCount++
			instState.BackoffUntilUnix = now.Add(routingCrashBackoff(instState.FailureCount)).Unix()
			instState.State = birdInstanceStateDegraded
			instState.LastError = fmt.Sprintf("bird process exited: %s", instState.LastExit)
			running = false
		}
		if !running && instState.BackoffUntilUnix > now.Unix() {
			instState.State = birdInstanceStateDegraded
			instState.LastError = fmt.Sprintf("bird restart backoff active until %s", time.Unix(instState.BackoffUntilUnix, 0).Format(time.RFC3339))
			return nil
		}
		if !running {
			if err := d.linuxDriver.StartBird(ctx, spec); err != nil {
				instState.State = birdInstanceStateError
				instState.LastError = err.Error()
				if !isDryRunMissingBirdError(err) {
					return fmt.Errorf("start bird for netns %q: %w", netnsName, err)
				}
			} else {
				instState.State = birdInstanceStateRunning
				instState.FailureCount = 0
				instState.BackoffUntilUnix = 0
				instState.LastExit = ""
			}
		} else if configChanged {
			if err := d.linuxDriver.ConfigureBird(ctx, spec.ControlSocketPath, spec.ConfigPath); err != nil {
				instState.State = birdInstanceStateDegraded
				instState.LastError = err.Error()
				if !isDryRunConnectError(err) {
					return fmt.Errorf("configure bird for netns %q: %w", netnsName, err)
				}
			} else {
				instState.State = birdInstanceStateRunning
			}
		} else {
			// The process can become healthy again without a config change (for
			// example after a daemon restart adopts an already-running BIRD).
			// Do not retain an expired crash-backoff state in that case.
			instState.State = birdInstanceStateRunning
			instState.FailureCount = 0
			instState.BackoffUntilUnix = 0
			instState.LastExit = ""
		}
		d.observeBirdForHealth(ctx, runtime.LinkInstances, runtime.IPsecReconcile, netnsName, instState.Overlays, spec.ControlSocketPath)

	case bird.BirdModeExternal:
		observed, err := d.linuxDriver.ObserveBird(ctx, spec.ControlSocketPath, bird.InternalRouteTableNames(netnsName)...)
		if err != nil {
			instState.State = birdInstanceStateError
			instState.LastError = err.Error()
			d.recordBirdHealthObservationUnavailableForLinks(runtime.LinkInstances, runtime.IPsecReconcile, netnsName, instState.Overlays)
			if !isDryRunConnectError(err) {
				return fmt.Errorf("bird status for netns %q: %w", netnsName, err)
			}
		} else {
			instState.State = birdInstanceStateRunning
			d.recordBirdHealthObservationForLinks(runtime.LinkInstances, runtime.IPsecReconcile, netnsName, instState.Overlays, observed)
		}
	}

	instState.LastConfigHash = configHash
	if instState.State == "" {
		instState.State = birdInstanceStatePending
	}
	if instState.State == birdInstanceStateRunning {
		instState.LastError = ""
	}
	return nil
}

func (d *Daemon) observeBirdForHealth(ctx context.Context, instances map[string]linkInstanceState, reconcile *ipsecReconcileState, netnsName string, overlays []string, socketPath string) {
	if d == nil || d.health == nil || d.health.Manager == nil || socketPath == "" {
		return
	}
	observeCtx, cancel := context.WithTimeout(ctx, birdHealthObservationTimeout)
	defer cancel()
	observed, err := d.linuxDriver.ObserveBird(observeCtx, socketPath, bird.InternalRouteTableNames(netnsName)...)
	if err != nil {
		d.recordBirdHealthObservationUnavailableForLinks(instances, reconcile, netnsName, overlays)
		return
	}
	d.recordBirdHealthObservationForLinks(instances, reconcile, netnsName, overlays, observed)
}

func (d *Daemon) recordBirdHealthObservationUnavailableForLinks(instances map[string]linkInstanceState, reconcile *ipsecReconcileState, netnsName string, overlays []string) {
	d.recordBirdHealthObservationForLinks(instances, reconcile, netnsName, overlays, &bird.BirdObservedState{})
}

func (d *Daemon) recordBirdHealthObservationForLinks(instances map[string]linkInstanceState, reconcile *ipsecReconcileState, netnsName string, overlays []string, observed *bird.BirdObservedState) {
	if d == nil || d.health == nil || d.health.Manager == nil || observed == nil {
		return
	}
	for _, link := range buildLinkOutputs(instances, reconcile) {
		if link.RuntimeRole != "staged" || link.InterfaceName == "" || !linkOutputBelongsToBirdInstance(link, netnsName, overlays) {
			continue
		}
		instanceID := strings.TrimSuffix(link.ID, "#staged")
		obs := birdObservationForInterface(instanceID, linkstate.ProbeID(instanceID, "staged"), link.InterfaceName, observed)
		d.health.SetBabelObservation(obs)
	}
}

func linkOutputBelongsToBirdInstance(link photonstate.LinkOutput, netnsName string, overlays []string) bool {
	if link.NetNS != "" && link.NetNS != netnsName {
		return false
	}
	if len(overlays) == 0 {
		return true
	}
	return slices.Contains(overlays, link.GroupID)
}

func birdObservationForInterface(instanceID, probeID, iface string, observed *bird.BirdObservedState) health.BabelObservation {
	obs := health.BabelObservation{InstanceID: instanceID, ProbeID: probeID}
	if iface == "" || observed == nil {
		return obs
	}
	for _, n := range observed.Neighbors {
		if n.Interface != iface {
			continue
		}
		obs.Neighbor = true
		if n.Routes > 0 {
			obs.Route = true
		}
		if n.Metric > 0 && (obs.Metric == 0 || int(n.Metric) < obs.Metric) {
			obs.Metric = int(n.Metric)
		}
	}
	for _, r := range observed.Routes {
		if r.Iface == iface && birdRouteIsBabel(r) {
			obs.Route = true
			if r.Metric > 0 && (obs.Metric == 0 || int(r.Metric) < obs.Metric) {
				obs.Metric = int(r.Metric)
			}
		}
	}
	return obs
}

func birdRouteIsBabel(route bird.BirdRoute) bool {
	return strings.Contains(strings.ToLower(route.Protocol), "babel") ||
		strings.Contains(strings.ToLower(route.Source), "babel")
}

func (d *Daemon) stopManagedBirdInstances(ctx context.Context, force bool) error {
	if d == nil || d.App == nil || d.App.Config == nil {
		return nil
	}
	if ctx == nil {
		ctx = context.Background()
	}

	var firstErr error
	for _, inst := range d.App.Config.Routing.Instances {
		if !inst.Enabled || inst.Mode == ipsec.RoutingModeDisabled || inst.Mode == ipsec.RoutingModeExternal {
			continue
		}
		if !force && normalizedRoutingShutdownPolicy(inst.ShutdownPolicy) != routingShutdownPolicyStop {
			continue
		}
		mode := bird.BirdMode(inst.Mode)
		if mode == "" {
			mode = bird.BirdModeManaged
		}
		spec := bird.BirdInstanceSpec{
			NetNSName:         inst.NetNS,
			ControlSocketPath: inst.ControlSocket,
			PIDFilePath:       inst.PIDFile,
			ConfigPath:        inst.ConfigFile,
			Mode:              mode,
			Owner:             birdOwnerForInstance(inst, inst.NetNS),
		}
		if err := d.linuxDriver.StopBird(ctx, spec); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("stop bird for netns %q: %w", inst.NetNS, err)
		}
	}
	return firstErr
}

func (d *Daemon) birdDumpForControl(ctx context.Context, netnsName string, view birdDebugView) (*inspect.BirdDumpResponse, error) {
	response := &inspect.BirdDumpResponse{Instances: map[string]inspect.BirdDumpInstance{}}
	if d == nil || d.App == nil || d.App.Config == nil {
		return response, nil
	}
	commands, err := birdDebugCommands(view)
	if err != nil {
		return nil, err
	}
	var runtime *linuxRuntimeState
	if d.StateStore != nil {
		_, runtime = d.StateStore.readCommonAndRuntime()
	}
	for _, inst := range d.App.Config.Routing.Instances {
		if !inst.Enabled || inst.Mode == ipsec.RoutingModeDisabled {
			continue
		}
		if netnsName != "" && inst.NetNS != netnsName && inst.ID != netnsName {
			continue
		}
		item := inspect.BirdDumpInstance{
			NetNS:         inst.NetNS,
			InstanceID:    inst.ID,
			ControlSocket: inst.ControlSocket,
			Raw:           map[string]string{},
		}
		if view == birdDebugFilter {
			addBirdFilterDefinitions(&item, inst.ConfigFile)
		}
		if inst.ControlSocket == "" {
			item.Error = "control socket is not configured"
			response.Instances[inst.NetNS] = item
			continue
		}
		for _, cmd := range commands {
			out, err := d.linuxDriver.RawBird(ctx, inst.ControlSocket, cmd)
			if err != nil {
				if item.Error == "" {
					item.Error = err.Error()
				}
				item.Raw[cmd] = out
				continue
			}
			item.Raw[cmd] = out
		}
		if runtime != nil {
			enrichBirdDumpInstance(&item, runtime.LinkInstances, runtime.IPsecReconcile)
		}
		response.Instances[inst.NetNS] = item
	}
	return response, nil
}

func buildBirdInstanceSpecForNetns(inst RoutingInstance, routerID uint32, _ string, ng *netnsOverlayGroup, netnsCfg netnsConfig, ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath) bird.BirdInstanceSpec {
	netnsSpec := ipsec.NetNSSpec{}
	if s, ok := netnsCfg.Names[inst.NetNS]; ok {
		netnsSpec = s
	}
	if ng != nil {
		netnsSpec = ng.Spec
	}

	overlays := []string{}
	if ng != nil {
		overlays = ng.Overlays
	}
	// Build interface patterns: merge the instance default + any overlay-specific patterns.
	// Currently all overlays use "phx*" by default, so the instance pattern suffices.
	interfacePatterns := []string{}
	if inst.InterfacePat != "" {
		interfacePatterns = append(interfacePatterns, inst.InterfacePat)
	}

	mode := bird.BirdMode(inst.Mode)
	if mode == "" {
		mode = bird.BirdModeManaged
	}

	spec := bird.BirdInstanceSpec{
		RouterID:            routerID,
		NetNSName:           inst.NetNS,
		Overlays:            overlays,
		NetNS:               bird.NetNSSpec{Kind: netnsSpec.Kind, Name: netnsSpec.Name, Path: netnsSpec.Path, Create: netnsSpec.Create},
		ControlSocketPath:   inst.ControlSocket,
		PIDFilePath:         inst.PIDFile,
		ConfigPath:          inst.ConfigFile,
		TableID:             inst.TableID,
		MetricBase:          inst.MetricBase,
		MetricStaged:        inst.MetricStaged,
		MetricDraining:      inst.MetricDraining,
		BabelRTTCost:        inst.RTTCost,
		BabelRTTMin:         inst.RTTMin,
		BabelRTTMax:         inst.RTTMax,
		BabelRTTDecay:       inst.RTTDecay,
		BabelHelloInterval:  inst.HelloInterval,
		BabelUpdateInterval: inst.UpdateInterval,
		InterfacePatterns:   interfacePatterns,
		Mode:                mode,
		ECMP:                inst.ECMP,
		ECMPLimit:           inst.ECMPLimit,
	}

	// Wire upstream config into BIRD spec.
	if inst.Upstream != nil && inst.Upstream.Enabled {
		spec.Upstream = &bird.UpstreamSpec{
			Interface: inst.Upstream.MeshInterface,
		}
	}

	// Build static routes for local assigned prefixes.
	if ars != nil && managedZone.Valid() && upstreamStaticRoutesEnabled(inst.Upstream) {
		for _, prefix := range localAssignedPrefixes(ars, managedZone) {
			via := ""
			var nextHop netip.Addr
			if inst.Upstream != nil && inst.Upstream.Enabled && inst.Upstream.Mode == upstreamModeStatic {
				via = inst.Upstream.MeshInterface
				nextHop = upstreamPeerNextHop(prefix, inst.Upstream)
			}
			spec.StaticRoutes = append(spec.StaticRoutes, bird.StaticRouteSpec{
				Prefix:  prefix,
				Via:     via,
				NextHop: nextHop,
			})
		}
	}

	return spec
}

func birdRotateInterfacePolicies(instances map[string]linkInstanceState, reconcile *ipsecReconcileState, netnsName string, overlays []string, routingInst RoutingInstance) []bird.BabelInterfacePolicy {
	metrics := make(map[string]uint)
	for _, link := range buildLinkOutputs(instances, reconcile) {
		if link.InterfaceName == "" || !linkOutputBelongsToBirdInstance(link, netnsName, overlays) {
			continue
		}
		instanceID := strings.TrimSuffix(link.ID, "#"+photonstate.LinkRuntimeStaged)
		instance, ok := linkInstanceStateByLinkID(instances, instanceID)
		if !ok || instance.StagedInterfaceName == "" {
			continue
		}
		metric := routingInst.MetricBase
		if link.RuntimeRole == photonstate.LinkRuntimeStaged {
			metric = routingInst.MetricStaged
		}
		if instance.RotatePhase == ipsec.RotatePhaseDraining {
			if link.RuntimeRole == photonstate.LinkRuntimeStaged {
				metric = routingInst.MetricBase
			} else {
				metric = routingInst.MetricDraining
			}
		}
		if previous := metrics[link.InterfaceName]; metric > previous {
			metrics[link.InterfaceName] = metric
		}
	}
	interfaces := make([]string, 0, len(metrics))
	for iface := range metrics {
		interfaces = append(interfaces, iface)
	}
	sort.Strings(interfaces)
	policies := make([]bird.BabelInterfacePolicy, 0, len(interfaces))
	for _, iface := range interfaces {
		policies = append(policies, bird.BabelInterfacePolicy{InterfaceName: iface, Metric: metrics[iface]})
	}
	return policies
}

func linkInstanceStateByLinkID(instances map[string]linkInstanceState, id string) (linkInstanceState, bool) {
	if instance, ok := instances[id]; ok {
		return instance, true
	}
	for _, instance := range instances {
		if firstNonEmpty(instance.LinkID, instance.ID) == id {
			return instance, true
		}
	}
	return linkInstanceState{}, false
}

func upstreamPeerNextHop(prefix netip.Prefix, upstream *UpstreamConfig) netip.Addr {
	if upstream == nil {
		return netip.Addr{}
	}
	value := upstream.ExternalIPv6LL
	if prefix.Addr().Is4() {
		value = upstream.ExternalIPv4LL
	}
	parsed, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Addr{}
	}
	return parsed.Addr()
}

func upstreamStaticRoutesEnabled(upstream *UpstreamConfig) bool {
	if upstream == nil || !upstream.Enabled {
		return true
	}
	return upstream.Mode == upstreamModeStatic
}

func routingInstancesEnabled(config *appConfig) []RoutingInstance {
	if config == nil {
		return nil
	}
	var out []RoutingInstance
	for _, inst := range config.Routing.Instances {
		if inst.Enabled && inst.Mode != ipsec.RoutingModeDisabled {
			out = append(out, inst)
		}
	}
	return out
}

// buildRoutingExportSet computes the BIRD export set using the forwarding policy
// shared with the firewall planner (Phase 6.3.4). An absent or non-transit
// namespace policy exports only local assigned prefixes; transit=true exports
// authorized prefixes filtered by the shared allow/deny lists.
func buildRoutingExportSet(ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath, config *appConfig, netnsName string) []netip.Prefix {
	localExport := authorizedPrefixes(ars, []zone.ZonePath{managedZone})
	policy := netnsForwardingPolicy(config, netnsName)
	if !policy.Transit {
		// Non-transit or no policy: only export local assigned prefixes.
		return localExport
	}
	// Transit: export all authorized prefixes filtered by the policy.
	allAuthorized := authorizedPrefixes(ars, nil)
	if len(policy.AllowPrefixes) == 0 && len(policy.DenyPrefixes) == 0 {
		return allAuthorized
	}
	return filterAuthorizedByPolicy(allAuthorized, policy)
}

func authorizedPrefixes(ars *routing.AuthorizedRouteSet, zones []zone.ZonePath) []netip.Prefix {
	if ars == nil {
		return nil
	}
	var out []netip.Prefix
	for source, prefixes := range ars.Announced {
		if len(zones) > 0 {
			found := slices.Contains(zones, source)
			if !found {
				continue
			}
		}
		for prefix := range prefixes {
			out = append(out, prefix)
		}
	}
	return out
}

func localAssignedPrefixes(ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath) []netip.Prefix {
	return localAssignedPrefixesMatching(ars, managedZone, nil)
}

func localNonSharedAssignedPrefixes(ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath) []netip.Prefix {
	return localAssignedPrefixesMatching(ars, managedZone, func(entry *routing.AssignmentEntry) bool {
		return !entry.Shared
	})
}

func localAssignedPrefixesMatching(ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath, match func(*routing.AssignmentEntry) bool) []netip.Prefix {
	if ars == nil || !managedZone.Valid() {
		return nil
	}
	outSet := make(map[netip.Prefix]struct{})
	if len(ars.AllAssignments) > 0 {
		for _, entry := range ars.AllAssignments {
			if entry == nil || entry.AssignedTo != managedZone || (match != nil && !match(entry)) {
				continue
			}
			outSet[entry.Prefix] = struct{}{}
		}
	} else {
		for prefix, entry := range ars.Assignments {
			if entry == nil || entry.AssignedTo != managedZone || (match != nil && !match(entry)) {
				continue
			}
			outSet[prefix] = struct{}{}
		}
	}
	out := make([]netip.Prefix, 0, len(outSet))
	for prefix := range outSet {
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool { return netipPrefixLess(out[i], out[j]) })
	return out
}

func ipamAutoAnnounceEnabled(config ipamConfig) bool {
	return config.AutoAnnounceAssignedIPs || len(config.Announce) > 0
}

func autoAnnounceAssignedPrefixes(ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath, config ipamConfig) []netip.Prefix {
	if ars == nil || !managedZone.Valid() || !ipamAutoAnnounceEnabled(config) {
		return nil
	}
	entries := ars.AllAssignments
	if len(entries) == 0 {
		entries = make([]*routing.AssignmentEntry, 0, len(ars.Assignments))
		for _, entry := range ars.Assignments {
			entries = append(entries, entry)
		}
	}
	selected := make(map[netip.Prefix]struct{})
	for _, entry := range entries {
		if entry == nil || entry.AssignedTo != managedZone {
			continue
		}
		if config.AutoAnnounceAssignedIPs || assignmentMatchesAnnounceSelectors(entry, config.Announce) {
			selected[entry.Prefix] = struct{}{}
		}
	}
	out := make([]netip.Prefix, 0, len(selected))
	for prefix := range selected {
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool { return netipPrefixLess(out[i], out[j]) })
	return out
}

func assignmentMatchesAnnounceSelectors(entry *routing.AssignmentEntry, selectors []string) bool {
	for _, selector := range selectors {
		switch {
		case selector == "all":
			return true
		case selector == "non-shared" && !entry.Shared:
			return true
		case selector == "shared" && entry.Shared:
			return true
		case strings.HasPrefix(selector, "tag:") && entry.Tag == strings.TrimPrefix(selector, "tag:"):
			return true
		case strings.HasPrefix(selector, "assignment:") && entry.Prefix.String() == strings.TrimPrefix(selector, "assignment:"):
			return true
		}
	}
	return false
}

func externalUpstreamRoutePrefixes(ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath) []netip.Prefix {
	authorized := authorizedPrefixes(ars, nil)
	localAssigned := localAssignedPrefixes(ars, managedZone)
	if len(authorized) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(authorized))
	seen := make(map[netip.Prefix]struct{}, len(authorized))
	for _, prefix := range authorized {
		if prefixWithinAny(prefix, localAssigned) {
			continue
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool { return netipPrefixLess(out[i], out[j]) })
	return out
}

func externalUpstreamSourcePrefixes(ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath) []netip.Prefix {
	// Source identities belong to the node itself. Shared/anycast prefixes are
	// served behind the upstream veth and must remain routes, not addresses on
	// the veth endpoint itself.
	localAssigned := localNonSharedAssignedPrefixes(ars, managedZone)
	out := make([]netip.Prefix, 0, len(localAssigned))
	seen := make(map[netip.Prefix]struct{}, len(localAssigned))
	for _, prefix := range localAssigned {
		source := firstUsablePrefixAddress(prefix)
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool { return netipPrefixLess(out[i], out[j]) })
	return out
}

func firstUsablePrefixAddress(prefix netip.Prefix) netip.Prefix {
	addr := prefix.Addr()
	if prefix.Bits() < addr.BitLen() {
		next := addr.Next()
		if next.IsValid() && prefix.Contains(next) {
			addr = next
		}
	}
	return netip.PrefixFrom(addr, prefix.Bits())
}

func prefixWithinAny(prefix netip.Prefix, candidates []netip.Prefix) bool {
	for _, candidate := range candidates {
		if prefixWithin(prefix, candidate) {
			return true
		}
	}
	return false
}

func prefixWithin(prefix, parent netip.Prefix) bool {
	if prefix.Addr().Is4() != parent.Addr().Is4() {
		return false
	}
	return prefix.Bits() >= parent.Bits() && parent.Contains(prefix.Addr())
}

func netipPrefixLess(a, b netip.Prefix) bool {
	if a.Addr().Less(b.Addr()) {
		return true
	}
	if b.Addr().Less(a.Addr()) {
		return false
	}
	return a.Bits() < b.Bits()
}

// assignmentPrefixes returns all IPAM assignment prefixes from the authorized
// route set. These prefixes are still used by firewall/IPAM consumers; BIRD
// import/export filters use authorized route announcements instead.
func assignmentPrefixes(ars *routing.AuthorizedRouteSet) []netip.Prefix {
	if ars == nil {
		return nil
	}
	out := make([]netip.Prefix, 0, len(ars.Assignments))
	for prefix := range ars.Assignments {
		out = append(out, prefix)
	}
	return out
}

func birdOwnerForInstance(inst RoutingInstance, netnsName string) bird.BirdResourceOwner {
	owner := bird.BirdResourceOwner{
		Manager:    "photon",
		InstanceID: inst.ID,
		NetNSName:  netnsName,
	}
	owner.Token = bird.OwnerToken(owner.InstanceID, owner.NetNSName)
	owner.ControlSocketToken = bird.ResourceToken(owner, "control_socket")
	owner.PIDFileToken = bird.ResourceToken(owner, "pid_file")
	owner.ConfigFileToken = bird.ResourceToken(owner, "config_file")
	owner.RouteTableToken = bird.ResourceToken(owner, "route_table")
	owner.RuleToken = bird.ResourceToken(owner, "rule")
	return owner
}

func routingCrashBackoff(failureCount int) time.Duration {
	if failureCount < 1 {
		failureCount = 1
	}
	backoff := time.Duration(1<<minInt(failureCount-1, 6)) * time.Second
	if backoff > maxRoutingCrashBackoff {
		return maxRoutingCrashBackoff
	}
	return backoff
}

func formatBirdProcessExit(exit *bird.ProcessExit) string {
	if exit == nil {
		return ""
	}
	if exit.PID > 0 && exit.Error != "" {
		return fmt.Sprintf("pid %d: %s", exit.PID, exit.Error)
	}
	if exit.PID > 0 {
		return fmt.Sprintf("pid %d", exit.PID)
	}
	return exit.Error
}

func rootTrustHash(ns *zone.NetworkState) []byte {
	if ns == nil {
		return nil
	}
	if len(ns.GlobalRoot) > 0 {
		return ns.GlobalRoot
	}
	root := ns.Zones[zone.RootZone]
	if root != nil && root.Authority != nil && len(root.Authority.Keys) > 0 {
		return root.Authority.Keys[0].Key
	}
	return nil
}

func isDryRunMissingBirdError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "bird binary not found") || strings.Contains(msg, "no such file") || strings.Contains(msg, "executable file not found")
}

func isDryRunConnectError(err error) bool {
	if err == nil {
		return false
	}
	msg := err.Error()
	return strings.Contains(msg, "dial") || strings.Contains(msg, "no such file") || strings.Contains(msg, "connection refused")
}

// autoAnnounceAssignedIPsResult publishes or withdraws routes/announcements/*
// records for every IPAM assignment whose assigned_to equals this node's
// managed zone. It commits network record changes through the daemon state
// store so routing reconcile can run BIRD work from a refreshed committed
// snapshot.
func (d *Daemon) autoAnnounceAssignedIPsResult(ars *routing.AuthorizedRouteSet) (bool, error) {
	if d == nil || d.App == nil || d.StateStore == nil {
		return false, nil
	}

	view := d.StateStore.common.ReadView()
	if view.State == nil {
		return false, nil
	}
	plan, planErr := autoAnnounceAssignedIPsPlan(view.State.Network, view.State.ManagedZone, ars, d.App.Config.IPAM)
	if planErr != nil {
		return false, planErr
	}
	if !plan.changed() {
		return false, nil
	}

	managedZone := view.State.ManagedZone
	if !managedZone.Valid() || managedZone.IsRoot() {
		return false, nil
	}
	intents := make([]corestate.LocalIntent, 0, len(plan.announce)+len(plan.withdraw))
	for _, prefix := range plan.announce {
		intents = append(intents, corestate.AnnounceRouteIntent{Zone: managedZone, Prefix: prefix.Masked().String(), Controller: routing.RouteControllerAuto})
	}
	for _, prefix := range plan.withdraw {
		intents = append(intents, corestate.WithdrawRouteIntent{Zone: managedZone, Prefix: prefix.Masked().String(), Controller: routing.RouteControllerAuto})
	}
	result, err := d.StateStore.ApplyCommonLocalIntents(context.Background(), intents, d.now())
	if err != nil {
		return false, err
	}
	if !result.Committed {
		return false, nil
	}
	for _, prefix := range plan.announce {
		d.logInfo("routing", "auto_announce_assigned_ip", map[string]any{"zone": managedZone, "prefix": prefix.String()})
	}
	for _, prefix := range plan.withdraw {
		d.logInfo("routing", "auto_withdraw_assigned_ip", map[string]any{"zone": managedZone, "prefix": prefix.String()})
	}
	d.notifyStateChanged()
	return true, nil
}

type autoAnnouncePlan struct {
	announce []netip.Prefix
	withdraw []netip.Prefix
}

func (p autoAnnouncePlan) changed() bool {
	return len(p.announce) > 0 || len(p.withdraw) > 0
}

func autoAnnounceAssignedIPsPlan(network *zone.NetworkState, managedZone zone.ZonePath, ars *routing.AuthorizedRouteSet, config ipamConfig) (autoAnnouncePlan, error) {
	if network == nil {
		return autoAnnouncePlan{}, nil
	}
	if managedZone.IsRoot() || !managedZone.Valid() {
		return autoAnnouncePlan{}, nil
	}

	desired := make(map[netip.Prefix]struct{})
	for _, prefix := range autoAnnounceAssignedPrefixes(ars, managedZone, config) {
		desired[prefix] = struct{}{}
	}

	localAnnounced := make(map[netip.Prefix]*routing.RouteAnnouncementRecord)
	zs := network.Zones[managedZone]
	if zs != nil {
		for key, rec := range zs.Records {
			if !strings.HasPrefix(key, routing.RecordKeyPrefixRoutes) {
				continue
			}
			ann, err := routing.ParseRouteAnnouncementRecord(rec)
			if err != nil {
				continue
			}
			p, err := netip.ParsePrefix(ann.Prefix)
			if err != nil {
				continue
			}
			localAnnounced[p] = ann
		}
	}

	var plan autoAnnouncePlan
	for prefix := range desired {
		if ann, ok := localAnnounced[prefix]; ok && ann.Active {
			continue
		}
		plan.announce = append(plan.announce, prefix)
	}

	for prefix, ann := range localAnnounced {
		if !ann.Active {
			continue
		}
		if _, ok := desired[prefix]; ok {
			continue
		}
		// Legacy true retains the old ownership model and reconciles every local
		// announcement. Selector mode only withdraws records it created, leaving
		// service/operator-controlled shared prefixes untouched.
		if !config.AutoAnnounceAssignedIPs && ann.Controller != routing.RouteControllerAuto {
			continue
		}
		plan.withdraw = append(plan.withdraw, prefix)
	}
	return plan, nil
}

func (d *Daemon) routingNetnsProtocolIntent(verified *corestate.VerifiedState) (*corestate.PutProtocolRecordIntent, error) {
	if d == nil || verified == nil || verified.Network == nil || d.App == nil || d.App.Config == nil {
		return nil, nil
	}
	config := d.App.Config
	if verified.ManagedZone == zone.RootZone || !verified.ManagedZone.Valid() || len(verified.IdentityPrivateKey) == 0 {
		return nil, nil
	}
	if len(config.Routing.Instances) == 0 {
		return nil, nil
	}
	netnsNames := routingNetnsNames(config.Routing)
	if len(netnsNames) == 0 {
		return nil, nil
	}
	record := routing.RoutingNetnsRecord{Version: 1, Netns: netnsNames}
	value, err := json.Marshal(record)
	if err != nil {
		return nil, fmt.Errorf("marshal routing/netns record: %w", err)
	}
	if zs := verified.Network.Zones[verified.ManagedZone]; zs != nil {
		if current := zs.Records[routing.RecordKeyRoutingNetns]; current != nil && bytesEqual(current.Value, value) {
			return nil, nil
		}
	}
	return &corestate.PutProtocolRecordIntent{
		Kind: corestate.ProtocolRecordRoutingNetns, Zone: verified.ManagedZone,
		Key: routing.RecordKeyRoutingNetns, Type: routing.RecordTypeRoutingNetns, Value: value,
	}, nil
}

func bytesEqual(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
