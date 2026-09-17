package main

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
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
	common := d.State.Common.ReadView()
	if common.State == nil {
		return nil
	}
	links, ipsecReconcile := d.linuxObservation.ipsecSnapshot()
	rev := uint64(common.Revision)
	verified := common.State
	routingObserved := d.linuxObservation.routingSnapshot()
	config := d.App.Config
	routingInstances := routingInstancesEnabled(config)
	if len(routingInstances) == 0 {
		d.linuxObservation.replaceRouting(nil)
		return nil
	}
	if verified.ManagedZone.IsRoot() || !verified.ManagedZone.Valid() {
		d.linuxObservation.replaceRouting(nil)
		return nil
	}
	birdInstances := make(map[string]*bird.InstanceObservation, len(routingInstances))
	if routingObserved != nil {
		for _, configured := range routingInstances {
			if previous := routingObserved.Instances[configured.Bird.NetNSName]; previous != nil {
				birdInstances[configured.Bird.NetNSName] = previous
			}
		}
	}
	forceReload := d.routingForceReload
	d.routingForceReload = false

	now := d.now()
	summary := &routingObservation{Instances: birdInstances, LastRunUnix: now.Unix()}

	ars, err := routing.BuildAuthorizedRouteSet(verified.Network, now)
	if err != nil {
		summary.LastFailure = err
		d.publishRoutingObservation(rev, summary)
		return fmt.Errorf("build authorized route set: %w", err)
	}

	var firstErr error
	autoAnnounceChanged, autoAnnounceErr := d.autoAnnounceAssignedIPsResult(ars)
	if autoAnnounceErr != nil {
		firstErr = autoAnnounceErr
	}

	// Auto-announce changes verified Network through its own common-state
	// transaction. Refresh the common view only in that uncommon case.
	if autoAnnounceChanged {
		common = d.State.Common.ReadView()
		if common.State == nil {
			return firstErr
		}
		rev = uint64(common.Revision)
		verified = common.State
		ars, err = routing.BuildAuthorizedRouteSet(verified.Network, now)
		if err != nil && firstErr == nil {
			firstErr = fmt.Errorf("rebuild authorized route set after auto-announce: %w", err)
		}
	}

	// Build per-netns overlay groups for interface pattern merging.
	overlayByNetns := groupOverlaysByNetns(config.IPsec.LinkGroups)

	for _, inst := range routingInstances {
		if err := d.reconcileRoutingForInstance(ctx, verified, birdInstances, links, ipsecReconcile, inst, ars, overlayByNetns, config, now, forceReload); err != nil && firstErr == nil {
			firstErr = err
		}
	}

	if firstErr != nil {
		summary.LastFailure = firstErr
	}

	d.publishRoutingObservation(rev, summary)
	return firstErr
}

// netnsOverlayGroup holds the overlays sharing a single netns/BIRD instance.
type netnsOverlayGroup struct {
	NetNSName string
	Overlays  []string
	Spec      ipsec.NetNSSpec
}

func groupOverlaysByNetns(groups []ipsec.LinkGroupSpec) map[string]*netnsOverlayGroup {
	out := make(map[string]*netnsOverlayGroup)
	for _, group := range groups {
		netnsName := photonlinux.NetNSTarget(group.NetNS)
		ng, ok := out[netnsName]
		if !ok {
			ng = &netnsOverlayGroup{NetNSName: netnsName}
			ng.Spec = group.NetNS.Normalized()
			out[netnsName] = ng
		}
		ng.Overlays = append(ng.Overlays, group.ID)
	}
	return out
}

func (d *Daemon) publishRoutingObservation(rev uint64, summary *routingObservation) {
	if d == nil || d.State == nil || summary == nil {
		return
	}
	currentRev := uint64(d.State.Common.VerifiedRevision())
	if currentRev != rev {
		d.routingDirty = true
		d.logWarn("routing", "stale_reconcile_result", map[string]any{
			"source_revision":  rev,
			"current_revision": currentRev,
		})
		return
	}
	d.linuxObservation.replaceRouting(summary)
}

func (d *Daemon) reconcileRoutingForInstance(ctx context.Context, verified *corestate.VerifiedState, birdInstances map[string]*bird.InstanceObservation, links map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, inst photonlinux.RoutingInstance, ars *routing.AuthorizedRouteSet, overlayByNetns map[string]*netnsOverlayGroup, config *appConfig, now time.Time, forceReload bool) error {
	// Keep the single-instance entry point safe for dirty flushes, explicit
	// reloads, tests, and future callers that do not pass the filtered list.
	// Disabling an instance stops reconciliation; it intentionally does not
	// tear down resources created while the instance was enabled.
	if !routingInstanceEnabled(inst) {
		return nil
	}

	netnsName := inst.Bird.NetNSName
	instState := birdInstances[netnsName]
	if instState == nil {
		instState = &bird.InstanceObservation{NetNSName: netnsName}
		birdInstances[netnsName] = instState
	}

	// Record which overlays share this instance.
	overlays := []string{}
	if ng, ok := overlayByNetns[netnsName]; ok {
		overlays = ng.Overlays
	}
	instState.Overlays = overlays

	routerIDLabel := inst.RouterIDLabel
	if routerIDLabel == "" {
		routerIDLabel = inst.Bird.NetNSName
	}
	routerID := bird.StableRouterID(verified.ManagedZone, rootTrustHash(verified.Network), routerIDLabel)
	instState.RouterID = routerID

	spec := buildBirdInstanceSpecForNetns(inst, routerID, overlayByNetns[netnsName], ars, verified.ManagedZone)
	spec.InterfacePolicies = birdRotateInterfacePolicies(links, reconcile, netnsName, overlays, inst)
	instState.ConfigPath = spec.ConfigPath
	instState.ControlSocket = spec.ControlSocketPath
	instState.PIDFile = spec.PIDFilePath
	instState.Owner = birdOwnerForInstance(inst, netnsName)
	spec.Owner = instState.Owner

	// Ensure veth pair for upstream if configured and create_veth is true.
	if inst.Upstream != nil && inst.Upstream.Enabled && inst.Upstream.CreateVeth {
		vspec := inst.Upstream.Veth
		vspec.MeshNetns = netnsName
		if err := d.linuxDriver.EnsureRoutingVeth(ctx, vspec); err != nil {
			instState.State = birdInstanceStateError
			instState.LastFailure = fmt.Errorf("ensure veth: %w", err)
			return fmt.Errorf("ensure upstream veth for netns %q: %w", netnsName, err)
		}
	}
	if inst.Upstream != nil && inst.Upstream.Enabled &&
		(inst.Upstream.Mode == photonlinux.UpstreamModeStatic || inst.Upstream.InstallSourceAddresses) {
		var routePrefixes []netip.Prefix
		if inst.Upstream.Mode == photonlinux.UpstreamModeStatic {
			routePrefixes = photonlinux.ExternalUpstreamRoutePrefixes(ars, verified.ManagedZone)
		}
		var sourcePrefixes []netip.Prefix
		if inst.Upstream.InstallSourceAddresses {
			sourcePrefixes = photonlinux.ExternalUpstreamSourcePrefixes(ars, verified.ManagedZone)
		}
		rspec := photonlinux.UpstreamRouteSpec{
			NetNS:          inst.Upstream.Veth.PeerNetns,
			Interface:      inst.Upstream.Veth.PeerInterface,
			Prefixes:       routePrefixes,
			SourcePrefixes: sourcePrefixes,
			MeshIPv4LL:     inst.Upstream.Veth.MeshIPv4LL,
			MeshIPv6LL:     inst.Upstream.Veth.MeshIPv6LL,
		}
		if err := d.linuxDriver.EnsureUpstreamRoutes(ctx, rspec); err != nil {
			instState.State = birdInstanceStateError
			instState.LastFailure = fmt.Errorf("ensure upstream routes: %w", err)
			return fmt.Errorf("ensure upstream routes for netns %q: %w", netnsName, err)
		}
	}

	importSet := routing.AuthorizedPrefixes(ars, nil)
	// Phase 6.3.4: BIRD export set must use the same forwarding policy as the
	// firewall. A non-transit node only exports its own local assigned prefixes;
	// a transit node exports authorized prefixes filtered by the forwarding
	// policy allow/deny lists. Both BIRD and firewall consume the same policy
	// so they never disagree on which transit paths are allowed.
	exportSet := photonlinux.BuildRoutingExportSet(ars, verified.ManagedZone, config.Netns.ForwardingPolicy(netnsName))

	configBytes, err := bird.DefaultConfigGenerator{}.Generate(spec, importSet, exportSet)
	if err != nil {
		instState.State = birdInstanceStateError
		instState.LastFailure = err
		return fmt.Errorf("generate bird config for netns %q: %w", netnsName, err)
	}

	configHash := fmt.Sprintf("%x", sha256.Sum256(configBytes))
	configChanged := forceReload || instState.LastConfigHash == "" || instState.LastConfigHash != configHash

	mode := inst.Bird.Mode
	if mode == "" {
		mode = bird.BirdModeManaged
	}

	switch mode {
	case bird.BirdModeManaged:
		if configChanged {
			if err := d.linuxDriver.WriteBirdConfig(spec.ConfigPath, configBytes); err != nil {
				instState.State = birdInstanceStateError
				instState.LastFailure = err
				return fmt.Errorf("write bird config for netns %q: %w", netnsName, err)
			}
		}

		running, exit := d.linuxDriver.BirdProcessStatus(ctx, netnsName)
		if exit != nil {
			instState.LastExit = formatBirdProcessExit(exit)
			instState.FailureCount++
			instState.BackoffUntilUnix = now.Add(routingCrashBackoff(instState.FailureCount)).Unix()
			instState.State = birdInstanceStateDegraded
			instState.LastFailure = fmt.Errorf("bird process exited: %s", instState.LastExit)
			running = false
		}
		if !running && instState.BackoffUntilUnix > now.Unix() {
			instState.State = birdInstanceStateDegraded
			instState.LastFailure = fmt.Errorf("bird restart backoff active until %s", time.Unix(instState.BackoffUntilUnix, 0).Format(time.RFC3339))
			return nil
		}
		if !running {
			if err := d.linuxDriver.StartBird(ctx, spec); err != nil {
				instState.State = birdInstanceStateError
				instState.LastFailure = err
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
				instState.LastFailure = err
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
		d.observeBirdForHealth(ctx, links, reconcile, netnsName, instState.Overlays, spec.ControlSocketPath)

	case bird.BirdModeExternal:
		observed, err := d.linuxDriver.ObserveBird(ctx, spec.ControlSocketPath, bird.InternalRouteTableNames(netnsName)...)
		if err != nil {
			instState.State = birdInstanceStateError
			instState.LastFailure = err
			d.recordBirdHealthObservationUnavailableForLinks(links, reconcile, netnsName, instState.Overlays)
			if !isDryRunConnectError(err) {
				return fmt.Errorf("bird status for netns %q: %w", netnsName, err)
			}
		} else {
			instState.State = birdInstanceStateRunning
			d.recordBirdHealthObservationForLinks(links, reconcile, netnsName, instState.Overlays, observed)
		}
	}

	instState.LastConfigHash = configHash
	if instState.State == "" {
		instState.State = birdInstanceStatePending
	}
	if instState.State == birdInstanceStateRunning {
		instState.LastFailure = nil
	}
	return nil
}

func (d *Daemon) observeBirdForHealth(ctx context.Context, instances map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, netnsName string, overlays []string, socketPath string) {
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

func (d *Daemon) recordBirdHealthObservationUnavailableForLinks(instances map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, netnsName string, overlays []string) {
	d.recordBirdHealthObservationForLinks(instances, reconcile, netnsName, overlays, &bird.BirdObservation{})
}

func (d *Daemon) recordBirdHealthObservationForLinks(instances map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, netnsName string, overlays []string, observed *bird.BirdObservation) {
	if d == nil || d.health == nil || d.health.Manager == nil || observed == nil {
		return
	}
	for _, link := range buildLinkOutputs(instances, reconcile) {
		if link.RuntimeRole != "staged" || link.InterfaceName == "" || !linkOutputBelongsToBirdInstance(link, netnsName, overlays) {
			continue
		}
		instanceID := strings.TrimSuffix(link.ID, "#staged")
		obs := birdObservationForInterface(instanceID, healthProbeID(instanceID, "staged"), link.InterfaceName, observed)
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

func birdObservationForInterface(instanceID, probeID, iface string, observed *bird.BirdObservation) health.BabelObservation {
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
		if !inst.Enabled || inst.Bird.Mode == ipsec.RoutingModeDisabled || inst.Bird.Mode == ipsec.RoutingModeExternal {
			continue
		}
		if !force && inst.ShutdownPolicy != photonlinux.RoutingShutdownPolicyStop {
			continue
		}
		spec := inst.Bird
		if spec.Mode == "" {
			spec.Mode = bird.BirdModeManaged
		}
		spec.Owner = birdOwnerForInstance(inst, inst.Bird.NetNSName)
		if err := d.linuxDriver.StopBird(ctx, spec); err != nil && firstErr == nil {
			firstErr = fmt.Errorf("stop bird for netns %q: %w", inst.Bird.NetNSName, err)
		}
	}
	return firstErr
}

func (d *Daemon) birdDumpForControl(ctx context.Context, netnsName string, view bird.DebugView) (*inspect.BirdDumpResponse, error) {
	response := &inspect.BirdDumpResponse{Instances: map[string]inspect.BirdDumpInstance{}}
	if d == nil || d.App == nil || d.App.Config == nil {
		return response, nil
	}
	commands, err := bird.DebugCommands(view)
	if err != nil {
		return nil, err
	}
	links, reconcile := d.linuxObservation.ipsecSnapshot()
	linkOutputs := buildLinkOutputs(links, reconcile)
	for _, inst := range d.App.Config.Routing.Instances {
		if !inst.Enabled || inst.Bird.Mode == ipsec.RoutingModeDisabled {
			continue
		}
		if netnsName != "" && inst.Bird.NetNSName != netnsName && inst.ID != netnsName {
			continue
		}
		item := inspect.BirdDumpInstance{
			NetNS:         inst.Bird.NetNSName,
			InstanceID:    inst.ID,
			ControlSocket: inst.Bird.ControlSocketPath,
			Raw:           map[string]string{},
		}
		if view == bird.DebugFilter {
			addBirdFilterDefinitions(&item, inst.Bird.ConfigPath)
		}
		if inst.Bird.ControlSocketPath == "" {
			item.Failure = inspect.BuildFailure(inspect.FailureCodeBirdQuery, errors.New("control socket is not configured"))
			response.Instances[inst.Bird.NetNSName] = item
			continue
		}
		for _, cmd := range commands {
			out, err := d.linuxDriver.RawBird(ctx, inst.Bird.ControlSocketPath, cmd)
			if err != nil {
				if item.Failure == nil {
					item.Failure = inspect.BuildFailure(inspect.FailureCodeBirdQuery, err)
				}
				item.Raw[cmd] = out
				continue
			}
			item.Raw[cmd] = out
		}
		inspect.EnrichBirdDumpInstance(&item, inspect.BuildBirdInterfaceContexts(linkOutputs, item.NetNS))
		response.Instances[inst.Bird.NetNSName] = item
	}
	return response, nil
}

func buildBirdInstanceSpecForNetns(inst photonlinux.RoutingInstance, routerID uint32, ng *netnsOverlayGroup, ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath) bird.BirdInstanceSpec {
	spec := inst.Bird
	spec.RouterID = routerID
	if ng != nil {
		spec.Overlays = ng.Overlays
		spec.NetNS = bird.NetNSSpec{Kind: ng.Spec.Kind, Name: ng.Spec.Name, Path: ng.Spec.Path, Create: ng.Spec.Create}
	}
	if spec.Mode == "" {
		spec.Mode = bird.BirdModeManaged
	}

	// Wire upstream config into BIRD spec.
	if inst.Upstream != nil && inst.Upstream.Enabled {
		spec.Upstream = &bird.UpstreamSpec{
			Interface: inst.Upstream.Veth.MeshInterface,
		}
	}

	// Build static routes for local assigned prefixes.
	if ars != nil && managedZone.Valid() && upstreamStaticRoutesEnabled(inst.Upstream) {
		for _, prefix := range routing.LocalAssignedPrefixes(ars, managedZone, true) {
			via := ""
			var nextHop netip.Addr
			if inst.Upstream != nil && inst.Upstream.Enabled && inst.Upstream.Mode == photonlinux.UpstreamModeStatic {
				via = inst.Upstream.Veth.MeshInterface
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

func birdRotateInterfacePolicies(instances map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, netnsName string, overlays []string, routingInst photonlinux.RoutingInstance) []bird.BabelInterfacePolicy {
	metrics := make(map[string]uint)
	for _, link := range buildLinkOutputs(instances, reconcile) {
		if link.InterfaceName == "" || !linkOutputBelongsToBirdInstance(link, netnsName, overlays) {
			continue
		}
		instanceID := strings.TrimSuffix(link.ID, "#"+photonstate.LinkRuntimeStaged)
		instance, ok := linkInstanceByLinkID(instances, instanceID)
		if !ok || instance.StagedInterfaceName == "" {
			continue
		}
		metric := routingInst.Bird.MetricBase
		if link.RuntimeRole == photonstate.LinkRuntimeStaged {
			metric = routingInst.Bird.MetricStaged
		}
		if instance.RotatePhase == ipsec.RotatePhaseDraining {
			if link.RuntimeRole == photonstate.LinkRuntimeStaged {
				metric = routingInst.Bird.MetricBase
			} else {
				metric = routingInst.Bird.MetricDraining
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

func linkInstanceByLinkID(instances map[string]ipsec.LinkInstance, id string) (ipsec.LinkInstance, bool) {
	if instance, ok := instances[id]; ok {
		return instance, true
	}
	for _, instance := range instances {
		if firstNonEmpty(instance.LinkID, instance.ID) == id {
			return instance, true
		}
	}
	return ipsec.LinkInstance{}, false
}

func upstreamPeerNextHop(prefix netip.Prefix, upstream *photonlinux.UpstreamConfig) netip.Addr {
	if upstream == nil {
		return netip.Addr{}
	}
	value := upstream.Veth.PeerIPv6LL
	if prefix.Addr().Is4() {
		value = upstream.Veth.PeerIPv4LL
	}
	parsed, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Addr{}
	}
	return parsed.Addr()
}

func upstreamStaticRoutesEnabled(upstream *photonlinux.UpstreamConfig) bool {
	if upstream == nil || !upstream.Enabled {
		return true
	}
	return upstream.Mode == photonlinux.UpstreamModeStatic
}

func routingInstancesEnabled(config *appConfig) []photonlinux.RoutingInstance {
	if config == nil {
		return nil
	}
	var out []photonlinux.RoutingInstance
	for _, inst := range config.Routing.Instances {
		if routingInstanceEnabled(inst) {
			out = append(out, inst)
		}
	}
	return out
}

func routingInstanceEnabled(inst photonlinux.RoutingInstance) bool {
	return inst.Enabled && inst.Bird.Mode != ipsec.RoutingModeDisabled
}

func birdOwnerForInstance(inst photonlinux.RoutingInstance, netnsName string) bird.BirdResourceOwner {
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
	backoff := time.Duration(1<<min(failureCount-1, 6)) * time.Second
	if backoff > maxRoutingCrashBackoff {
		return maxRoutingCrashBackoff
	}
	return backoff
}

func formatBirdProcessExit(exit *bird.ProcessExit) string {
	if exit == nil {
		return ""
	}
	if exit.PID > 0 && exit.Failure != nil {
		return fmt.Sprintf("pid %d: %s", exit.PID, exit.Failure)
	}
	if exit.PID > 0 {
		return fmt.Sprintf("pid %d", exit.PID)
	}
	if exit.Failure != nil {
		return exit.Failure.Error()
	}
	return ""
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
	if d == nil || d.App == nil || d.State == nil {
		return false, nil
	}

	view := d.State.Common.ReadView()
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
	result, err := d.State.Common.ApplyLocalIntents(context.Background(), intents, d.now())
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
	for _, prefix := range routing.AutoAnnounceAssignedPrefixes(ars, managedZone, config.AutoAnnounceAssignedIPs, config.Announce) {
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
	netnsNames := config.Routing.NetNSNames()
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
