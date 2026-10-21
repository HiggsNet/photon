package main

import (
	"context"
	"fmt"
	"reflect"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

const defaultFirewallReconcileInterval = 30 * time.Second

// firewallDriver is the subset of firewall.FirewallDriver used by the daemon.
type firewallDriver interface {
	Preflight(ctx context.Context, spec firewall.FirewallInstanceSpec) (firewall.FirewallPreflight, error)
	Plan(ctx context.Context, desired *firewall.FirewallDesiredState, observed firewall.FirewallObservedState) (firewall.FirewallPlan, error)
	Apply(ctx context.Context, plan firewall.FirewallPlan, desired *firewall.FirewallDesiredState) (firewall.FirewallApplyResult, error)
	ListOwned(ctx context.Context, owner firewall.Owner) (firewall.FirewallObservedState, error)
	DeleteStale(ctx context.Context, refs []firewall.FirewallObjectRef) error
}

// reconcileFirewall is the daemon single-writer firewall reconcile entry point.
// It computes the desired state from verified active state + local config,
// diffs against observed owned objects, and applies the plan via the driver.
// The default driver is DryRunDriver; real nft/iptables drivers are added later.
func (d *DaemonService) reconcileFirewall(ctx context.Context) error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil
	}
	snapshot, rev := d.StateStore.firewallSnapshot()
	if snapshot == nil {
		return nil
	}
	config := d.Sync.App.Config
	instances := firewallInstancesEnabled(config)
	if len(instances) == 0 {
		return nil
	}
	if snapshot.ManagedZone.IsRoot() || !snapshot.ManagedZone.Valid() {
		return nil
	}

	now := d.Sync.now()
	summary := cloneFirewallReconcileState(snapshot.FirewallReconcile)
	if summary == nil {
		summary = &firewallReconcileState{}
	}
	summary.LastRunUnix = now.Unix()

	// Build authorized route set for prefix inputs.
	ars, err := routing.BuildAuthorizedRouteSet(snapshot.Network, now)
	if err != nil {
		summary.LastError = err.Error()
		_ = d.commitFirewallReconcileResult(rev, snapshot.EndpointACLs, summary)
		return fmt.Errorf("firewall build authorized route set: %w", err)
	}

	preflight := firewall.PreflightProbe(ctx)
	summary.Backend = preflight.Backend

	if summary.Instances == nil {
		summary.Instances = make(map[string]*firewallInstanceReconcileStateEntry)
	}

	charonIKE, charonNATT := firewallCharonPorts(config, snapshot)

	if len(instances) > 0 && preflight.NFTNetlink != "ok" && !firewall.IPTablesAvailable(preflight) {
		d.logWarn("firewall", "no_backend_available", map[string]any{
			"nft":       preflight.NFTNetlink,
			"iptables":  preflight.Iptables,
			"ip6tables": preflight.IptablesV6,
			"ipset":     preflight.IPSet,
			"net_admin": preflight.CAPNetAdmin,
			"message":   "no complete nft or iptables/ip6tables/ipset backend available; firewall rules will not be applied",
		})
	}

	var firstErr error
	for _, instCfg := range instances {
		listenAddrs := instCfg.ListenAddrs
		spec := firewallInstanceSpecFromConfig(instCfg, listenAddrs, charonIKE, charonNATT)
		if spec.IsHost {
			endpointServices, endpointErr := resolveEndpointServices(snapshot.EndpointACLs, ars)
			if endpointErr != nil {
				if firstErr == nil {
					firstErr = endpointErr
				}
				continue
			}
			spec.EndpointServices = endpointServices
		}
		input := buildFirewallPolicyInput(spec, ars, snapshot, config)
		desired, err := firewall.BuildDesiredState(spec, input)
		if err != nil {
			entry := getOrCreateFirewallEntry(summary, instCfg.ID)
			entry.LastRunUnix = now.Unix()
			entry.LastError = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall instance %s: %w", instCfg.ID, err)
			}
			continue
		}
		resolvedBackend, resolveErr := firewall.ResolveBackendForInstance(spec, preflight)
		if resolveErr != nil {
			entry := getOrCreateFirewallEntry(summary, instCfg.ID)
			entry.LastRunUnix = now.Unix()
			entry.LastError = resolveErr.Error()
			if firstErr == nil {
				firstErr = resolveErr
			}
			continue
		}
		if resolvedBackend == firewall.BackendNone && instCfg.Backend != firewall.BackendNone {
			message := "configured firewall backend is unavailable; rules were not applied"
			d.logWarn("firewall", "backend_unavailable", map[string]any{
				"instance": instCfg.ID, "configured_backend": instCfg.Backend,
				"nft": preflight.NFTNetlink, "iptables": preflight.Iptables,
				"ip6tables": preflight.IptablesV6, "ipset": preflight.IPSet,
				"message": message,
			})
			entry := getOrCreateFirewallEntry(summary, instCfg.ID)
			entry.LastRunUnix = now.Unix()
			entry.Backend = firewall.BackendNone
			entry.LastError = message
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall instance %s: %s", instCfg.ID, message)
			}
			continue
		}

		driver, err := d.firewallDriverInstance(instCfg)
		if err != nil {
			entry := getOrCreateFirewallEntry(summary, instCfg.ID)
			entry.LastRunUnix = now.Unix()
			entry.LastError = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall driver %s: %w", instCfg.ID, err)
			}
			continue
		}
		if driver == nil {
			driver = firewall.NewDryRunDriver()
		}

		owner := firewall.Owner{
			Manager:     "photon",
			InstanceID:  firewallOwnerScope(spec),
			OwnerPrefix: instCfg.OwnerPrefix,
			Token:       firewall.OwnerToken(spec),
		}
		observed, _ := driver.ListOwned(ctx, owner)

		plan, err := driver.Plan(ctx, desired, observed)
		if err != nil {
			entry := getOrCreateFirewallEntry(summary, instCfg.ID)
			entry.LastRunUnix = now.Unix()
			entry.LastError = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall plan %s: %w", instCfg.ID, err)
			}
			continue
		}

		result, err := driver.Apply(ctx, plan, desired)
		entry := getOrCreateFirewallEntry(summary, instCfg.ID)
		entry.LastRunUnix = now.Unix()
		entry.Backend = resolvedBackend
		entry.PolicyHash = firewall.DesiredStateHash(desired)
		entry.OwnedObjects = len(firewall.DesiredObjects(desired))
		if err != nil {
			entry.LastError = err.Error()
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall apply %s: %w", instCfg.ID, err)
			}
			continue
		}
		entry.Generation = result.Generation
		entry.LastError = ""
	}

	if firstErr != nil {
		summary.LastError = firstErr.Error()
	} else {
		summary.LastError = ""
	}

	if err := d.commitFirewallReconcileResult(rev, snapshot.EndpointACLs, summary); err != nil {
		return fmt.Errorf("save firewall reconcile state: %w", err)
	}
	return firstErr
}

func getOrCreateFirewallEntry(state *firewallReconcileState, id string) *firewallInstanceReconcileStateEntry {
	if state.Instances == nil {
		state.Instances = make(map[string]*firewallInstanceReconcileStateEntry)
	}
	entry := state.Instances[id]
	if entry == nil {
		entry = &firewallInstanceReconcileStateEntry{}
		state.Instances[id] = entry
	}
	return entry
}

func (d *DaemonService) commitFirewallReconcileResult(rev uint64, endpointACLs map[string]endpointACL, summary *firewallReconcileState) error {
	if d == nil || d.StateStore == nil || summary == nil {
		return nil
	}
	snapshot, snapshotRev := d.StateStore.firewallSnapshot()
	if snapshot == nil || snapshotRev != rev {
		d.firewallDirty = true
		d.publishStateStoreRuntimeFlags()
		d.logWarn("firewall", "stale_reconcile_result", map[string]any{
			"source_revision":  rev,
			"current_revision": snapshotRev,
		})
		return nil
	}
	if firewallReconcileResultEqual(snapshot.EndpointACLs, snapshot.FirewallReconcile, endpointACLs, summary) {
		return nil
	}
	currentRev, committed := d.StateStore.commitFirewallIfRevision(rev, endpointACLs, summary)
	if !committed {
		d.firewallDirty = true
		d.publishStateStoreRuntimeFlags()
		d.logWarn("firewall", "stale_reconcile_result", map[string]any{
			"source_revision":  rev,
			"current_revision": currentRev,
		})
		return nil
	}
	return d.saveCommittedMeta()
}

func firewallReconcileResultEqual(baseACLs map[string]endpointACL, base *firewallReconcileState, nextACLs map[string]endpointACL, next *firewallReconcileState) bool {
	if !reflect.DeepEqual(baseACLs, nextACLs) {
		return false
	}
	if base == nil || next == nil {
		return base == nil && next == nil
	}
	base = cloneFirewallReconcileState(base)
	next = cloneFirewallReconcileState(next)
	base.LastRunUnix = 0
	next.LastRunUnix = 0
	for _, entry := range base.Instances {
		if entry != nil {
			entry.LastRunUnix = 0
		}
	}
	for _, entry := range next.Instances {
		if entry != nil {
			entry.LastRunUnix = 0
		}
	}
	return reflect.DeepEqual(base, next)
}

func firewallOwnerScope(spec firewall.FirewallInstanceSpec) string {
	if spec.IsHost {
		return "host"
	}
	return spec.NetNS
}

// firewallDriverInstance returns the configured firewall driver for one
// instance, or nil to fall back to dry-run.
func (d *DaemonService) firewallDriverInstance(inst FirewallInstanceConfig) (firewallDriver, error) {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil, nil
	}
	if d.firewallDriver != nil {
		return d.firewallDriver, nil
	}
	pf := firewall.PreflightProbe(context.Background())
	resolved, err := firewall.ResolveBackendForInstance(firewall.FirewallInstanceSpec{
		ID: inst.ID, Backend: inst.Backend, NativeHooks: inst.NativeHooks,
	}, pf)
	if err != nil {
		return nil, err
	}
	switch resolved {
	case firewall.BackendNFT:
		netns, err := firewallDriverNetNS(inst, d.Sync.App.Config)
		if err != nil {
			return nil, err
		}
		driver := firewall.NewNFTDriver()
		driver.NetNS = netns
		return driver, nil
	case firewall.BackendIptables:
		netns, err := firewallDriverNetNS(inst, d.Sync.App.Config)
		if err != nil {
			return nil, err
		}
		driver := firewall.NewIPTablesDriver()
		driver.NetNS = netns
		return driver, nil
	default:
		// dry-run / none
		return nil, nil
	}
}

func firewallDriverNetNS(inst FirewallInstanceConfig, config *appConfig) (string, error) {
	if inst.IsHost {
		return "", nil
	}
	if config == nil {
		return "", nil
	}
	spec, ok := config.Netns.Names[inst.NetNS]
	if !ok {
		return "", fmt.Errorf("netns %q not found", inst.NetNS)
	}
	spec = spec.Normalized()
	switch spec.Kind {
	case ipsec.NetNSHost:
		return "", nil
	case ipsec.NetNSName:
		return spec.Name, nil
	default:
		return "", fmt.Errorf("netns %q kind %q is not supported by firewall CLI drivers", inst.NetNS, spec.Kind)
	}
}

// buildFirewallPolicyInput assembles the verified derived state for the planner.
func buildFirewallPolicyInput(spec firewall.FirewallInstanceSpec, ars *routing.AuthorizedRouteSet, state *stateFile, config *appConfig) firewall.FirewallPolicyInput {
	input := firewall.FirewallPolicyInput{}
	if ars == nil || state == nil {
		return input
	}
	runtimeNetNS := firewallRuntimeNetNS(config, spec.NetNS)

	// Local assigned prefixes (AssignedTo == managed zone).
	managedZone := state.ManagedZone
	// Use AllAssignments through the shared helper: Assignments keeps only one
	// representative per prefix, so it can hide this zone's membership in a
	// shared/anycast assignment when another zone is the representative.
	input.LocalAssigned = append(input.LocalAssigned, localAssignedPrefixes(ars, managedZone)...)

	// All authorized mesh prefixes.
	for _, prefixes := range ars.Announced {
		for prefix := range prefixes {
			input.MeshAuthorized = append(input.MeshAuthorized, prefix)
		}
	}

	// Assignment prefixes (import whitelist).
	input.AssignmentPrefixes = assignmentPrefixes(ars)

	// Provider-neutral live Babel-facing interfaces.
	for _, link := range linkOutputsFromState(state) {
		if link.InterfaceName != "" &&
			link.Readiness.Interface == "ready" &&
			(link.Provider == "" || link.Provider == ipsec.ProviderStrongSwan) &&
			(link.NetNS == "" || link.NetNS == runtimeNetNS) {
			input.LiveInterfaces = append(input.LiveInterfaces, link.InterfaceName)
		}
	}

	// Upstream interfaces come only from routing instances in this firewall's
	// namespace. This keeps routing as the sole authority for veth names.
	for _, inst := range config.Routing.Instances {
		if inst.Enabled &&
			firewallRuntimeNetNS(config, inst.NetNS) == runtimeNetNS &&
			inst.Upstream != nil &&
			inst.Upstream.Enabled &&
			inst.Upstream.MeshInterface != "" {
			input.UpstreamInterfaces = append(input.UpstreamInterfaces, inst.Upstream.MeshInterface)
		}
	}

	// Forwarding policy is owned by the network namespace and shared with BIRD.
	if !spec.IsHost {
		input.Forwarding = netnsForwardingPolicy(config, spec.NetNS)
	}

	// Phase 6.3.7: derive revoked prefixes from the route authorization errors.
	// Any prefix in a revoked zone is excluded from allow sets (deny-first).
	revokedSet := make(map[string]bool)
	for _, e := range ars.Errors {
		if e.Code == "route_zone_revoked" {
			input.Revoked = append(input.Revoked, e.Prefix)
			revokedSet[e.Prefix.String()] = true
		}
	}

	// Advertised current/previous ports for host redirect. Current advertised
	// ports keep ipsec.port_mode=range usable while charon listens on stable
	// 500/4500; previous ports keep rotate grace alive during the configured
	// window.
	if spec.IsHost && state.Network != nil && state.ManagedZone.Valid() {
		now := time.Now()
		if d := nowFunc(); !d.IsZero() {
			now = d
		}
		input.AdvertisedCurrentIKEPorts, input.AdvertisedCurrentNATTPorts, input.AdvertisedPreviousIKEPorts, input.AdvertisedPreviousNATTPorts = extractIPsecRedirectPortsFromNetwork(state.Network, state.ManagedZone, now)
	}

	return input
}

func firewallRuntimeNetNS(config *appConfig, name string) string {
	if config == nil {
		return name
	}
	if spec, ok := config.Netns.Names[name]; ok {
		return routingNetNSTarget(spec)
	}
	return name
}

// extractIPsecRedirectPortsFromNetwork reads the signed ipsec/ports record from
// the managed zone's active state and returns current advertised ports plus
// previous-generation ports still within the grace window. These ports are used
// by the host firewall planner to generate DNAT/redirect rules.
func extractIPsecRedirectPortsFromNetwork(network *zone.NetworkState, managedZone zone.ZonePath, now time.Time) (currentIKE []uint16, currentNATT []uint16, previousIKE []uint16, previousNATT []uint16) {
	if network == nil || !managedZone.Valid() {
		return nil, nil, nil, nil
	}
	zs, ok := network.Zones[managedZone]
	if !ok || zs == nil {
		return nil, nil, nil, nil
	}
	record := zs.Records[ipsec.RecordKeyPorts]
	if record == nil {
		return nil, nil, nil, nil
	}
	pr, err := ipsec.ParsePortRecord(record)
	if err != nil || pr == nil {
		return nil, nil, nil, nil
	}
	if pr.Current != nil {
		if pr.Current.IKE.Advertised > 0 {
			currentIKE = append(currentIKE, pr.Current.IKE.Advertised)
		}
		if pr.Current.NATT.Advertised > 0 {
			currentNATT = append(currentNATT, pr.Current.NATT.Advertised)
		}
	}
	for _, sel := range pr.Previous {
		// Check if still within grace window.
		if sel.ValidUntil > 0 && now.Unix() > sel.ValidUntil {
			continue
		}
		if sel.IKE.Advertised > 0 {
			previousIKE = append(previousIKE, sel.IKE.Advertised)
		}
		if sel.NATT.Advertised > 0 {
			previousNATT = append(previousNATT, sel.NATT.Advertised)
		}
	}
	return currentIKE, currentNATT, previousIKE, previousNATT
}

// nowFunc returns the current time. Overridable in tests.
var nowFunc = func() time.Time { return time.Time{} }

// firewallCharonPorts returns the charon IKE/NAT-T listen ports the host
// firewall should open. These are the local listener ports, matching the
// defaults localIPsecPortRecord publishes when the config leaves them unset.
func firewallCharonPorts(config *appConfig, _ *stateFile) (uint16, uint16) {
	ike, natt := uint16(ipsec.DefaultIKEPort), uint16(ipsec.DefaultNATTPort)
	if config != nil {
		if config.IPsec.FixedIKEPort != 0 {
			ike = config.IPsec.FixedIKEPort
		}
		if config.IPsec.FixedNATTPort != 0 {
			natt = config.IPsec.FixedNATTPort
		}
	}
	return ike, natt
}

// flushFirewallReconcile runs firewall reconcile if dirty.
func (d *DaemonService) flushFirewallReconcile(ctx context.Context) bool {
	flushed, err := d.flushFirewallReconcileResult(ctx)
	if err != nil {
		d.logWarn("firewall", "reconcile_failed", map[string]any{"error": err})
	}
	return flushed
}

// flushFirewallReconcileResult is used by security-sensitive control writes
// that must not report success before the new policy reaches the backend.
func (d *DaemonService) flushFirewallReconcileResult(ctx context.Context) (bool, error) {
	if d == nil || !d.firewallDirty {
		return false, nil
	}
	d.firewallDirty = false
	d.noteReconcileFlush("firewall")
	reconcileCtx, cancel := boundedReconcileContext(ctx)
	defer cancel()
	err := d.reconcileFirewall(reconcileCtx)
	return true, err
}

// recoverFirewallOnStart triggers an initial firewall reconcile at daemon start.
func (d *DaemonService) recoverFirewallOnStart(ctx context.Context) {
	if d == nil {
		return
	}
	d.firewallDirty = true
	d.flushFirewallReconcile(ctx)
}
