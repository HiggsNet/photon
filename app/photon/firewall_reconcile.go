package main

import (
	"context"
	"fmt"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

const defaultFirewallReconcileInterval = 30 * time.Second

const (
	defaultCharonIKEPort  uint16 = 500
	defaultCharonNATTPort uint16 = 4500
)

func (d *Daemon) firewallReconcileInterval() time.Duration {
	if d == nil || d.App == nil || d.App.Config == nil || len(firewallInstancesEnabled(d.App.Config)) == 0 {
		return 0
	}
	return defaultFirewallReconcileInterval
}

func nextFirewallReconcileTime(now time.Time, interval time.Duration) time.Time {
	if interval <= 0 {
		return time.Time{}
	}
	return now.Add(interval)
}

// reconcileFirewall is the daemon single-writer firewall reconcile entry point.
// It computes the desired state from verified active state + local config,
// diffs against observed owned objects, and applies the plan via the driver.
// The default driver is DryRunDriver; real nft/iptables drivers are added later.
func (d *Daemon) reconcileFirewall(ctx context.Context) error {
	if d == nil || d.App == nil || d.App.Config == nil {
		return nil
	}
	common := d.State.Common.ReadView()
	runtime := d.State.ReadLinux()
	if common.State == nil || runtime == nil {
		return nil
	}
	links, ipsecReconcile := d.linuxObservation.ipsecSnapshot()
	rev := uint64(common.Revision)
	config := d.App.Config
	instances := firewallInstancesEnabled(config)
	if len(instances) == 0 {
		return nil
	}
	if common.State.ManagedZone.IsRoot() || !common.State.ManagedZone.Valid() {
		return nil
	}

	now := d.now()
	summary := &firewall.FirewallObservation{
		Instances:   make(map[string]*firewall.FirewallInstanceObservation),
		LastRunUnix: now.Unix(),
	}

	// Build authorized route set for prefix inputs.
	ars, err := routing.BuildAuthorizedRouteSet(common.State.Network, now)
	if err != nil {
		summary.LastFailure = err
		d.publishFirewallObservation(rev, summary)
		return fmt.Errorf("firewall build authorized route set: %w", err)
	}

	var firstErr error
	for _, instCfg := range instances {
		listenAddrs := instCfg.ListenAddrs
		spec := firewallInstanceSpecFromConfig(instCfg, listenAddrs, defaultCharonIKEPort, defaultCharonNATTPort)
		if spec.IsHost {
			endpointServices, endpointErr := resolveEndpointServices(runtime.EndpointACLs, ars)
			if endpointErr != nil {
				if firstErr == nil {
					firstErr = endpointErr
				}
				continue
			}
			spec.EndpointServices = endpointServices
		}
		input := buildFirewallPolicyInput(spec, ars, common.State, runtime, links, ipsecReconcile, config, now)
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
		resolvedBackend, preflight, resolveErr := d.linuxDriver.ResolveFirewallBackend(ctx, spec)
		summary.Backend = preflight.Backend
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

		owner := firewall.Owner{
			Manager:     "photon",
			InstanceID:  firewallOwnerScope(spec),
			OwnerPrefix: instCfg.OwnerPrefix,
			Token:       firewall.OwnerToken(spec),
		}
		result, err := d.linuxDriver.ApplyFirewall(ctx, spec, resolvedBackend, owner, desired)
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
		summary.LastFailure = firstErr
	} else {
		summary.LastFailure = nil
	}

	d.publishFirewallObservation(rev, summary)
	return firstErr
}

func getOrCreateFirewallEntry(state *firewall.FirewallObservation, id string) *firewall.FirewallInstanceObservation {
	if state.Instances == nil {
		state.Instances = make(map[string]*firewall.FirewallInstanceObservation)
	}
	entry := state.Instances[id]
	if entry == nil {
		entry = &firewall.FirewallInstanceObservation{}
		state.Instances[id] = entry
	}
	return entry
}

func (d *Daemon) publishFirewallObservation(rev uint64, summary *firewall.FirewallObservation) {
	if d == nil || d.State == nil || summary == nil {
		return
	}
	currentRev := uint64(d.State.Common.VerifiedRevision())
	if currentRev != rev {
		d.firewallDirty = true
		d.logWarn("firewall", "stale_reconcile_result", map[string]any{
			"source_revision":  rev,
			"current_revision": currentRev,
		})
		return
	}
	d.linuxObservation.replaceFirewall(summary)
}

func firewallOwnerScope(spec firewall.FirewallInstanceSpec) string {
	if spec.IsHost {
		return "host"
	}
	return spec.NetNS
}

// buildFirewallPolicyInput assembles the verified derived state for the planner.
func buildFirewallPolicyInput(spec firewall.FirewallInstanceSpec, ars *routing.AuthorizedRouteSet, verified *corestate.VerifiedState, runtime *photonlinux.LinuxState, links map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, config *appConfig, now time.Time) firewall.FirewallPolicyInput {
	input := firewall.FirewallPolicyInput{}
	if ars == nil || verified == nil || runtime == nil {
		return input
	}
	runtimeNetNS := firewallRuntimeNetNS(config, spec.NetNS)

	// Local assigned prefixes (AssignedTo == managed zone).
	managedZone := verified.ManagedZone
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
	for _, link := range buildLinkOutputs(links, reconcile) {
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
	if spec.IsHost && verified.Network != nil && verified.ManagedZone.Valid() {
		input.AdvertisedCurrentIKEPorts, input.AdvertisedCurrentNATTPorts, input.AdvertisedPreviousIKEPorts, input.AdvertisedPreviousNATTPorts = extractIPsecRedirectPortsFromNetwork(verified.Network, verified.ManagedZone, now)
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

// flushFirewallReconcile runs firewall reconcile if dirty.
func (d *Daemon) flushFirewallReconcile(ctx context.Context) bool {
	flushed, err := d.flushFirewallReconcileResult(ctx)
	if err != nil {
		d.logWarn("firewall", "reconcile_failed", map[string]any{"error": err})
	}
	return flushed
}

// flushFirewallReconcileResult is used by security-sensitive control writes
// that must not report success before the new policy reaches the backend.
func (d *Daemon) flushFirewallReconcileResult(ctx context.Context) (bool, error) {
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
func (d *Daemon) recoverFirewallOnStart(ctx context.Context) {
	if d == nil {
		return
	}
	d.firewallDirty = true
	d.flushFirewallReconcile(ctx)
}
