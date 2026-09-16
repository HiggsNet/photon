package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing"
)

const defaultFirewallReconcileInterval = 30 * time.Second

func (d *Daemon) firewallReconcileInterval() time.Duration {
	if d == nil || d.App == nil || d.App.Config == nil || len(d.App.Config.Firewall.ManagedInstances()) == 0 {
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
	instances := config.Firewall.ManagedInstances()
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
		spec := instCfg.Spec()
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
		input := photonlinux.BuildFirewallPolicyInput(spec, ars, common.State, buildLinkOutputs(links, ipsecReconcile), config.Netns, config.Routing.Instances, now)
		desired, err := firewall.BuildDesiredState(spec, input)
		if err != nil {
			entry := getOrCreateFirewallEntry(summary, instCfg.ID)
			entry.LastRunUnix = now.Unix()
			entry.LastFailure = err
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
			entry.LastFailure = resolveErr
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
			entry.LastFailure = errors.New(message)
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
			entry.LastFailure = err
			if firstErr == nil {
				firstErr = fmt.Errorf("firewall apply %s: %w", instCfg.ID, err)
			}
			continue
		}
		entry.Generation = result.Generation
		entry.LastFailure = nil
	}

	summary.LastFailure = firstErr

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
