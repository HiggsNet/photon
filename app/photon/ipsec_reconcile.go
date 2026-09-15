package main

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func (d *DaemonService) reconcileIPsecLinks(ctx context.Context) error {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil {
		return nil
	}
	snapshot, rev := d.StateStore.ipsecSnapshot()
	if snapshot == nil {
		return nil
	}
	groups := append([]ipsec.LinkGroupSpec(nil), d.Sync.App.Config.IPsec.LinkGroups...)
	if snapshot.ManagedZone.IsRoot() || !snapshot.ManagedZone.Valid() {
		return nil
	}
	now := d.Sync.now()
	dnsResolver := d.ipsecReconcileDNSResolver()
	plan := ipsec.LinkPlan{}
	if len(groups) > 0 {
		var err error
		plan, err = ipsec.PlanTransportLinks(ctx, snapshot.Network, snapshot.ManagedZone, groups, ipsec.LinkPlannerOptions{
			Now:                 now,
			DNSResolver:         dnsResolver,
			ContactPointQuality: d.buildIPsecContactPointQuality(snapshot, now),
			ExcludedPeers:       peerLifecycleExcludedPeers(snapshot, now, d.Sync.App.Config.PeerLifecycle),
		})
		if err != nil {
			d.recordIPsecReconcileError(rev, now.Unix(), err)
			return err
		}
		plan.Desired = injectIPsecKeyMaterial(snapshot, plan.Desired)
	}
	ipsecDriver, xfrmDriver := d.ipsecDrivers()
	sas, err := ipsecDriver.ListSAs(ctx)
	if err != nil {
		d.recordIPsecReconcileError(rev, now.Unix(), err)
		return fmt.Errorf("list ipsec sas: %w", err)
	}
	instances := linkInstancesToIPsec(snapshot.LinkInstances)
	forceUpdates, err := localAnnounceDNSForceUpdates(ctx, d.Sync.App.Config.IPsec, plan.Desired, instances, sas, dnsResolver)
	if err != nil {
		d.logWarn("ipsec", "local_announce_dns_check_failed", map[string]any{"error": err.Error()})
	}
	d.logDebug("ipsec", "reconcile_observed", map[string]any{
		"managed_zone": snapshot.ManagedZone.String(),
		"groups":       len(groups),
		"desired":      len(plan.Desired),
		"instances":    len(instances),
		"sas":          len(sas),
	})
	xfrmObservations := d.observeXFRMLinksForReconcile(ctx, xfrmDriver, plan.Desired, instances, groups)
	sas, missingXFRMLinks, err := d.filterSAsWithMissingXFRMLinks(ctx, xfrmDriver, plan.Desired, instances, sas, xfrmObservations)
	if err != nil {
		d.recordIPsecReconcileError(rev, now.Unix(), err)
		return fmt.Errorf("inspect xfrm links: %w", err)
	}
	markMissingXFRMLinkInstances(instances, missingXFRMLinks, now)
	result := ipsec.ReconcileLinkInstances(ipsec.ReconcileInputs{
		Desired:               plan.Desired,
		Instances:             instances,
		SAs:                   sas,
		Now:                   now,
		Revoked:               revokedLinkPeers(snapshot, now),
		Roles:                 plan.Roles,
		GroupSpecs:            groupSpecMap(groups),
		GroupBackoff:          groupBackoffMap(groups),
		GroupRotateRetention:  groupRotateRetentionMap(groups),
		RotateActivationReady: d.ipsecRotateActivationReady(),
		RotateCutoverReady:    d.ipsecRotateCutoverReady(),
		PrepareStandby:        d.ipsecPrepareStandby,
		TakeoverNotBefore:     d.ipsecTakeoverNotBefore,
		ForceUpdates:          forceUpdates,
	})
	result.Actions = append(result.Actions, ipsec.PlanDuplicateSAGC(plan.Desired, result.Instances, sas, plan.Roles)...)
	diagnosticPrefixes := d.localIPv6DiagnosticPrefixes(snapshot, now)
	for _, action := range result.Actions {
		d.logDebug("ipsec", "reconcile_action", ipsecReconcileActionLogFields(action))
		switch action.Action {
		case ipsec.ReconcileActionCleanupDuplicateSA:
			if _, err := ipsec.ApplyReconcileAction(ctx, ipsecDriver, xfrmDriver, action, ipsec.NetNSSpec{}); err != nil {
				d.logWarn("ipsec", "duplicate_sa_gc_failed", map[string]any{
					"sa_unique_id": action.SAUniqueID,
					"error":        err,
				})
			}
		case ipsec.ReconcileActionCreate, ipsec.ReconcileActionUpdate, ipsec.ReconcileActionRepair, ipsec.ReconcileActionPrepareStandby,
			ipsec.ReconcileActionAdopt, ipsec.ReconcileActionTeardown, ipsec.ReconcileActionPrepareRotate, ipsec.ReconcileActionInitiateRotate,
			ipsec.ReconcileActionCommitRotate, ipsec.ReconcileActionRollbackRotate, ipsec.ReconcileActionCleanupRotate:
			netns := netnsForAction(action, groups)
			if _, err := ipsec.ApplyReconcileAction(ctx, ipsecDriver, xfrmDriver, action, netns); err != nil {
				markIPsecActionFailed(result.Instances, action, groupBackoffPolicy(action, groups), now, err)
				if saveErr := d.commitIPsecReconcileResult(rev, snapshot, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, err.Error()); saveErr != nil {
					return fmt.Errorf("save failed ipsec reconcile state after apply error %q: %w", err.Error(), saveErr)
				}
				return err
			}
			if shouldAssignIPsecDiagnosticAddresses(action) {
				if err := d.assignIPsecDiagnosticAddresses(ctx, xfrmDriver, *action.Spec, diagnosticPrefixes); err != nil {
					markIPsecActionFailed(result.Instances, action, groupBackoffPolicy(action, groups), now, err)
					if saveErr := d.commitIPsecReconcileResult(rev, snapshot, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, err.Error()); saveErr != nil {
						return fmt.Errorf("save failed ipsec reconcile state after diagnostic address error %q: %w", err.Error(), saveErr)
					}
					return err
				}
			}
			markIPsecActionSucceeded(result.Instances, action, now)
		}
	}
	if err := d.maintainExistingXFRMInterfaces(ctx, xfrmDriver, plan.Desired, result.Instances, result.Actions, groups, diagnosticPrefixes, xfrmObservations); err != nil {
		if saveErr := d.commitIPsecReconcileResult(rev, snapshot, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, err.Error()); saveErr != nil {
			return fmt.Errorf("save failed ipsec reconcile state after xfrm maintenance error %q: %w", err.Error(), saveErr)
		}
		return err
	}
	if err := d.commitIPsecReconcileResult(rev, snapshot, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, ""); err != nil {
		return fmt.Errorf("save ipsec reconcile state: %w", err)
	}
	return nil
}

func (d *DaemonService) ipsecReconcileDNSResolver() ipsec.DNSResolver {
	if d != nil && d.ipsecDNSResolver != nil {
		return d.ipsecDNSResolver
	}
	now := time.Now
	if d != nil && d.Sync != nil {
		now = d.Sync.now
	}
	resolver := ipsec.NewDNSFamilyHoldDownResolver(net.DefaultResolver, ipsec.DNSFamilyHoldDownOptions{Now: now})
	if d != nil {
		d.ipsecDNSResolver = resolver
	}
	return resolver
}

type ipLookupResolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// localAnnounceDNSForceUpdates detects the asymmetric case where this node is
// the initiator and its own advertised DNS address moved while StrongSwan still
// reports the old SA as established. It uses the live SA endpoint and traffic
// counters instead of persisting a second DNS snapshot.
func localAnnounceDNSForceUpdates(ctx context.Context, config ipsecConfig, desired []ipsec.TransportLinkSpec, instances map[string]ipsec.LinkInstance, sas []ipsec.SAState, resolver ipLookupResolver) (map[string]string, error) {
	if len(config.AnnounceDNS) == 0 || config.AnnounceDNSReconnectAfter <= 0 || resolver == nil {
		return nil, nil
	}
	resolved := make(map[netip.Addr]struct{})
	for _, host := range config.AnnounceDNS {
		addresses, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			// A partial answer set is unsafe: the current SA may correspond to
			// the name that failed, so force no reconnect this round.
			return nil, fmt.Errorf("resolve local announce DNS %q: %w", host, err)
		}
		for _, address := range addresses {
			if address.IP == nil {
				continue
			}
			if addr, ok := netip.AddrFromSlice(address.IP); ok {
				resolved[addr.Unmap()] = struct{}{}
			}
		}
	}
	if len(resolved) == 0 {
		return nil, nil
	}

	threshold := uint64(config.AnnounceDNSReconnectAfter / time.Second)
	updates := make(map[string]string)
	for _, spec := range desired {
		if !ipsec.IsActiveInitiatorRole(spec.InitiatorRole) {
			continue
		}
		id := ipsec.LinkInstanceID(spec)
		instance, ok := instances[id]
		if !ok {
			continue
		}
		sa := localDNSInstanceSA(sas, instance)
		if !sa.Established || !sa.InitiatorKnown || !sa.Initiator || !sa.InboundKnown || !saInboundIdleFor(sa, threshold) {
			continue
		}
		localAddr, ok := endpointAddr(sa.LocalEndpoint)
		if !ok {
			continue
		}
		if _, present := resolved[localAddr]; present {
			continue
		}
		compatible := false
		for address := range resolved {
			if address.Is4() == localAddr.Is4() && addressScope(address) == addressScope(localAddr) {
				compatible = true
				break
			}
		}
		if compatible {
			updates[id] = "local announce DNS changed after inbound idle"
		}
	}
	if len(updates) == 0 {
		return nil, nil
	}
	return updates, nil
}

func localDNSInstanceSA(sas []ipsec.SAState, instance ipsec.LinkInstance) ipsec.SAState {
	for _, sa := range sas {
		if sa.Name == instance.IKEName || sa.ChildSA == instance.ChildSAName || (instance.XFRMIfID != 0 && sa.XFRMIfID == instance.XFRMIfID) {
			return sa
		}
	}
	return ipsec.SAState{}
}

func saInboundIdleFor(sa ipsec.SAState, threshold uint64) bool {
	if threshold == 0 {
		return false
	}
	if sa.InboundPackets == 0 {
		return max(sa.ChildAgeSeconds, sa.IKEAgeSeconds) >= threshold
	}
	return sa.InboundIdleSecs >= threshold
}

func endpointAddr(endpoint string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = strings.Trim(endpoint, "[]")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.IsUnspecified() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func addressScope(addr netip.Addr) string {
	if addr.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(addr) {
		return "private"
	}
	return "public"
}

type xfrmMaintenanceItem struct {
	id        string
	candidate ipsec.TransportLinkSpec
	state     ipsec.XFRMLinkState
	matches   bool
	reason    string
}

type xfrmReconcileObservations struct {
	links map[string]ipsec.XFRMLinkState
}

func (d *DaemonService) observeXFRMLinksForReconcile(ctx context.Context, xfrmDriver ipsec.XFRMDriver, desired []ipsec.TransportLinkSpec, instances map[string]ipsec.LinkInstance, groups []ipsec.LinkGroupSpec) *xfrmReconcileObservations {
	inspector, ok := xfrmDriver.(ipsec.XFRMLinkBatchInspector)
	if !ok || len(desired) == 0 {
		return nil
	}

	seen := make(map[string]struct{})
	specs := make([]ipsec.TransportLinkSpec, 0, len(desired)*2)
	appendSpec := func(spec ipsec.TransportLinkSpec) {
		key := xfrmObservationKey(spec)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		specs = append(specs, spec)
	}
	for _, spec := range desired {
		id := ipsec.LinkInstanceID(spec)
		inst, hasInstance := instances[id]
		for _, candidate := range xfrmLinkInspectCandidates(spec, inst) {
			appendSpec(candidate)
		}
		if hasInstance && shouldMaintainXFRMInstance(inst) {
			appendSpec(xfrmMaintenanceSpec(spec, inst, groups))
		}
	}

	states, err := inspector.InspectLinks(ctx, specs)
	if err != nil {
		d.logWarn("ipsec", "xfrm_batch_observe_fallback", map[string]any{
			"candidates": len(specs),
			"error":      err.Error(),
		})
		return nil
	}
	if len(states) != len(specs) {
		d.logWarn("ipsec", "xfrm_batch_observe_fallback", map[string]any{
			"candidates": len(specs),
			"observed":   len(states),
			"error":      "batch result length mismatch",
		})
		return nil
	}
	observations := &xfrmReconcileObservations{links: make(map[string]ipsec.XFRMLinkState, len(specs))}
	for i, spec := range specs {
		observations.links[xfrmObservationKey(spec)] = states[i]
	}
	return observations
}

func inspectXFRMLinkWithObservations(ctx context.Context, inspector ipsec.XFRMLinkInspector, observed *xfrmReconcileObservations, spec ipsec.TransportLinkSpec) (ipsec.XFRMLinkState, error) {
	if observed != nil {
		if state, ok := observed.links[xfrmObservationKey(spec)]; ok {
			return state, nil
		}
	}
	return inspector.InspectLink(ctx, spec)
}

func xfrmObservationKey(spec ipsec.TransportLinkSpec) string {
	return spec.NetNS + "\x00" + spec.InterfaceName
}

func (d *DaemonService) maintainExistingXFRMInterfaces(ctx context.Context, xfrmDriver ipsec.XFRMDriver, desired []ipsec.TransportLinkSpec, instances map[string]ipsec.LinkInstance, actions []ipsec.ReconcileAction, groups []ipsec.LinkGroupSpec, diagnosticPrefixes []netip.Prefix, observed ...*xfrmReconcileObservations) error {
	driver, ok := xfrmDriver.(interface {
		ipsec.XFRMDriver
		ipsec.XFRMLinkInspector
	})
	if !ok {
		d.logDebug("ipsec", "xfrm_maintenance_skip_driver", map[string]any{
			"reason": "xfrm driver does not implement link inspection",
		})
		return nil
	}
	if len(desired) == 0 || len(instances) == 0 {
		d.logDebug("ipsec", "xfrm_maintenance_skip_empty", map[string]any{
			"desired":   len(desired),
			"instances": len(instances),
		})
		return nil
	}
	activeActions := make(map[string]struct{})
	for _, action := range actions {
		if !ipsecActionAppliesXFRM(action.Action) {
			continue
		}
		if id := actionInstanceID(action); id != "" {
			activeActions[id] = struct{}{}
		}
	}
	d.logDebug("ipsec", "xfrm_maintenance_begin", map[string]any{
		"desired":        len(desired),
		"instances":      len(instances),
		"active_actions": len(activeActions),
	})
	var observations *xfrmReconcileObservations
	if len(observed) > 0 {
		observations = observed[0]
	}
	var items []xfrmMaintenanceItem
	for _, spec := range desired {
		id := ipsec.LinkInstanceID(spec)
		if _, ok := activeActions[id]; ok {
			continue
		}
		inst, ok := instances[id]
		if !ok || !shouldMaintainXFRMInstance(inst) {
			continue
		}
		candidate := xfrmMaintenanceSpec(spec, inst, groups)
		state, err := inspectXFRMLinkWithObservations(ctx, driver, observations, candidate)
		if err != nil {
			return fmt.Errorf("inspect xfrm interface %q: %w", candidate.InterfaceName, err)
		}
		matches, reason := d.xfrmLinkStateMatchReason(state, candidate)
		d.logDebug("ipsec", "xfrm_runtime_observed", xfrmLinkObservationLogFields("runtime_ensure", id, "active", candidate, state, matches, reason))
		if !state.NamespaceExists || !state.InterfaceExists {
			d.logDebug("ipsec", "xfrm_maintenance_skip_missing", map[string]any{
				"instance_id": id,
				"peer":        candidate.PeerZone,
				"interface":   candidate.InterfaceName,
				"netns":       candidate.NetNS,
				"runtime":     "active",
			})
			continue
		}
		if matches {
			d.logDebug("ipsec", "xfrm_maintenance_skip_matched", map[string]any{
				"instance_id": id,
				"peer":        candidate.PeerZone,
				"interface":   candidate.InterfaceName,
				"netns":       candidate.NetNS,
				"runtime":     "active",
				"reason":      reason,
			})
		}
		items = append(items, xfrmMaintenanceItem{id: id, candidate: candidate, state: state, matches: matches, reason: reason})
	}

	var repairs []ipsec.XFRMObservedInterface
	for _, item := range items {
		if !item.matches {
			repairs = append(repairs, ipsec.XFRMObservedInterface{Spec: item.candidate, State: item.state})
		}
	}
	if len(repairs) > 0 {
		if ensurer, ok := xfrmDriver.(ipsec.XFRMObservedEnsurer); ok && observations != nil {
			if err := ensurer.EnsureObservedInterfaces(ctx, repairs); err != nil {
				return fmt.Errorf("maintain observed xfrm interfaces: %w", err)
			}
		} else {
			for _, repair := range repairs {
				if err := driver.EnsureInterface(ctx, repair.Spec); err != nil {
					return fmt.Errorf("maintain xfrm interface %q: %w", repair.Spec.InterfaceName, err)
				}
			}
		}
	}

	for _, item := range items {
		candidate := item.candidate
		if candidate.LocalTunnelAddr.IsValid() && !xfrmStateHasAddress(item.state, candidate.LocalTunnelAddr) {
			if err := driver.AssignAddress(ctx, candidate, tunnelAddressPrefixForDaemon(candidate.LocalTunnelAddr)); err != nil {
				return fmt.Errorf("maintain xfrm address %q: %w", candidate.InterfaceName, err)
			}
		}
		stateForDiagnostics := &item.state
		if !item.matches {
			stateForDiagnostics = nil
		}
		if err := d.assignIPsecDiagnosticAddressesIfMissing(ctx, xfrmDriver, candidate, diagnosticPrefixes, stateForDiagnostics); err != nil {
			return fmt.Errorf("maintain xfrm diagnostic address %q: %w", candidate.InterfaceName, err)
		}
		d.logDebug("ipsec", "xfrm_maintenance_applied", map[string]any{
			"instance_id": item.id,
			"peer":        candidate.PeerZone,
			"interface":   candidate.InterfaceName,
			"netns":       candidate.NetNS,
			"runtime":     "active",
			"reason":      item.reason,
		})
	}
	return nil
}

func shouldAssignIPsecDiagnosticAddresses(action ipsec.ReconcileAction) bool {
	if action.Spec == nil {
		return false
	}
	switch action.Action {
	case ipsec.ReconcileActionCreate, ipsec.ReconcileActionUpdate, ipsec.ReconcileActionRepair, ipsec.ReconcileActionPrepareStandby, ipsec.ReconcileActionPrepareRotate:
		return true
	default:
		return false
	}
}

func (d *DaemonService) localIPv6DiagnosticPrefixes(state *stateFile, now time.Time) []netip.Prefix {
	if d == nil || d.Sync == nil || d.Sync.App == nil || d.Sync.App.Config == nil || state == nil || state.Network == nil {
		return nil
	}
	if !ipamAutoAnnounceEnabled(d.Sync.App.Config.IPAM) {
		return nil
	}
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, now)
	if err != nil {
		d.logWarn("ipsec", "diagnostic_prefixes_unavailable", map[string]any{"error": err.Error()})
		return nil
	}
	prefixes := autoAnnounceAssignedPrefixes(ars, state.ManagedZone, d.Sync.App.Config.IPAM)
	out := prefixes[:0]
	for _, prefix := range prefixes {
		if prefix.Addr().Is6() && prefix.Bits() == 64 {
			out = append(out, prefix.Masked())
		}
	}
	return out
}

func (d *DaemonService) assignIPsecDiagnosticAddresses(ctx context.Context, xfrmDriver ipsec.XFRMDriver, spec ipsec.TransportLinkSpec, prefixes []netip.Prefix) error {
	return d.assignIPsecDiagnosticAddressesIfMissing(ctx, xfrmDriver, spec, prefixes, nil)
}

func (d *DaemonService) assignIPsecDiagnosticAddressesIfMissing(ctx context.Context, xfrmDriver ipsec.XFRMDriver, spec ipsec.TransportLinkSpec, prefixes []netip.Prefix, observed *ipsec.XFRMLinkState) error {
	if len(prefixes) == 0 {
		return nil
	}
	assigner, ok := xfrmDriver.(ipsec.XFRMExtraAddressAssigner)
	if !ok {
		return nil
	}
	suffix, ok := ipsecDiagnosticSuffix(spec)
	if !ok {
		return nil
	}
	for _, prefix := range prefixes {
		addr, ok := diagnosticAddressForPrefix(prefix, suffix)
		if !ok {
			continue
		}
		if observed != nil && xfrmStateHasAddress(*observed, addr) {
			continue
		}
		if err := assigner.AssignExtraAddress(ctx, spec, netip.PrefixFrom(addr, 128).String()); err != nil {
			return err
		}
		d.logDebug("ipsec", "diagnostic_address_assigned", map[string]any{
			"interface": spec.InterfaceName,
			"netns":     spec.NetNS,
			"address":   addr.String(),
			"prefix":    prefix.String(),
			"path_key":  spec.PathKey,
		})
	}
	return nil
}

func xfrmStateHasAddress(state ipsec.XFRMLinkState, address netip.Addr) bool {
	for _, prefix := range state.Addresses {
		if prefix.Addr() == address {
			return true
		}
	}
	return false
}

func ipsecDiagnosticSuffix(spec ipsec.TransportLinkSpec) (uint16, bool) {
	pathKey := strings.ToLower(spec.PathKey)
	switch {
	case strings.Contains(pathKey, "ipv4"):
		return 0xfff4, true
	case strings.Contains(pathKey, "ipv6"):
		return 0xfff6, true
	}
	if ip := net.ParseIP(spec.LocalAddress); ip != nil {
		if ip.To4() != nil {
			return 0xfff4, true
		}
		return 0xfff6, true
	}
	return 0, false
}

func diagnosticAddressForPrefix(prefix netip.Prefix, suffix uint16) (netip.Addr, bool) {
	prefix = prefix.Masked()
	if !prefix.Addr().Is6() || prefix.Bits() != 64 {
		return netip.Addr{}, false
	}
	raw := prefix.Addr().As16()
	raw[14] = byte(suffix >> 8)
	raw[15] = byte(suffix)
	return netip.AddrFrom16(raw), true
}

func ipsecActionAppliesXFRM(action string) bool {
	switch action {
	case ipsec.ReconcileActionCreate,
		ipsec.ReconcileActionUpdate,
		ipsec.ReconcileActionRepair,
		ipsec.ReconcileActionPrepareStandby,
		ipsec.ReconcileActionAdopt,
		ipsec.ReconcileActionTeardown,
		ipsec.ReconcileActionPrepareRotate,
		ipsec.ReconcileActionCommitRotate,
		ipsec.ReconcileActionRollbackRotate,
		ipsec.ReconcileActionCleanupRotate:
		return true
	default:
		return false
	}
}

func shouldMaintainXFRMInstance(inst ipsec.LinkInstance) bool {
	if inst.InterfaceName == "" || inst.XFRMIfID == 0 {
		return false
	}
	switch inst.ActualState {
	case ipsec.LinkStateUp, ipsec.LinkStateConnecting, ipsec.LinkStateConfiguring:
		return true
	default:
		return false
	}
}

func xfrmMaintenanceSpec(spec ipsec.TransportLinkSpec, inst ipsec.LinkInstance, groups []ipsec.LinkGroupSpec) ipsec.TransportLinkSpec {
	out := runtimeSpecForInstanceGeneration(spec, inst, groups)
	if inst.InterfaceName != "" {
		out.InterfaceName = inst.InterfaceName
	}
	if inst.XFRMIfID != 0 {
		out.XFRMIfID = inst.XFRMIfID
	}
	return out
}

func runtimeSpecForInstanceGeneration(spec ipsec.TransportLinkSpec, inst ipsec.LinkInstance, groups []ipsec.LinkGroupSpec) ipsec.TransportLinkSpec {
	generation := inst.RemoteGeneration
	if generation == 0 {
		generation = spec.Generation
	}
	out, err := ipsec.RuntimeSpecForPortGeneration(spec, linkGroupForSpec(spec, groups), generation)
	if err != nil {
		return spec
	}
	return out
}

func tunnelAddressPrefixForDaemon(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	bits := 32
	if addr.Is6() {
		bits = 128
		if addr.IsLinkLocalUnicast() {
			bits = 64
		}
	}
	return netip.PrefixFrom(addr, bits).String()
}

func (d *DaemonService) ipsecRotateCutoverReady() map[string]bool {
	if d == nil || d.health == nil {
		return nil
	}
	return d.health.RotateCutoverReadiness()
}

func (d *DaemonService) ipsecRotateActivationReady() map[string]bool {
	if d == nil || d.health == nil {
		return nil
	}
	return d.health.RotateActivationReadiness()
}

func ipsecReconcileActionLogFields(action ipsec.ReconcileAction) map[string]any {
	fields := map[string]any{
		"action": action.Action,
		"reason": action.Reason,
	}
	if id := actionInstanceID(action); id != "" {
		fields["instance_id"] = id
	}
	if action.Spec != nil {
		fields["peer"] = action.Spec.PeerZone.String()
		fields["group"] = action.Spec.OverlayID
		fields["transport_id"] = action.Spec.TransportID
		fields["remote_generation"] = action.Spec.Generation
		fields["interface"] = action.Spec.InterfaceName
		if len(action.Spec.ContactPoints) > 0 {
			cp := action.Spec.ContactPoints[0]
			fields["endpoint_address"] = firstNonEmpty(cp.Address, cp.Host)
			fields["endpoint_ike_port"] = cp.IKEPort
			fields["endpoint_natt_port"] = cp.NATTPort
			fields["endpoint_current"] = cp.Current
			fields["endpoint_source"] = cp.Source
		}
	}
	if action.Instance != nil {
		fields["peer"] = action.Instance.PeerZone.String()
		fields["group"] = action.Instance.GroupID
		fields["transport_id"] = action.Instance.TransportID
		fields["remote_generation"] = action.Instance.RemoteGeneration
		fields["staged_generation"] = action.Instance.StagedGeneration
		fields["rotate_phase"] = action.Instance.RotatePhase
		fields["rotate_deadline"] = action.Instance.RotateDeadline
		fields["staged_attempt_count"] = action.Instance.StagedAttemptCount
		fields["staged_next_attempt"] = action.Instance.StagedNextAttempt
		fields["ike_name"] = action.Instance.IKEName
		fields["staged_ike"] = action.Instance.StagedIKEName
		fields["interface"] = action.Instance.InterfaceName
		fields["staged_interface"] = action.Instance.StagedInterfaceName
	}
	if action.SAUniqueID != 0 {
		fields["sa_unique_id"] = action.SAUniqueID
	}
	return fields
}

func (d *DaemonService) filterSAsWithMissingXFRMLinks(ctx context.Context, xfrmDriver ipsec.XFRMDriver, desired []ipsec.TransportLinkSpec, instances map[string]ipsec.LinkInstance, sas []ipsec.SAState, observed *xfrmReconcileObservations) ([]ipsec.SAState, map[string]ipsec.TransportLinkSpec, error) {
	if inspector, ok := xfrmDriver.(ipsec.XFRMLinkInspector); ok && len(instances) > 0 {
		return d.filterSAsWithMissingRuntimeLinks(ctx, inspector, desired, instances, sas, observed)
	}
	filter, ok := xfrmDriver.(ipsec.XFRMSAFilter)
	if !ok {
		return sas, nil, nil
	}
	filtered, missing, err := filter.FilterSAsWithMissingLinks(ctx, desired, sas)
	if err != nil {
		return nil, nil, err
	}
	for _, spec := range missing {
		d.logDebug("ipsec", "xfrm_link_missing", map[string]any{
			"instance_id": ipsec.LinkInstanceID(spec),
			"peer":        spec.PeerZone,
			"interface":   spec.InterfaceName,
			"netns":       spec.NetNS,
		})
	}
	return filtered, missing, nil
}

func (d *DaemonService) filterSAsWithMissingRuntimeLinks(ctx context.Context, inspector ipsec.XFRMLinkInspector, desired []ipsec.TransportLinkSpec, instances map[string]ipsec.LinkInstance, sas []ipsec.SAState, observed *xfrmReconcileObservations) ([]ipsec.SAState, map[string]ipsec.TransportLinkSpec, error) {
	if len(desired) == 0 {
		return sas, nil, nil
	}
	missing := make(map[string]ipsec.TransportLinkSpec)
	missingCandidates := make(map[string][]ipsec.TransportLinkSpec)
	for _, spec := range desired {
		id := ipsec.LinkInstanceID(spec)
		candidates := xfrmLinkInspectCandidates(spec, instances[id])
		found := false
		for _, candidate := range candidates {
			state, err := inspectXFRMLinkWithObservations(ctx, inspector, observed, candidate)
			if err != nil {
				return nil, nil, err
			}
			matches, reason := d.xfrmLinkStateMatchReason(state, candidate)
			d.logDebug("ipsec", "xfrm_runtime_observed", xfrmLinkObservationLogFields("pre_reconcile_filter", id, xfrmCandidateRuntime(spec, candidate, instances[id]), candidate, state, matches, reason))
			if matches {
				found = true
				break
			}
		}
		if found {
			continue
		}
		missing[id] = spec
		missingCandidates[id] = candidates
		d.logDebug("ipsec", "xfrm_link_missing", map[string]any{
			"instance_id": id,
			"peer":        spec.PeerZone,
			"interface":   spec.InterfaceName,
			"netns":       spec.NetNS,
			"reason":      "no_candidate_matched",
			"candidates":  len(candidates),
		})
	}
	if len(missing) == 0 || len(sas) == 0 {
		return sas, missing, nil
	}
	filtered := sas[:0]
	for _, sa := range sas {
		if saMatchesMissingXFRMCandidate(sa, missingCandidates) {
			continue
		}
		filtered = append(filtered, sa)
	}
	return filtered, missing, nil
}

func (d *DaemonService) xfrmLinkStateMatchReason(state ipsec.XFRMLinkState, spec ipsec.TransportLinkSpec) (bool, string) {
	if !state.NamespaceExists || !state.InterfaceExists {
		if !state.NamespaceExists {
			return false, "missing_namespace"
		}
		return false, "missing_interface"
	}
	if state.FlagsKnown && !state.InterfaceUp {
		return false, "interface_down"
	}
	// Shared attachments (policy backend on lo) never carry MULTICAST.
	if state.FlagsKnown && !state.Multicast && !state.SharedAttachment {
		return false, "missing_multicast"
	}
	if state.IPv6AddrGenModeKnown && !state.IPv6AddrGenDisabled {
		return false, "ipv6_addrgen_enabled"
	}
	if state.NamespaceForwardingKnown && !state.NamespaceForwarding {
		return false, "namespace_forwarding_disabled"
	}
	if state.InterfaceForwardingKnown && !state.InterfaceForwarding {
		return false, "interface_forwarding_disabled"
	}
	if !spec.LocalTunnelAddr.IsValid() {
		return true, "matched_no_expected_address"
	}
	for _, prefix := range state.Addresses {
		if prefix.Addr() == spec.LocalTunnelAddr {
			return true, "matched"
		}
	}
	return false, "missing_address"
}

func xfrmLinkObservationLogFields(phase, instanceID, runtime string, spec ipsec.TransportLinkSpec, state ipsec.XFRMLinkState, matches bool, reason string) map[string]any {
	fields := map[string]any{
		"phase":            phase,
		"instance_id":      instanceID,
		"runtime":          runtime,
		"matched":          matches,
		"reason":           reason,
		"peer":             spec.PeerZone.String(),
		"group":            spec.OverlayID,
		"transport_id":     spec.TransportID,
		"interface":        spec.InterfaceName,
		"xfrm_if_id":       spec.XFRMIfID,
		"requested_netns":  spec.NetNS,
		"observed_netns":   state.NetNS.Target(),
		"namespace_exists": state.NamespaceExists,
		"interface_exists": state.InterfaceExists,
		"flags_known":      state.FlagsKnown,
		"interface_up":     state.InterfaceUp,
		"multicast":        state.Multicast,
		"addresses":        xfrmPrefixStrings(state.Addresses),
	}
	if spec.LocalTunnelAddr.IsValid() {
		fields["expected_local_tunnel_addr"] = spec.LocalTunnelAddr.String()
	}
	if spec.PeerTunnelAddr.IsValid() {
		fields["expected_peer_tunnel_addr"] = spec.PeerTunnelAddr.String()
	}
	return fields
}

func xfrmPrefixStrings(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out
}

func xfrmCandidateRuntime(base, candidate ipsec.TransportLinkSpec, inst ipsec.LinkInstance) string {
	if candidate.InterfaceName == inst.StagedInterfaceName && candidate.XFRMIfID == inst.StagedXFRMIfID {
		return "staged"
	}
	if candidate.InterfaceName == inst.InterfaceName && candidate.XFRMIfID == inst.XFRMIfID {
		return "active"
	}
	if candidate.InterfaceName == base.InterfaceName && candidate.XFRMIfID == base.XFRMIfID {
		return "desired"
	}
	return "candidate"
}

func xfrmLinkInspectCandidates(spec ipsec.TransportLinkSpec, inst ipsec.LinkInstance) []ipsec.TransportLinkSpec {
	candidates := []ipsec.TransportLinkSpec{spec}
	if inst.InterfaceName != "" || inst.XFRMIfID != 0 {
		active := spec
		if inst.InterfaceName != "" {
			active.InterfaceName = inst.InterfaceName
		}
		if inst.XFRMIfID != 0 {
			active.XFRMIfID = inst.XFRMIfID
		}
		active.LocalTunnelAddr = inst.LocalTunnelAddr
		active.PeerTunnelAddr = inst.PeerTunnelAddr
		if !containsXFRMInspectCandidate(candidates, active) {
			candidates = append(candidates, active)
		}
	}
	if inst.StagedInterfaceName != "" || inst.StagedXFRMIfID != 0 {
		staged := spec
		if inst.StagedInterfaceName != "" {
			staged.InterfaceName = inst.StagedInterfaceName
		}
		if inst.StagedXFRMIfID != 0 {
			staged.XFRMIfID = inst.StagedXFRMIfID
		}
		staged.LocalTunnelAddr = inst.StagedLocalTunnelAddr
		staged.PeerTunnelAddr = inst.StagedPeerTunnelAddr
		if !containsXFRMInspectCandidate(candidates, staged) {
			candidates = append(candidates, staged)
		}
	}
	return candidates
}

func containsXFRMInspectCandidate(candidates []ipsec.TransportLinkSpec, candidate ipsec.TransportLinkSpec) bool {
	for _, existing := range candidates {
		if existing.InterfaceName == candidate.InterfaceName && existing.XFRMIfID == candidate.XFRMIfID {
			return true
		}
	}
	return false
}

func saMatchesMissingXFRMCandidate(sa ipsec.SAState, missing map[string][]ipsec.TransportLinkSpec) bool {
	for _, candidates := range missing {
		for _, spec := range candidates {
			if sa.Name == spec.TransportID || sa.ChildSA == ipsec.ChildSAName(spec) || (spec.XFRMIfID != 0 && sa.XFRMIfID == spec.XFRMIfID) {
				return true
			}
		}
	}
	return false
}

func markMissingXFRMLinkInstances(instances map[string]ipsec.LinkInstance, missing map[string]ipsec.TransportLinkSpec, now time.Time) {
	if len(missing) == 0 {
		return
	}
	for id := range missing {
		inst, ok := instances[id]
		if !ok {
			continue
		}
		inst.ActualState = ipsec.LinkStateDegraded
		inst.LastError = "xfrm namespace or interface missing"
		inst.LastTransition = now.Unix()
		instances[id] = inst
	}
}

func (d *DaemonService) ipsecDrivers() (ipsec.IPsecDriver, ipsec.XFRMDriver) {
	var dryRun *ipsec.DryRunDriver
	ipsecDriver := d.IPsecDriver
	xfrmDriver := d.XFRMDriver
	if ipsecDriver == nil || xfrmDriver == nil {
		dryRun = &ipsec.DryRunDriver{}
	}
	if ipsecDriver == nil {
		ipsecDriver = dryRun
	}
	if xfrmDriver == nil {
		xfrmDriver = dryRun
	}
	return ipsecDriver, xfrmDriver
}

func (d *DaemonService) commitIPsecReconcileResult(rev uint64, workspace *stateFile, unix int64, instances map[string]ipsec.LinkInstance, desired []ipsec.TransportLinkSpec, sas []ipsec.SAState, actions []ipsec.ReconcileAction, skips []ipsec.PlanSkip, lastError string) error {
	if d == nil || d.StateStore == nil || workspace == nil {
		return nil
	}
	summary := summarizeIPsecReconcile(rev, unix, desired, sas, actions, skips, lastError)
	summary.Committed = true
	nextInstances := linkInstancesFromIPsec(instances)
	if ipsecReconcileResultEqual(workspace, nextInstances, summary) {
		return nil
	}
	currentRev, committed := d.StateStore.commitIPsecIfRevision(rev, workspace.IPsecTransportKey, workspace.IPsecPortRecord, nextInstances, summary)
	if !committed {
		d.ipsecDirty = true
		d.publishStateStoreRuntimeFlags()
		d.logWarn("ipsec", "stale_reconcile_result", map[string]any{
			"source_revision":  rev,
			"current_revision": currentRev,
		})
		return nil
	}
	return d.saveCommittedMeta()
}

func ipsecReconcileResultEqual(base *stateFile, nextInstances map[string]linkInstanceState, nextReconcile *ipsecReconcileState) bool {
	if base == nil {
		return false
	}
	if !reflect.DeepEqual(base.LinkInstances, nextInstances) {
		return false
	}
	return ipsecReconcileSummaryEqual(base.IPsecReconcile, nextReconcile)
}

func ipsecReconcileSummaryEqual(base, next *ipsecReconcileState) bool {
	if base == nil || next == nil {
		return base == nil && next == nil
	}
	base = cloneIPsecReconcileState(base)
	next = cloneIPsecReconcileState(next)
	normalizeIPsecReconcileForComparison(base)
	normalizeIPsecReconcileForComparison(next)
	return reflect.DeepEqual(base, next)
}

// normalizeIPsecReconcileForComparison removes values sampled only for live
// diagnostics. Link lifecycle/backoff/owner state remains in LinkInstances and
// is compared exactly by ipsecReconcileResultEqual.
func normalizeIPsecReconcileForComparison(summary *ipsecReconcileState) {
	if summary == nil {
		return
	}
	summary.LastRunUnix = 0
	summary.SourceRevision = 0
	for i := range summary.ActualSAs {
		sa := &summary.ActualSAs[i]
		sa.IKEAgeSeconds = 0
		sa.ChildAgeSeconds = 0
		sa.InboundBytes = 0
		sa.InboundPackets = 0
		sa.InboundIdleSecs = 0
	}
	sort.Slice(summary.ActualSAs, func(i, j int) bool {
		a, b := summary.ActualSAs[i], summary.ActualSAs[j]
		if a.Name != b.Name {
			return a.Name < b.Name
		}
		if a.UniqueID != b.UniqueID {
			return a.UniqueID < b.UniqueID
		}
		if a.ChildSA != b.ChildSA {
			return a.ChildSA < b.ChildSA
		}
		return a.ReqID < b.ReqID
	})
}

func (d *DaemonService) recordIPsecReconcileError(rev uint64, unix int64, err error) {
	if d == nil || d.StateStore == nil || err == nil {
		return
	}
	snapshot, snapshotRev := d.StateStore.ipsecSnapshot()
	if snapshot == nil || snapshotRev != rev {
		d.ipsecDirty = true
		d.publishStateStoreRuntimeFlags()
		d.logWarn("ipsec", "stale_reconcile_error", map[string]any{
			"source_revision":  rev,
			"current_revision": snapshotRev,
			"error":            err,
		})
		return
	}
	reconcile := cloneIPsecReconcileState(snapshot.IPsecReconcile)
	if reconcile == nil {
		reconcile = &ipsecReconcileState{}
	}
	reconcile.LastRunUnix = unix
	reconcile.SourceRevision = rev
	reconcile.Committed = true
	reconcile.Stale = false
	reconcile.LastError = err.Error()
	if ipsecReconcileResultEqual(snapshot, snapshot.LinkInstances, reconcile) {
		return
	}
	currentRev, committed := d.StateStore.commitIPsecIfRevision(rev, snapshot.IPsecTransportKey, snapshot.IPsecPortRecord, snapshot.LinkInstances, reconcile)
	if !committed {
		d.ipsecDirty = true
		d.publishStateStoreRuntimeFlags()
		d.logWarn("ipsec", "stale_reconcile_error", map[string]any{
			"source_revision":  rev,
			"current_revision": currentRev,
			"error":            err,
		})
		return
	}
	if saveErr := d.saveCommittedMeta(); saveErr != nil {
		d.logWarn("ipsec", "save_reconcile_error_failed", map[string]any{"error": saveErr})
	}
}

func (d *DaemonService) saveCommittedState() error {
	if d == nil || d.StateStore == nil {
		return nil
	}
	lease := d.StateStore.persistenceLease()
	var err error
	if d.Sync != nil {
		err = d.Sync.saveStateSnapshotAtRevision(lease.state, lease.revision)
	} else {
		err = saveState(lease.state)
	}
	if err == nil {
		d.noteMetadataPersisted(lease.revision)
	}
	return err
}

func (d *DaemonService) saveCommittedMeta() error {
	if d == nil || d.StateStore == nil {
		return nil
	}
	lease := d.StateStore.persistenceLease()
	var err error
	if d.Sync != nil {
		err = d.Sync.saveStateMetaSnapshotAtRevision(lease.state, lease.revision)
	} else {
		err = saveStateMeta(lease.state)
	}
	if err == nil {
		d.noteMetadataPersisted(lease.revision)
	}
	return err
}

// buildIPsecContactPointQuality builds a per-peer, per-contact-point quality
// map from the gossip transport's runtime reachability state. This lets the
// IPsec planner deprioritize addresses that are currently in backoff or have
// recent failures, matching the gossip transport's own dialing preferences.
func (d *DaemonService) buildIPsecContactPointQuality(state *stateFile, now time.Time) map[zone.ZonePath]map[string]ipsec.ContactPointQuality {
	if d == nil || d.Sync == nil || d.Sync.Transport == nil || state == nil || state.Network == nil {
		return nil
	}
	transport := d.Sync.Transport
	ns := state.Network
	out := make(map[zone.ZonePath]map[string]ipsec.ContactPointQuality)

	for _, peerID := range transport.KnownPeerIDs() {
		peerPath := zone.ZonePath(peerID)
		if !peerPath.Valid() || peerPath.IsRoot() || peerPath == state.ManagedZone {
			continue
		}
		states := transport.PeerAddrStates(peerID)
		if len(states) == 0 {
			continue
		}
		records, err := ipsec.ExtractNodeRecords(ns, peerPath, now)
		if err != nil || records.Addresses == nil || records.Ports == nil {
			continue
		}
		portAds := ipsec.PortAdvertisements(records.Ports, now)
		if len(portAds) == 0 {
			continue
		}

		inner := make(map[string]ipsec.ContactPointQuality)
		for addrStr, st := range states {
			udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
			if err != nil {
				continue
			}
			ip := udpAddr.IP.String()
			for _, ad := range records.Addresses.Addresses {
				if ad.Address != ip {
					continue
				}
				for _, port := range portAds {
					if !ipsecQualityAddrPortMatches(udpAddr.Port, port) {
						continue
					}
					key := ipsec.ContactPoint{
						AddressID:  ad.ID,
						Address:    ad.Address,
						Generation: port.Generation,
						IKEPort:    contactDialPort(port.IKE),
						NATTPort:   contactDialPort(port.NATT),
					}.Key()
					inner[key] = ipsec.ContactPointQuality{
						Successes:    st.SuccessCount,
						Failures:     st.FailureCount,
						BackoffUntil: st.BackoffUntil,
					}
				}
			}
		}
		if len(inner) > 0 {
			out[peerPath] = inner
		}
	}
	return out
}

func ipsecQualityAddrPortMatches(addrPort int, port ipsec.PortAdvertisement) bool {
	if addrPort <= 0 {
		return false
	}
	return addrPort == int(contactDialPort(port.IKE)) || addrPort == int(contactDialPort(port.NATT))
}

func contactDialPort(binding ipsec.PortBinding) uint16 {
	if binding.Observed != 0 {
		return binding.Observed
	}
	return binding.Advertised
}

func summarizeIPsecReconcile(sourceRev uint64, unix int64, desired []ipsec.TransportLinkSpec, sas []ipsec.SAState, actions []ipsec.ReconcileAction, skips []ipsec.PlanSkip, lastError string) *ipsecReconcileState {
	state := &ipsecReconcileState{
		LastRunUnix:    unix,
		SourceRevision: sourceRev,
		DesiredLinks:   len(desired),
		LastError:      lastError,
	}
	for _, spec := range desired {
		state.Desired = append(state.Desired, desiredLinkState{
			InstanceID:      ipsec.LinkInstanceID(spec),
			GroupID:         spec.OverlayID,
			PeerZone:        spec.PeerZone,
			LinkID:          spec.LinkID,
			PathKey:         spec.PathKey,
			TransportID:     spec.TransportID,
			DesiredSpecHash: ipsec.TransportLinkSpecHash(spec),
			InterfaceName:   spec.InterfaceName,
			XFRMIfID:        spec.XFRMIfID,
			Endpoint:        summarizeContactEndpoint(spec.ContactPoints),
			LocalTunnelAddr: ipsec.FormatScopedTunnelAddress(spec.LocalTunnelAddr, spec.InterfaceName, spec.NetNS),
			PeerTunnelAddr:  ipsec.FormatScopedTunnelAddress(spec.PeerTunnelAddr, spec.InterfaceName, spec.NetNS),
		})
	}
	for _, sa := range sas {
		state.ActualSAs = append(state.ActualSAs, linkSAState{
			Name:            sa.Name,
			UniqueID:        sa.UniqueID,
			Initiator:       sa.Initiator,
			InitiatorKnown:  sa.InitiatorKnown,
			IKEAgeSeconds:   sa.IKEAgeSeconds,
			ChildAgeSeconds: sa.ChildAgeSeconds,
			InboundBytes:    sa.InboundBytes,
			InboundPackets:  sa.InboundPackets,
			InboundIdleSecs: sa.InboundIdleSecs,
			InboundKnown:    sa.InboundKnown,
			Peer:            sa.Peer,
			ChildSA:         sa.ChildSA,
			IKEState:        sa.IKEState,
			ChildState:      sa.ChildState,
			XFRMIfID:        sa.XFRMIfID,
			ReqID:           sa.ReqID,
			LocalIdentity:   sa.LocalIdentity,
			RemoteIdentity:  sa.RemoteIdentity,
			LocalEndpoint:   sa.LocalEndpoint,
			RemoteEndpoint:  sa.RemoteEndpoint,
			Endpoint:        sa.Endpoint,
			Established:     sa.Established,
		})
	}
	for _, action := range actions {
		item := linkActionState{Action: action.Action, Reason: action.Reason, SAUniqueID: action.SAUniqueID}
		if action.Instance != nil {
			item.InstanceID = action.Instance.ID
			item.GroupID = action.Instance.GroupID
			item.PeerZone = action.Instance.PeerZone
		}
		if action.Spec != nil {
			item.InstanceID = ipsec.LinkInstanceID(*action.Spec)
			item.GroupID = action.Spec.OverlayID
			item.PeerZone = action.Spec.PeerZone
		}
		state.Actions = append(state.Actions, item)
	}
	for _, skip := range skips {
		state.Skipped = append(state.Skipped, linkSkipState{
			GroupID: skip.GroupID,
			Peer:    skip.Peer,
			Reason:  skip.Reason,
			Detail:  skip.Detail,
		})
	}
	return state
}

func summarizeContactEndpoint(points []ipsec.ContactPoint) string {
	if len(points) == 0 {
		return ""
	}
	if points[0].Address != "" {
		return points[0].Address
	}
	return points[0].Host
}

func linkInstancesToIPsec(in map[string]linkInstanceState) map[string]ipsec.LinkInstance {
	out := make(map[string]ipsec.LinkInstance, len(in))
	for id, inst := range in {
		out[id] = ipsec.LinkInstance{
			ID:                    inst.ID,
			GroupID:               inst.GroupID,
			PeerZone:              inst.PeerZone,
			TransportKind:         inst.TransportKind,
			LinkID:                inst.LinkID,
			PathKey:               inst.PathKey,
			TransportID:           inst.TransportID,
			DesiredSpecHash:       inst.DesiredSpecHash,
			ActualState:           inst.ActualState,
			InterfaceName:         inst.InterfaceName,
			XFRMIfID:              inst.XFRMIfID,
			LocalTunnelAddr:       parseStateAddr(inst.LocalTunnelAddr),
			PeerTunnelAddr:        parseStateAddr(inst.PeerTunnelAddr),
			IKEName:               inst.IKEName,
			ChildSAName:           inst.ChildSAName,
			Endpoint:              inst.Endpoint,
			RemoteGeneration:      inst.RemoteGeneration,
			StagedGeneration:      inst.StagedGeneration,
			RotatePhase:           inst.RotatePhase,
			StagedIKEName:         inst.StagedIKEName,
			StagedChildSAName:     inst.StagedChildSAName,
			StagedInterfaceName:   inst.StagedInterfaceName,
			StagedXFRMIfID:        inst.StagedXFRMIfID,
			StagedLocalTunnelAddr: parseStateAddr(inst.StagedLocalTunnelAddr),
			StagedPeerTunnelAddr:  parseStateAddr(inst.StagedPeerTunnelAddr),
			RotateDeadline:        inst.RotateDeadline,
			StagedAttemptCount:    inst.StagedAttemptCount,
			StagedNextAttempt:     inst.StagedNextAttempt,
			LastError:             inst.LastError,
			FailureCount:          inst.FailureCount,
			BackoffUntil:          inst.BackoffUntil,
			LastTransition:        inst.LastTransition,
			Owner: ipsec.ResourceOwner{
				Manager:     inst.Owner.Manager,
				GroupID:     inst.Owner.GroupID,
				InstanceID:  inst.Owner.InstanceID,
				LinkID:      inst.Owner.LinkID,
				TransportID: inst.Owner.TransportID,
				Token:       inst.Owner.Token,
			},
			InitiatorRole:     inst.InitiatorRole,
			TakeoverPhase:     inst.TakeoverPhase,
			TakeoverStartedAt: inst.TakeoverStartedAt,
			TakeoverUntil:     inst.TakeoverUntil,
			LastTakeoverError: inst.LastTakeoverError,
			ObservedInitiator: inst.ObservedInitiator,
			SAAbsentSince:     inst.SAAbsentSince,
			SAAbsentCount:     inst.SAAbsentCount,
		}
	}
	return out
}

func linkInstancesFromIPsec(in map[string]ipsec.LinkInstance) map[string]linkInstanceState {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]linkInstanceState, len(in))
	for id, inst := range in {
		out[id] = linkInstanceState{
			ID:                    inst.ID,
			GroupID:               inst.GroupID,
			PeerZone:              inst.PeerZone,
			TransportKind:         inst.TransportKind,
			LinkID:                inst.LinkID,
			PathKey:               inst.PathKey,
			TransportID:           inst.TransportID,
			DesiredSpecHash:       inst.DesiredSpecHash,
			ActualState:           inst.ActualState,
			InterfaceName:         inst.InterfaceName,
			XFRMIfID:              inst.XFRMIfID,
			LocalTunnelAddr:       formatStateAddr(inst.LocalTunnelAddr),
			PeerTunnelAddr:        formatStateAddr(inst.PeerTunnelAddr),
			IKEName:               inst.IKEName,
			ChildSAName:           inst.ChildSAName,
			Endpoint:              inst.Endpoint,
			RemoteGeneration:      inst.RemoteGeneration,
			StagedGeneration:      inst.StagedGeneration,
			RotatePhase:           inst.RotatePhase,
			StagedIKEName:         inst.StagedIKEName,
			StagedChildSAName:     inst.StagedChildSAName,
			StagedInterfaceName:   inst.StagedInterfaceName,
			StagedXFRMIfID:        inst.StagedXFRMIfID,
			StagedLocalTunnelAddr: formatStateAddr(inst.StagedLocalTunnelAddr),
			StagedPeerTunnelAddr:  formatStateAddr(inst.StagedPeerTunnelAddr),
			RotateDeadline:        inst.RotateDeadline,
			StagedAttemptCount:    inst.StagedAttemptCount,
			StagedNextAttempt:     inst.StagedNextAttempt,
			LastError:             inst.LastError,
			FailureCount:          inst.FailureCount,
			BackoffUntil:          inst.BackoffUntil,
			LastTransition:        inst.LastTransition,
			Owner: linkOwnerState{
				Manager:     inst.Owner.Manager,
				GroupID:     inst.Owner.GroupID,
				InstanceID:  inst.Owner.InstanceID,
				LinkID:      inst.Owner.LinkID,
				TransportID: inst.Owner.TransportID,
				Token:       inst.Owner.Token,
			},
			InitiatorRole:     inst.InitiatorRole,
			TakeoverPhase:     inst.TakeoverPhase,
			TakeoverStartedAt: inst.TakeoverStartedAt,
			TakeoverUntil:     inst.TakeoverUntil,
			LastTakeoverError: inst.LastTakeoverError,
			ObservedInitiator: inst.ObservedInitiator,
			SAAbsentSince:     inst.SAAbsentSince,
			SAAbsentCount:     inst.SAAbsentCount,
		}
	}
	return out
}

func parseStateAddr(s string) netip.Addr {
	if s == "" {
		return netip.Addr{}
	}
	addr, err := netip.ParseAddr(stripScope(s))
	if err != nil {
		return netip.Addr{}
	}
	return addr
}

func formatStateAddr(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func revokedLinkPeers(state *stateFile, now time.Time) map[zone.ZonePath]bool {
	// Phase 6.4.5: use the comprehensive revoked peer zone collector that
	// covers both LinkInstances and SyncPeers, so that revocation is detected
	// even for peers that don't have an active link instance yet.
	return collectRevokedPeerZones(state, now)
}

func injectIPsecKeyMaterial(state *stateFile, desired []ipsec.TransportLinkSpec) []ipsec.TransportLinkSpec {
	if state == nil {
		return desired
	}
	localKey := state.IPsecTransportKey
	out := make([]ipsec.TransportLinkSpec, len(desired))
	for i, spec := range desired {
		if localKey != nil && len(localKey.PrivateKey) > 0 {
			spec.LocalPrivateKey = append([]byte(nil), localKey.PrivateKey...)
			spec.LocalPrivateKeyAlgorithm = localKey.Algorithm
		}
		if peerZone := state.Network.Zones[spec.PeerZone]; peerZone != nil {
			if record := peerZone.Records[ipsec.RecordKeyTransportKey]; record != nil {
				if keyRecord, err := ipsec.ParseTransportKeyRecord(record); err == nil {
					if pub, err := ipsec.DecodeTransportPublicKey(*keyRecord); err == nil {
						spec.PeerPublicKey = append([]byte(nil), pub...)
					}
				}
			}
		}
		out[i] = spec
	}
	return out
}

func netnsForAction(action ipsec.ReconcileAction, groups []ipsec.LinkGroupSpec) ipsec.NetNSSpec {
	groupID := ""
	if action.Spec != nil {
		groupID = action.Spec.OverlayID
	} else if action.Instance != nil {
		groupID = action.Instance.GroupID
	}
	for _, group := range groups {
		if group.ID == groupID {
			return group.NetNS
		}
	}
	return ipsec.NetNSSpec{}
}

func markIPsecActionFailed(instances map[string]ipsec.LinkInstance, action ipsec.ReconcileAction, policy ipsec.BackoffPolicy, now time.Time, err error) {
	id := actionInstanceID(action)
	if id == "" {
		return
	}
	inst, ok := instances[id]
	if !ok {
		if action.Instance != nil {
			inst = *action.Instance
		} else if action.Spec != nil {
			inst = ipsec.NewLinkInstance(*action.Spec, ipsec.LinkStateError, now)
		} else {
			return
		}
	}
	inst = ipsec.MarkLinkApplyFailure(inst, policy, now, err)
	switch action.Action {
	case ipsec.ReconcileActionPrepareRotate, ipsec.ReconcileActionInitiateRotate, ipsec.ReconcileActionCommitRotate, ipsec.ReconcileActionRollbackRotate, ipsec.ReconcileActionCleanupRotate:
		if inst.RotatePhase != "" {
			inst.LastError = "rotate " + inst.RotatePhase + ": " + inst.LastError
		}
	}
	if inst.InitiatorRole == ipsec.InitiatorRoleSecondaryTakeover {
		inst.TakeoverPhase = ipsec.TakeoverPhaseCooldown
		inst.TakeoverUntil = now.Add(ipsec.TakeoverCooldownDuration(policy)).Unix()
		inst.LastTakeoverError = inst.LastError
	}
	instances[id] = inst
}

func markIPsecActionSucceeded(instances map[string]ipsec.LinkInstance, action ipsec.ReconcileAction, now time.Time) {
	id := actionInstanceID(action)
	if id == "" {
		return
	}
	if action.Action == ipsec.ReconcileActionTeardown {
		delete(instances, id)
		return
	}
	inst, ok := instances[id]
	if !ok {
		return
	}
	// A successful rollback means the staged resources were cleaned up, not
	// that the failed rotation recovered. Preserve the failure/backoff recorded
	// by the planner so the same generation is not prepared again immediately.
	if action.Action != ipsec.ReconcileActionRollbackRotate {
		inst = ipsec.MarkLinkApplySuccess(inst, now)
	}
	switch action.Action {
	case ipsec.ReconcileActionCreate, ipsec.ReconcileActionUpdate, ipsec.ReconcileActionRepair, ipsec.ReconcileActionPrepareStandby, ipsec.ReconcileActionPrepareRotate, ipsec.ReconcileActionInitiateRotate:
		if inst.InitiatorRole == ipsec.InitiatorRoleSecondaryStandby ||
			(action.Spec != nil && action.Spec.InitiatorRole == ipsec.InitiatorRoleSecondaryStandby) {
			inst.ActualState = ipsec.LinkStateDown
		} else {
			inst.ActualState = ipsec.LinkStateConnecting
		}
		inst.LastTransition = now.Unix()
		if inst.StagedGeneration != 0 {
			inst.RotatePhase = ipsec.RotatePhaseTestingNew
		}
	case ipsec.ReconcileActionCommitRotate:
		// The staged SA was already established before commit; after tearing
		// down the old connection the link is up and rotation is complete.
		inst.ActualState = ipsec.LinkStateUp
		inst.RotatePhase = ipsec.RotatePhaseIdle
		inst.LastTransition = now.Unix()
	case ipsec.ReconcileActionRollbackRotate:
		inst.ActualState = ipsec.LinkStateConnecting
		inst.StagedGeneration = 0
		inst.StagedIKEName = ""
		inst.StagedChildSAName = ""
		inst.StagedInterfaceName = ""
		inst.StagedXFRMIfID = 0
		inst.StagedLocalTunnelAddr = netip.Addr{}
		inst.StagedPeerTunnelAddr = netip.Addr{}
		inst.RotatePhase = ipsec.RotatePhaseIdle
		inst.RotateDeadline = 0
		inst.StagedAttemptCount = 0
		inst.StagedNextAttempt = 0
		inst.LastTransition = now.Unix()
	case ipsec.ReconcileActionCleanupRotate:
		inst.StagedGeneration = 0
		inst.StagedIKEName = ""
		inst.StagedChildSAName = ""
		inst.StagedInterfaceName = ""
		inst.StagedXFRMIfID = 0
		inst.StagedLocalTunnelAddr = netip.Addr{}
		inst.StagedPeerTunnelAddr = netip.Addr{}
		inst.RotatePhase = ipsec.RotatePhaseIdle
		inst.RotateDeadline = 0
		inst.StagedAttemptCount = 0
		inst.StagedNextAttempt = 0
	}
	instances[id] = inst
}

func actionInstanceID(action ipsec.ReconcileAction) string {
	if action.Instance != nil && action.Instance.ID != "" {
		return action.Instance.ID
	}
	if action.Spec != nil {
		return ipsec.LinkInstanceID(*action.Spec)
	}
	return ""
}

func groupSpecMap(groups []ipsec.LinkGroupSpec) map[string]ipsec.LinkGroupSpec {
	out := make(map[string]ipsec.LinkGroupSpec, len(groups))
	for _, group := range groups {
		out[group.ID] = group.Normalized()
	}
	return out
}

func linkGroupForSpec(spec ipsec.TransportLinkSpec, groups []ipsec.LinkGroupSpec) ipsec.LinkGroupSpec {
	for _, group := range groups {
		if group.ID == spec.OverlayID {
			return group.Normalized()
		}
	}
	return ipsec.LinkGroupSpec{}
}

func groupBackoffMap(groups []ipsec.LinkGroupSpec) map[string]ipsec.BackoffPolicy {
	out := make(map[string]ipsec.BackoffPolicy, len(groups))
	for _, group := range groups {
		out[group.ID] = group.Reconcile.Backoff
	}
	return out
}

func groupRotateRetentionMap(groups []ipsec.LinkGroupSpec) map[string]int {
	out := make(map[string]int, len(groups))
	for _, group := range groups {
		out[group.ID] = group.Normalized().Reconcile.RotateRetentionSeconds
	}
	return out
}

func groupBackoffPolicy(action ipsec.ReconcileAction, groups []ipsec.LinkGroupSpec) ipsec.BackoffPolicy {
	groupID := ""
	if action.Spec != nil {
		groupID = action.Spec.OverlayID
	} else if action.Instance != nil {
		groupID = action.Instance.GroupID
	}
	for _, group := range groups {
		if group.ID == groupID {
			return group.Reconcile.Backoff
		}
	}
	return ipsec.BackoffPolicy{}
}
