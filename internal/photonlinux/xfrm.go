package photonlinux

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"

	transportipsec "github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type XFRMObservations struct {
	links map[string]transportipsec.XFRMLinkState
}

type xfrmMaintenanceItem struct {
	id        string
	candidate transportipsec.TransportLinkSpec
	state     transportipsec.XFRMLinkState
	matches   bool
	reason    string
}

func (r *LinuxDriver) ObserveXFRMLinks(ctx context.Context, desired []transportipsec.TransportLinkSpec, instances map[string]transportipsec.LinkInstance, groups []transportipsec.LinkGroupSpec) *XFRMObservations {
	driver := r.xfrmDriver
	inspector, ok := driver.(transportipsec.XFRMLinkBatchInspector)
	if !ok || len(desired) == 0 {
		return nil
	}
	seen := make(map[string]struct{})
	specs := make([]transportipsec.TransportLinkSpec, 0, len(desired)*2)
	appendSpec := func(spec transportipsec.TransportLinkSpec) {
		key := xfrmObservationKey(spec)
		if _, ok := seen[key]; ok {
			return
		}
		seen[key] = struct{}{}
		specs = append(specs, spec)
	}
	for _, spec := range desired {
		id := transportipsec.LinkInstanceID(spec)
		instance, found := instances[id]
		for _, candidate := range xfrmLinkInspectCandidates(spec, instance) {
			appendSpec(candidate)
		}
		if found && shouldMaintainXFRMInstance(instance) {
			appendSpec(xfrmMaintenanceSpec(spec, instance, groups))
		}
	}
	states, err := inspector.InspectLinks(ctx, specs)
	if err != nil {
		logWarn(r.logger, "xfrm_batch_observe_fallback", map[string]any{"candidates": len(specs), "error": err.Error()})
		return nil
	}
	if len(states) != len(specs) {
		logWarn(r.logger, "xfrm_batch_observe_fallback", map[string]any{"candidates": len(specs), "observed": len(states), "error": "batch result length mismatch"})
		return nil
	}
	observed := &XFRMObservations{links: make(map[string]transportipsec.XFRMLinkState, len(specs))}
	for index, spec := range specs {
		observed.links[xfrmObservationKey(spec)] = states[index]
	}
	logDebug(r.logger, "xfrm_batch_observed", map[string]any{"candidates": len(specs)})
	return observed
}

func (r *LinuxDriver) FilterSAsWithMissingXFRMLinks(ctx context.Context, desired []transportipsec.TransportLinkSpec, instances map[string]transportipsec.LinkInstance, sas []transportipsec.SAState, observed *XFRMObservations) ([]transportipsec.SAState, map[string]transportipsec.TransportLinkSpec, error) {
	driver := r.xfrmDriver
	if inspector, ok := driver.(transportipsec.XFRMLinkInspector); ok && len(instances) > 0 {
		return filterSAsWithMissingRuntimeLinks(ctx, inspector, desired, instances, sas, observed, r.logger)
	}
	filter, ok := driver.(transportipsec.XFRMSAFilter)
	if !ok {
		return sas, nil, nil
	}
	filtered, missing, err := filter.FilterSAsWithMissingLinks(ctx, desired, sas)
	if err != nil {
		return nil, nil, err
	}
	for _, spec := range missing {
		logDebug(r.logger, "xfrm_link_missing", missingLinkFields(spec, "driver_filter", 0))
	}
	return filtered, missing, nil
}

func (r *LinuxDriver) MaintainXFRMInterfaces(ctx context.Context, desired []transportipsec.TransportLinkSpec, instances map[string]transportipsec.LinkInstance, actions []transportipsec.ReconcileAction, groups []transportipsec.LinkGroupSpec, diagnosticPrefixes []netip.Prefix, observed *XFRMObservations) error {
	driver := r.xfrmDriver
	inspector, ok := driver.(interface {
		transportipsec.XFRMDriver
		transportipsec.XFRMLinkInspector
	})
	if !ok {
		logDebug(r.logger, "xfrm_maintenance_skip_driver", map[string]any{"reason": "xfrm driver does not implement link inspection"})
		return nil
	}
	if len(desired) == 0 || len(instances) == 0 {
		logDebug(r.logger, "xfrm_maintenance_skip_empty", map[string]any{"desired": len(desired), "instances": len(instances)})
		return nil
	}
	activeActions := make(map[string]struct{})
	for _, action := range actions {
		if ipsecActionAppliesXFRM(action.Action) {
			if id := actionInstanceID(action); id != "" {
				activeActions[id] = struct{}{}
			}
		}
	}
	logDebug(r.logger, "xfrm_maintenance_begin", map[string]any{"desired": len(desired), "instances": len(instances), "active_actions": len(activeActions)})
	var items []xfrmMaintenanceItem
	for _, spec := range desired {
		id := transportipsec.LinkInstanceID(spec)
		if _, active := activeActions[id]; active {
			continue
		}
		instance, found := instances[id]
		if !found || !shouldMaintainXFRMInstance(instance) {
			continue
		}
		candidate := xfrmMaintenanceSpec(spec, instance, groups)
		state, err := inspectXFRMLink(ctx, inspector, observed, candidate)
		if err != nil {
			return fmt.Errorf("inspect xfrm interface %q: %w", candidate.InterfaceName, err)
		}
		matches, reason := XFRMLinkStateMatchReason(state, candidate)
		logDebug(r.logger, "xfrm_runtime_observed", observationFields("runtime_ensure", id, "active", candidate, state, matches, reason))
		if !state.NamespaceExists || !state.InterfaceExists {
			logDebug(r.logger, "xfrm_maintenance_skip_missing", map[string]any{
				"instance_id": id,
				"peer":        candidate.PeerZone,
				"interface":   candidate.InterfaceName,
				"netns":       candidate.NetNS,
				"runtime":     "active",
			})
			continue
		}
		if matches {
			logDebug(r.logger, "xfrm_maintenance_skip_matched", map[string]any{
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
	var repairs []transportipsec.XFRMObservedInterface
	for _, item := range items {
		if !item.matches {
			repairs = append(repairs, transportipsec.XFRMObservedInterface{Spec: item.candidate, State: item.state})
		}
	}
	if len(repairs) > 0 {
		if ensurer, ok := driver.(transportipsec.XFRMObservedEnsurer); ok && observed != nil {
			if err := ensurer.EnsureObservedInterfaces(ctx, repairs); err != nil {
				return fmt.Errorf("maintain observed xfrm interfaces: %w", err)
			}
		} else {
			for _, repair := range repairs {
				if err := inspector.EnsureInterface(ctx, repair.Spec); err != nil {
					return fmt.Errorf("maintain xfrm interface %q: %w", repair.Spec.InterfaceName, err)
				}
			}
		}
	}
	for _, item := range items {
		candidate := item.candidate
		if candidate.LocalTunnelAddr.IsValid() && !xfrmStateHasAddress(item.state, candidate.LocalTunnelAddr) {
			if err := inspector.AssignAddress(ctx, candidate, tunnelAddressPrefix(candidate.LocalTunnelAddr)); err != nil {
				return fmt.Errorf("maintain xfrm address %q: %w", candidate.InterfaceName, err)
			}
		}
		stateForDiagnostics := &item.state
		if !item.matches {
			stateForDiagnostics = nil
		}
		if err := r.assignDiagnosticAddresses(ctx, candidate, diagnosticPrefixes, stateForDiagnostics); err != nil {
			return fmt.Errorf("maintain xfrm diagnostic address %q: %w", candidate.InterfaceName, err)
		}
		logDebug(r.logger, "xfrm_maintenance_applied", map[string]any{"instance_id": item.id, "peer": candidate.PeerZone, "interface": candidate.InterfaceName, "netns": candidate.NetNS, "runtime": "active", "reason": item.reason})
	}
	return nil
}

func (r *LinuxDriver) AssignDiagnosticAddresses(ctx context.Context, spec transportipsec.TransportLinkSpec, prefixes []netip.Prefix) error {
	return r.assignDiagnosticAddresses(ctx, spec, prefixes, nil)
}

func (r *LinuxDriver) assignDiagnosticAddresses(ctx context.Context, spec transportipsec.TransportLinkSpec, prefixes []netip.Prefix, observed *transportipsec.XFRMLinkState) error {
	if len(prefixes) == 0 {
		return nil
	}
	assigner, ok := r.xfrmDriver.(transportipsec.XFRMExtraAddressAssigner)
	if !ok {
		return nil
	}
	suffix, ok := IPsecDiagnosticSuffix(spec)
	if !ok {
		return nil
	}
	for _, prefix := range prefixes {
		address, ok := DiagnosticAddressForPrefix(prefix, suffix)
		if !ok || observed != nil && xfrmStateHasAddress(*observed, address) {
			continue
		}
		if err := assigner.AssignExtraAddress(ctx, spec, netip.PrefixFrom(address, 128).String()); err != nil {
			return err
		}
		logDebug(r.logger, "diagnostic_address_assigned", map[string]any{"interface": spec.InterfaceName, "netns": spec.NetNS, "address": address.String(), "prefix": prefix.String(), "path_key": spec.PathKey})
	}
	return nil
}

func filterSAsWithMissingRuntimeLinks(ctx context.Context, inspector transportipsec.XFRMLinkInspector, desired []transportipsec.TransportLinkSpec, instances map[string]transportipsec.LinkInstance, sas []transportipsec.SAState, observed *XFRMObservations, logger Logger) ([]transportipsec.SAState, map[string]transportipsec.TransportLinkSpec, error) {
	if len(desired) == 0 {
		return sas, nil, nil
	}
	missing := make(map[string]transportipsec.TransportLinkSpec)
	missingCandidates := make(map[string][]transportipsec.TransportLinkSpec)
	for _, spec := range desired {
		id := transportipsec.LinkInstanceID(spec)
		candidates := xfrmLinkInspectCandidates(spec, instances[id])
		found := false
		for _, candidate := range candidates {
			state, err := inspectXFRMLink(ctx, inspector, observed, candidate)
			if err != nil {
				return nil, nil, err
			}
			matches, reason := XFRMLinkStateMatchReason(state, candidate)
			logDebug(logger, "xfrm_runtime_observed", observationFields("pre_reconcile_filter", id, xfrmCandidateRuntime(spec, candidate, instances[id]), candidate, state, matches, reason))
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
		logDebug(logger, "xfrm_link_missing", missingLinkFields(spec, "no_candidate_matched", len(candidates)))
	}
	if len(missing) == 0 || len(sas) == 0 {
		return sas, missing, nil
	}
	filtered := sas[:0]
	for _, sa := range sas {
		if !saMatchesMissingXFRMCandidate(sa, missingCandidates) {
			filtered = append(filtered, sa)
		}
	}
	return filtered, missing, nil
}

func inspectXFRMLink(ctx context.Context, inspector transportipsec.XFRMLinkInspector, observed *XFRMObservations, spec transportipsec.TransportLinkSpec) (transportipsec.XFRMLinkState, error) {
	if observed != nil {
		if state, ok := observed.links[xfrmObservationKey(spec)]; ok {
			return state, nil
		}
	}
	return inspector.InspectLink(ctx, spec)
}

func XFRMLinkStateMatchReason(state transportipsec.XFRMLinkState, spec transportipsec.TransportLinkSpec) (bool, string) {
	if !state.NamespaceExists || !state.InterfaceExists {
		if !state.NamespaceExists {
			return false, "missing_namespace"
		}
		return false, "missing_interface"
	}
	if state.FlagsKnown && (!state.InterfaceUp || !state.Multicast) {
		if !state.InterfaceUp {
			return false, "interface_down"
		}
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
	if xfrmStateHasAddress(state, spec.LocalTunnelAddr) {
		return true, "matched"
	}
	return false, "missing_address"
}

func IPsecDiagnosticSuffix(spec transportipsec.TransportLinkSpec) (uint16, bool) {
	pathKey := strings.ToLower(spec.PathKey)
	switch {
	case strings.Contains(pathKey, "ipv4"):
		return 0xfff4, true
	case strings.Contains(pathKey, "ipv6"):
		return 0xfff6, true
	}
	if address := net.ParseIP(spec.LocalAddress); address != nil {
		if address.To4() != nil {
			return 0xfff4, true
		}
		return 0xfff6, true
	}
	return 0, false
}

func DiagnosticAddressForPrefix(prefix netip.Prefix, suffix uint16) (netip.Addr, bool) {
	prefix = prefix.Masked()
	if !prefix.Addr().Is6() || prefix.Bits() != 64 {
		return netip.Addr{}, false
	}
	raw := prefix.Addr().As16()
	raw[14] = byte(suffix >> 8)
	raw[15] = byte(suffix)
	return netip.AddrFrom16(raw), true
}

func xfrmObservationKey(spec transportipsec.TransportLinkSpec) string {
	return spec.NetNS + "\x00" + spec.InterfaceName
}

func xfrmStateHasAddress(state transportipsec.XFRMLinkState, address netip.Addr) bool {
	for _, prefix := range state.Addresses {
		if prefix.Addr() == address {
			return true
		}
	}
	return false
}

func ipsecActionAppliesXFRM(action string) bool {
	switch action {
	case transportipsec.ReconcileActionCreate, transportipsec.ReconcileActionUpdate, transportipsec.ReconcileActionRepair,
		transportipsec.ReconcileActionPrepareStandby, transportipsec.ReconcileActionTeardown, transportipsec.ReconcileActionPrepareRotate,
		transportipsec.ReconcileActionCommitRotate, transportipsec.ReconcileActionRollbackRotate, transportipsec.ReconcileActionCleanupRotate:
		return true
	default:
		return false
	}
}

func actionInstanceID(action transportipsec.ReconcileAction) string {
	if action.Instance != nil {
		return action.Instance.ID
	}
	if action.Spec != nil {
		return transportipsec.LinkInstanceID(*action.Spec)
	}
	return ""
}

func shouldMaintainXFRMInstance(instance transportipsec.LinkInstance) bool {
	if instance.InterfaceName == "" || instance.XFRMIfID == 0 {
		return false
	}
	switch instance.ActualState {
	case transportipsec.LinkStateUp, transportipsec.LinkStateConnecting, transportipsec.LinkStateConfiguring:
		return true
	default:
		return false
	}
}

func xfrmMaintenanceSpec(spec transportipsec.TransportLinkSpec, instance transportipsec.LinkInstance, groups []transportipsec.LinkGroupSpec) transportipsec.TransportLinkSpec {
	out := runtimeSpecForInstanceGeneration(spec, instance, groups)
	if instance.InterfaceName != "" {
		out.InterfaceName = instance.InterfaceName
	}
	if instance.XFRMIfID != 0 {
		out.XFRMIfID = instance.XFRMIfID
	}
	return out
}

func runtimeSpecForInstanceGeneration(spec transportipsec.TransportLinkSpec, instance transportipsec.LinkInstance, groups []transportipsec.LinkGroupSpec) transportipsec.TransportLinkSpec {
	generation := instance.RemoteGeneration
	if generation == 0 {
		generation = spec.Generation
	}
	out, err := transportipsec.RuntimeSpecForPortGeneration(spec, linkGroupForSpec(spec, groups), generation)
	if err != nil {
		return spec
	}
	return out
}

func linkGroupForSpec(spec transportipsec.TransportLinkSpec, groups []transportipsec.LinkGroupSpec) transportipsec.LinkGroupSpec {
	for _, group := range groups {
		if group.ID == spec.OverlayID {
			return group.Normalized()
		}
	}
	return transportipsec.LinkGroupSpec{ID: spec.OverlayID}.Normalized()
}

func tunnelAddressPrefix(address netip.Addr) string {
	if !address.IsValid() {
		return ""
	}
	bits := 32
	if address.Is6() {
		bits = 128
		if address.IsLinkLocalUnicast() {
			bits = 64
		}
	}
	return netip.PrefixFrom(address, bits).String()
}

func xfrmLinkInspectCandidates(spec transportipsec.TransportLinkSpec, instance transportipsec.LinkInstance) []transportipsec.TransportLinkSpec {
	candidates := []transportipsec.TransportLinkSpec{spec}
	appendCandidate := func(candidate transportipsec.TransportLinkSpec) {
		for _, existing := range candidates {
			if existing.InterfaceName == candidate.InterfaceName && existing.XFRMIfID == candidate.XFRMIfID {
				return
			}
		}
		candidates = append(candidates, candidate)
	}
	if instance.InterfaceName != "" || instance.XFRMIfID != 0 {
		active := spec
		if instance.InterfaceName != "" {
			active.InterfaceName = instance.InterfaceName
		}
		if instance.XFRMIfID != 0 {
			active.XFRMIfID = instance.XFRMIfID
		}
		active.LocalTunnelAddr = instance.LocalTunnelAddr
		active.PeerTunnelAddr = instance.PeerTunnelAddr
		appendCandidate(active)
	}
	if instance.StagedInterfaceName != "" || instance.StagedXFRMIfID != 0 {
		staged := spec
		if instance.StagedInterfaceName != "" {
			staged.InterfaceName = instance.StagedInterfaceName
		}
		if instance.StagedXFRMIfID != 0 {
			staged.XFRMIfID = instance.StagedXFRMIfID
		}
		staged.LocalTunnelAddr = instance.StagedLocalTunnelAddr
		staged.PeerTunnelAddr = instance.StagedPeerTunnelAddr
		appendCandidate(staged)
	}
	return candidates
}

func xfrmCandidateRuntime(base, candidate transportipsec.TransportLinkSpec, instance transportipsec.LinkInstance) string {
	if candidate.InterfaceName == instance.StagedInterfaceName && candidate.XFRMIfID == instance.StagedXFRMIfID {
		return "staged"
	}
	if candidate.InterfaceName == instance.InterfaceName && candidate.XFRMIfID == instance.XFRMIfID {
		return "active"
	}
	if candidate.InterfaceName == base.InterfaceName && candidate.XFRMIfID == base.XFRMIfID {
		return "desired"
	}
	return "candidate"
}

func saMatchesMissingXFRMCandidate(sa transportipsec.SAState, missing map[string][]transportipsec.TransportLinkSpec) bool {
	for _, candidates := range missing {
		for _, spec := range candidates {
			if sa.Name == spec.TransportID || sa.ChildSA == transportipsec.ChildSAName(spec) || spec.XFRMIfID != 0 && sa.XFRMIfID == spec.XFRMIfID {
				return true
			}
		}
	}
	return false
}

func observationFields(phase, instanceID, runtime string, spec transportipsec.TransportLinkSpec, state transportipsec.XFRMLinkState, matches bool, reason string) map[string]any {
	fields := map[string]any{"phase": phase, "instance_id": instanceID, "runtime": runtime, "matched": matches, "reason": reason, "peer": spec.PeerZone.String(), "group": spec.OverlayID, "transport_id": spec.TransportID, "interface": spec.InterfaceName, "xfrm_if_id": spec.XFRMIfID, "requested_netns": spec.NetNS, "observed_netns": state.NetNS.Target(), "namespace_exists": state.NamespaceExists, "interface_exists": state.InterfaceExists, "flags_known": state.FlagsKnown, "interface_up": state.InterfaceUp, "multicast": state.Multicast, "addresses": prefixStrings(state.Addresses)}
	if spec.LocalTunnelAddr.IsValid() {
		fields["expected_local_tunnel_addr"] = spec.LocalTunnelAddr.String()
	}
	if spec.PeerTunnelAddr.IsValid() {
		fields["expected_peer_tunnel_addr"] = spec.PeerTunnelAddr.String()
	}
	return fields
}

func missingLinkFields(spec transportipsec.TransportLinkSpec, reason string, candidates int) map[string]any {
	fields := map[string]any{"instance_id": transportipsec.LinkInstanceID(spec), "peer": spec.PeerZone, "interface": spec.InterfaceName, "netns": spec.NetNS, "reason": reason}
	if candidates > 0 {
		fields["candidates"] = candidates
	}
	return fields
}

func prefixStrings(prefixes []netip.Prefix) []string {
	if len(prefixes) == 0 {
		return nil
	}
	out := make([]string, 0, len(prefixes))
	for _, prefix := range prefixes {
		out = append(out, prefix.String())
	}
	return out
}

func logDebug(logger Logger, event string, fields map[string]any) {
	if logger != nil {
		logger.Debug("ipsec", event, fields)
	}
}

func logWarn(logger Logger, event string, fields map[string]any) {
	if logger != nil {
		logger.Warn("ipsec", event, fields)
	}
}
