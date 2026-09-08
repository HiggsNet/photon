package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"sort"
	"strings"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func (d *Daemon) reconcileIPsecLinks(ctx context.Context) error {
	if d == nil || d.App == nil || d.App.Config == nil {
		return nil
	}
	common, runtime := d.StateStore.readCommonAndRuntime()
	if common.State == nil || runtime == nil {
		return nil
	}
	rev := uint64(common.Revision)
	verified := common.State
	groups := append([]ipsec.LinkGroupSpec(nil), d.App.Config.IPsec.LinkGroups...)
	if verified.ManagedZone.IsRoot() || !verified.ManagedZone.Valid() {
		return nil
	}
	now := d.now()
	dnsResolver := d.ipsecReconcileDNSResolver()
	plan := ipsec.LinkPlan{}
	if len(groups) > 0 {
		var err error
		plan, err = ipsec.PlanTransportLinks(ctx, verified.Network, verified.ManagedZone, groups, ipsec.LinkPlannerOptions{
			Now:                 now,
			DNSResolver:         dnsResolver,
			ContactPointQuality: d.buildIPsecContactPointQuality(verified, now),
			ExcludedPeers:       peerLifecycleExcludedPeers(runtime.PeerCleanups, common.Gossip, now, d.App.Config.PeerLifecycle),
		})
		if err != nil {
			d.recordIPsecReconcileError(rev, now.Unix(), err)
			return err
		}
		plan.Desired = injectIPsecKeyMaterial(verified, runtime.IPsecTransportKey, plan.Desired)
	}
	if d.linuxDriver == nil {
		err := errors.New("linux driver is not configured")
		d.recordIPsecReconcileError(rev, now.Unix(), err)
		return err
	}
	platformDriver := d.linuxDriver
	connections, err := platformDriver.ListIPsecConnections(ctx)
	if err != nil {
		d.recordIPsecReconcileError(rev, now.Unix(), err)
		return fmt.Errorf("list ipsec connections: %w", err)
	}
	sas, err := platformDriver.ListIPsecSAs(ctx)
	if err != nil {
		d.recordIPsecReconcileError(rev, now.Unix(), err)
		return fmt.Errorf("list ipsec sas: %w", err)
	}
	// Link instances are daemon working memory, not restart input. A fresh
	// process starts empty and reconstructs usable current/previous generations
	// from the connection, SA and XFRM observations below.
	instances, _ := d.linuxObservation.ipsecSnapshot()
	forceUpdates, err := localAnnounceDNSForceUpdates(ctx, d.App.Config.IPsec, plan.Desired, instances, sas, dnsResolver)
	if err != nil {
		d.logWarn("ipsec", "local_announce_dns_check_failed", map[string]any{"error": err.Error()})
	}
	d.logDebug("ipsec", "reconcile_observed", map[string]any{
		"managed_zone": verified.ManagedZone.String(),
		"groups":       len(groups),
		"desired":      len(plan.Desired),
		"instances":    len(instances),
		"connections":  len(connections),
		"sas":          len(sas),
	})
	xfrmObservations := platformDriver.ObserveXFRMLinks(ctx, plan.Desired, instances, groups)
	sas, missingXFRMLinks, err := platformDriver.FilterSAsWithMissingXFRMLinks(ctx, plan.Desired, instances, sas, xfrmObservations)
	if err != nil {
		d.recordIPsecReconcileError(rev, now.Unix(), err)
		return fmt.Errorf("inspect xfrm links: %w", err)
	}
	markMissingXFRMLinkInstances(instances, missingXFRMLinks, now)
	var xfrmLinks []ipsec.XFRMLinkState
	if xfrmObservations != nil {
		xfrmLinks = xfrmObservations.Interfaces
	}
	groupSpecs := groupSpecMap(groups)
	for _, spec := range plan.Desired {
		id := ipsec.LinkInstanceID(spec)
		if _, exists := instances[id]; exists {
			continue
		}
		generationZone := verified.ManagedZone
		if ipsec.IsActiveInitiatorRole(spec.InitiatorRole) {
			generationZone = spec.PeerZone
		}
		generations := ipsecPortGenerations(verified, generationZone, now)
		if instance, ok := ipsec.RecoverObservedLinkInstance(spec, groupSpecs[spec.OverlayID], generations, connections, sas, xfrmLinks, now); ok {
			instances[id] = instance
		}
	}
	result := ipsec.ReconcileLinkInstances(ipsec.ReconcileInputs{
		Desired:               plan.Desired,
		Instances:             instances,
		Connections:           connections,
		SAs:                   sas,
		Now:                   now,
		Revoked:               revokedLinkPeers(verified.Network, linkInstancesFromIPsec(instances), common.Gossip, now),
		Roles:                 plan.Roles,
		GroupSpecs:            groupSpecs,
		GroupBackoff:          groupBackoffMap(groups),
		GroupRotateRetention:  groupRotateRetentionMap(groups),
		RotateActivationReady: d.ipsecRotateActivationReady(),
		RotateCutoverReady:    d.ipsecRotateCutoverReady(),
		PrepareStandby:        d.ipsecPrepareStandby,
		TakeoverNotBefore:     d.ipsecTakeoverNotBefore,
		ForceUpdates:          forceUpdates,
	})
	result.Actions = append(result.Actions, ipsec.PlanDuplicateSAGC(plan.Desired, result.Instances, sas, plan.Roles)...)
	diagnosticPrefixes := d.localIPv6DiagnosticPrefixes(verified, now)
	for _, action := range result.Actions {
		d.logDebug("ipsec", "reconcile_action", ipsecReconcileActionLogFields(action))
		switch action.Action {
		case ipsec.ReconcileActionCleanupDuplicateSA:
			if _, err := platformDriver.ApplyIPsecAction(ctx, action, ipsec.NetNSSpec{}); err != nil {
				d.logWarn("ipsec", "duplicate_sa_gc_failed", map[string]any{
					"sa_unique_id": action.SAUniqueID,
					"error":        err,
				})
			}
		case ipsec.ReconcileActionCreate, ipsec.ReconcileActionUpdate, ipsec.ReconcileActionRepair, ipsec.ReconcileActionPrepareStandby,
			ipsec.ReconcileActionTeardown, ipsec.ReconcileActionPrepareRotate, ipsec.ReconcileActionCommitRotate,
			ipsec.ReconcileActionRollbackRotate, ipsec.ReconcileActionCleanupRotate:
			netns := netnsForAction(action, groups)
			if _, err := platformDriver.ApplyIPsecAction(ctx, action, netns); err != nil {
				markIPsecActionFailed(result.Instances, action, groupBackoffPolicy(action, groups), now, err)
				if saveErr := d.commitIPsecReconcileResult(rev, runtime, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, err.Error()); saveErr != nil {
					return fmt.Errorf("save failed ipsec reconcile state after apply error %q: %w", err.Error(), saveErr)
				}
				return err
			}
			if shouldAssignIPsecDiagnosticAddresses(action) {
				if err := platformDriver.AssignDiagnosticAddresses(ctx, *action.Spec, diagnosticPrefixes); err != nil {
					markIPsecActionFailed(result.Instances, action, groupBackoffPolicy(action, groups), now, err)
					if saveErr := d.commitIPsecReconcileResult(rev, runtime, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, err.Error()); saveErr != nil {
						return fmt.Errorf("save failed ipsec reconcile state after diagnostic address error %q: %w", err.Error(), saveErr)
					}
					return err
				}
			}
			markIPsecActionSucceeded(result.Instances, action, now)
		}
	}
	if err := platformDriver.MaintainXFRMInterfaces(ctx, plan.Desired, result.Instances, result.Actions, groups, diagnosticPrefixes, xfrmObservations); err != nil {
		if saveErr := d.commitIPsecReconcileResult(rev, runtime, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, err.Error()); saveErr != nil {
			return fmt.Errorf("save failed ipsec reconcile state after xfrm maintenance error %q: %w", err.Error(), saveErr)
		}
		return err
	}
	if err := d.commitIPsecReconcileResult(rev, runtime, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, ""); err != nil {
		return fmt.Errorf("save ipsec reconcile state: %w", err)
	}
	return nil
}

func (d *Daemon) ipsecReconcileDNSResolver() ipsec.DNSResolver {
	if d != nil && d.ipsecDNSResolver != nil {
		return d.ipsecDNSResolver
	}
	now := time.Now
	if d != nil {
		now = d.now
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

func (d *Daemon) localIPv6DiagnosticPrefixes(verified *corestate.VerifiedState, now time.Time) []netip.Prefix {
	if d == nil || d.App == nil || d.App.Config == nil || verified == nil || verified.Network == nil {
		return nil
	}
	if !ipamAutoAnnounceEnabled(d.App.Config.IPAM) {
		return nil
	}
	ars, err := routing.BuildAuthorizedRouteSet(verified.Network, now)
	if err != nil {
		d.logWarn("ipsec", "diagnostic_prefixes_unavailable", map[string]any{"error": err.Error()})
		return nil
	}
	prefixes := autoAnnounceAssignedPrefixes(ars, verified.ManagedZone, d.App.Config.IPAM)
	out := prefixes[:0]
	for _, prefix := range prefixes {
		if prefix.Addr().Is6() && prefix.Bits() == 64 {
			out = append(out, prefix.Masked())
		}
	}
	return out
}

func (d *Daemon) ipsecRotateCutoverReady() map[string]bool {
	if d == nil || d.health == nil || d.health.Manager == nil {
		return nil
	}
	return d.health.RotateCutoverReadiness()
}

func (d *Daemon) ipsecRotateActivationReady() map[string]bool {
	if d == nil || d.health == nil || d.health.Manager == nil {
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

func (d *Daemon) commitIPsecReconcileResult(rev uint64, runtime *linuxRuntimeState, unix int64, instances map[string]ipsec.LinkInstance, desired []ipsec.TransportLinkSpec, sas []ipsec.SAState, actions []ipsec.ReconcileAction, skips []ipsec.PlanSkip, lastError string) error {
	if d == nil || d.StateStore == nil || runtime == nil {
		return nil
	}
	summary := summarizeIPsecReconcile(rev, unix, desired, sas, actions, skips, lastError)
	summary.Committed = true
	nextInstances := linkInstancesFromIPsec(instances)
	if ipsecReconcileResultEqual(runtime.LinkInstances, runtime.IPsecReconcile, nextInstances, summary) {
		if d.StateStore.Meta().Revision != rev {
			d.ipsecDirty = true
			d.publishStateStoreRuntimeFlags()
			return nil
		}
		d.linuxObservation.replaceIPsec(instances, summary)
		return nil
	}
	currentRev, committed, err := d.StateStore.commitIPsecIfRevision(rev, runtime.IPsecTransportKey, nextInstances, summary)
	if err != nil {
		return err
	}
	if !committed {
		d.ipsecDirty = true
		d.publishStateStoreRuntimeFlags()
		d.logWarn("ipsec", "stale_reconcile_result", map[string]any{
			"source_revision":  rev,
			"current_revision": currentRev,
		})
		return nil
	}
	d.linuxObservation.replaceIPsec(instances, summary)
	return nil
}

func ipsecReconcileResultEqual(baseInstances map[string]linkInstanceState, baseReconcile *ipsecReconcileState, nextInstances map[string]linkInstanceState, nextReconcile *ipsecReconcileState) bool {
	if !reflect.DeepEqual(baseInstances, nextInstances) {
		return false
	}
	return ipsecReconcileSummaryEqual(baseReconcile, nextReconcile)
}

func ipsecReconcileSummaryEqual(base, next *ipsecReconcileState) bool {
	if base == nil || next == nil {
		return base == nil && next == nil
	}
	base = photonstate.CloneIPsecReconcileState(base)
	next = photonstate.CloneIPsecReconcileState(next)
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

func (d *Daemon) recordIPsecReconcileError(rev uint64, unix int64, err error) {
	if d == nil || d.StateStore == nil || err == nil {
		return
	}
	common, runtime := d.StateStore.readCommonAndRuntime()
	if common.State == nil || runtime == nil || uint64(common.Revision) != rev {
		d.ipsecDirty = true
		d.publishStateStoreRuntimeFlags()
		d.logWarn("ipsec", "stale_reconcile_error", map[string]any{
			"source_revision":  rev,
			"current_revision": common.Revision,
			"error":            err,
		})
		return
	}
	links, observedReconcile := d.linuxObservation.ipsecSnapshot()
	reconcile := photonstate.CloneIPsecReconcileState(observedReconcile)
	if reconcile == nil {
		reconcile = &ipsecReconcileState{}
	}
	reconcile.LastRunUnix = unix
	reconcile.SourceRevision = rev
	reconcile.Committed = true
	reconcile.Stale = false
	reconcile.LastError = err.Error()
	if ipsecReconcileSummaryEqual(observedReconcile, reconcile) {
		return
	}
	linkStates := linkInstancesFromIPsec(links)
	currentRev, committed, commitErr := d.StateStore.commitIPsecIfRevision(rev, runtime.IPsecTransportKey, linkStates, reconcile)
	if commitErr != nil {
		d.logWarn("ipsec", "save_reconcile_error_failed", map[string]any{"error": commitErr})
		return
	}
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
	d.linuxObservation.replaceIPsec(links, reconcile)
}

// buildIPsecContactPointQuality builds a per-peer, per-contact-point quality
// map from the gossip transport's runtime reachability state. This lets the
// IPsec planner deprioritize addresses that are currently in backoff or have
// recent failures, matching the gossip transport's own dialing preferences.
func (d *Daemon) buildIPsecContactPointQuality(verified *corestate.VerifiedState, now time.Time) map[zone.ZonePath]map[string]ipsec.ContactPointQuality {
	if d == nil || d.gossipDriver == nil || d.gossipDriver.Transport() == nil || verified == nil || verified.Network == nil {
		return nil
	}
	transport := d.gossipDriver.Transport()
	ns := verified.Network
	out := make(map[zone.ZonePath]map[string]ipsec.ContactPointQuality)

	for _, peerID := range transport.KnownPeerIDs() {
		peerPath := zone.ZonePath(peerID)
		if !peerPath.Valid() || peerPath.IsRoot() || peerPath == verified.ManagedZone {
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

func revokedLinkPeers(network *zone.NetworkState, instances map[string]linkInstanceState, checkpoint *corestate.GossipCheckpoint, now time.Time) map[zone.ZonePath]bool {
	// Phase 6.4.5: use the comprehensive revoked peer zone collector that
	// covers both LinkInstances and gossip checkpoint peers, so that revocation is detected
	// even for peers that don't have an active link instance yet.
	return collectRevokedPeerZones(network, instances, checkpoint, now)
}

func injectIPsecKeyMaterial(verified *corestate.VerifiedState, localKey *ipsecTransportKeyState, desired []ipsec.TransportLinkSpec) []ipsec.TransportLinkSpec {
	if verified == nil {
		return desired
	}
	out := make([]ipsec.TransportLinkSpec, len(desired))
	for i, spec := range desired {
		if localKey != nil && len(localKey.PrivateKey) > 0 {
			spec.LocalPrivateKey = append([]byte(nil), localKey.PrivateKey...)
			spec.LocalPrivateKeyAlgorithm = localKey.Algorithm
		}
		if verified.Network != nil {
			peerZone := verified.Network.Zones[spec.PeerZone]
			if peerZone == nil {
				out[i] = spec
				continue
			}
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
	case ipsec.ReconcileActionPrepareRotate, ipsec.ReconcileActionCommitRotate, ipsec.ReconcileActionRollbackRotate, ipsec.ReconcileActionCleanupRotate:
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
	inst = ipsec.MarkLinkApplySuccess(inst, now)
	switch action.Action {
	case ipsec.ReconcileActionCreate, ipsec.ReconcileActionUpdate, ipsec.ReconcileActionRepair, ipsec.ReconcileActionPrepareStandby, ipsec.ReconcileActionPrepareRotate:
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

func ipsecPortGenerations(verified *corestate.VerifiedState, node zone.ZonePath, now time.Time) []uint64 {
	if verified == nil || verified.Network == nil || !node.Valid() {
		return nil
	}
	records, err := ipsec.ExtractNodeRecords(verified.Network, node, now)
	if err != nil {
		return nil
	}
	ports := ipsec.PortAdvertisements(records.Ports, now)
	generations := make([]uint64, 0, len(ports))
	for _, port := range ports {
		generations = append(generations, port.Generation)
	}
	return generations
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
