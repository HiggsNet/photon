package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
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
	common := d.State.Common.ReadView()
	runtime := d.State.ReadLinux()
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
			ExcludedPeers:       peerLifecycleExcludedPeers(common.Gossip, now, d.App.Config.PeerLifecycle),
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
	forceUpdates, err := ipsec.LocalAnnounceDNSForceUpdates(ctx, d.App.Config.IPsec.AnnounceDNS, d.App.Config.IPsec.AnnounceDNSReconnectAfter, plan.Desired, instances, sas, dnsResolver)
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
	xfrmObservations, err := platformDriver.ObserveXFRMLinks(ctx, plan.Desired, instances, groups)
	if err != nil {
		d.recordIPsecReconcileError(rev, now.Unix(), err)
		return err
	}
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
	groupSpecs := make(map[string]ipsec.LinkGroupSpec, len(groups))
	groupBackoff := make(map[string]ipsec.BackoffPolicy, len(groups))
	groupRetention := make(map[string]int, len(groups))
	for _, group := range groups {
		normalized := group.Normalized()
		groupSpecs[group.ID] = normalized
		groupBackoff[group.ID] = group.Reconcile.Backoff
		groupRetention[group.ID] = normalized.Reconcile.RotateRetentionSeconds
	}
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
		instance, ok, err := ipsec.RecoverObservedLinkInstance(spec, groupSpecs[spec.OverlayID], generations, connections, sas, xfrmLinks, now)
		if err != nil {
			d.recordIPsecReconcileError(rev, now.Unix(), err)
			return fmt.Errorf("derive observed ipsec runtime: %w", err)
		}
		if ok {
			instances[id] = instance
		}
	}
	result := ipsec.ReconcileLinkInstances(ipsec.ReconcileInputs{
		Desired:               plan.Desired,
		Instances:             instances,
		Connections:           connections,
		SAs:                   sas,
		Now:                   now,
		Revoked:               collectRevokedPeerZones(verified.Network, instances, common.Gossip, now),
		Roles:                 plan.Roles,
		GroupSpecs:            groupSpecs,
		GroupBackoff:          groupBackoff,
		GroupRotateRetention:  groupRetention,
		RotateActivationReady: d.ipsecRotateActivationReady(),
		RotateCutoverReady:    d.ipsecRotateCutoverReady(),
		PrepareStandby:        d.ipsecPrepareStandby,
		TakeoverNotBefore:     d.ipsecTakeoverNotBefore,
		ForceUpdates:          forceUpdates,
	})
	if result.Err != nil {
		d.recordIPsecReconcileError(rev, now.Unix(), result.Err)
		return fmt.Errorf("derive ipsec runtime: %w", result.Err)
	}
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
			ipsec.ReconcileActionTeardown, ipsec.ReconcileActionPrepareRotate, ipsec.ReconcileActionInitiateRotate, ipsec.ReconcileActionCommitRotate,
			ipsec.ReconcileActionRollbackRotate, ipsec.ReconcileActionCleanupRotate:
			group := groupForAction(action, groups)
			if _, err := platformDriver.ApplyIPsecAction(ctx, action, group.NetNS); err != nil {
				markIPsecActionFailed(result.Instances, action, group.Reconcile.Backoff, now, err)
				if saveErr := d.publishIPsecObservation(rev, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, err); saveErr != nil {
					return fmt.Errorf("save failed ipsec reconcile state after apply error %q: %w", err.Error(), saveErr)
				}
				return err
			}
			if shouldAssignIPsecDiagnosticAddresses(action) {
				if err := platformDriver.AssignDiagnosticAddresses(ctx, *action.Spec, diagnosticPrefixes); err != nil {
					markIPsecActionFailed(result.Instances, action, group.Reconcile.Backoff, now, err)
					if saveErr := d.publishIPsecObservation(rev, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, err); saveErr != nil {
						return fmt.Errorf("save failed ipsec reconcile state after diagnostic address error %q: %w", err.Error(), saveErr)
					}
					return err
				}
			}
			markIPsecActionSucceeded(result.Instances, action, now)
		}
	}
	if err := platformDriver.MaintainXFRMInterfaces(ctx, plan.Desired, result.Instances, result.Actions, groups, diagnosticPrefixes, xfrmObservations); err != nil {
		if saveErr := d.publishIPsecObservation(rev, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, err); saveErr != nil {
			return fmt.Errorf("save failed ipsec reconcile state after xfrm maintenance error %q: %w", err.Error(), saveErr)
		}
		return err
	}
	if err := d.publishIPsecObservation(rev, now.Unix(), result.Instances, plan.Desired, sas, result.Actions, plan.Skipped, nil); err != nil {
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
	if !d.App.Config.IPAM.AutoAnnounceAssignedIPs && len(d.App.Config.IPAM.Announce) == 0 {
		return nil
	}
	ars, err := routing.BuildAuthorizedRouteSet(verified.Network, now)
	if err != nil {
		d.logWarn("ipsec", "diagnostic_prefixes_unavailable", map[string]any{"error": err.Error()})
		return nil
	}
	prefixes := routing.AutoAnnounceAssignedPrefixes(ars, verified.ManagedZone, d.App.Config.IPAM.AutoAnnounceAssignedIPs, d.App.Config.IPAM.Announce)
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
		inst.LastFailure = errors.New("xfrm namespace or interface missing")
		inst.LastTransition = now.Unix()
		instances[id] = inst
	}
}

func (d *Daemon) publishIPsecObservation(rev uint64, unix int64, instances map[string]ipsec.LinkInstance, desired []ipsec.TransportLinkSpec, sas []ipsec.SAState, actions []ipsec.ReconcileAction, skips []ipsec.PlanSkip, lastError error) error {
	if d == nil || d.State == nil {
		return nil
	}
	currentRev := uint64(d.State.Common.VerifiedRevision())
	if currentRev != rev {
		d.ipsecDirty = true
		d.logWarn("ipsec", "stale_reconcile_result", map[string]any{
			"source_revision":  rev,
			"current_revision": currentRev,
		})
		return nil
	}
	summary := summarizeIPsecReconcile(rev, unix, desired, sas, actions, skips, lastError)
	d.linuxObservation.replaceIPsec(instances, summary)
	return nil
}

func (d *Daemon) recordIPsecReconcileError(rev uint64, unix int64, err error) {
	if d == nil || d.State == nil || err == nil {
		return
	}
	currentRev := uint64(d.State.Common.VerifiedRevision())
	if currentRev != rev {
		d.ipsecDirty = true
		d.logWarn("ipsec", "stale_reconcile_error", map[string]any{
			"source_revision":  rev,
			"current_revision": currentRev,
			"error":            err,
		})
		return
	}
	links, observedReconcile := d.linuxObservation.ipsecSnapshot()
	reconcile := cloneIPsecObservationSummary(observedReconcile)
	if reconcile == nil {
		reconcile = &ipsecObservationSummary{}
	}
	reconcile.LastRunUnix = unix
	reconcile.SourceRevision = rev
	reconcile.LastFailure = err
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

func summarizeIPsecReconcile(sourceRev uint64, unix int64, desired []ipsec.TransportLinkSpec, sas []ipsec.SAState, actions []ipsec.ReconcileAction, skips []ipsec.PlanSkip, lastError error) *ipsecObservationSummary {
	state := &ipsecObservationSummary{
		LastRunUnix:    unix,
		SourceRevision: sourceRev,
		DesiredLinks:   len(desired),
		LastFailure:    lastError,
	}
	state.Desired = photonlinux.ProjectIPsecDesired(desired)
	state.ActualSAs = photonlinux.ProjectIPsecSAs(sas)
	state.Actions = photonlinux.ProjectIPsecActions(actions)
	for _, skip := range skips {
		state.Skipped = append(state.Skipped, photonstate.LinkSkipObservation{
			GroupID: skip.GroupID,
			Peer:    skip.Peer,
			Reason:  skip.Reason,
			Detail:  skip.Detail,
		})
	}
	return state
}

func injectIPsecKeyMaterial(verified *corestate.VerifiedState, localKey *photonstate.IPsecTransportKeyState, desired []ipsec.TransportLinkSpec) []ipsec.TransportLinkSpec {
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

func groupForAction(action ipsec.ReconcileAction, groups []ipsec.LinkGroupSpec) ipsec.LinkGroupSpec {
	groupID := ""
	if action.Spec != nil {
		groupID = action.Spec.OverlayID
	} else if action.Instance != nil {
		groupID = action.Instance.GroupID
	}
	for _, group := range groups {
		if group.ID == groupID {
			return group
		}
	}
	return ipsec.LinkGroupSpec{}
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
		if inst.RotatePhase != "" && inst.LastFailure != nil {
			inst.LastFailure = fmt.Errorf("rotate %s: %w", inst.RotatePhase, inst.LastFailure)
		}
	}
	if inst.InitiatorRole == ipsec.InitiatorRoleSecondaryTakeover {
		inst.TakeoverPhase = ipsec.TakeoverPhaseCooldown
		inst.TakeoverUntil = now.Add(ipsec.TakeoverCooldownDuration(policy)).Unix()
		inst.LastTakeoverFailure = inst.LastFailure
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
	case ipsec.ReconcileActionRollbackRotate, ipsec.ReconcileActionCleanupRotate:
		if action.Action == ipsec.ReconcileActionRollbackRotate {
			inst.ActualState = ipsec.LinkStateConnecting
			inst.LastTransition = now.Unix()
		}
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
