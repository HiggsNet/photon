package ipsec

import (
	"errors"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"strings"
	"testing"
	"time"
)

func TestReconcileLinkInstancesCreatesAdoptsRepairsAndTeardowns(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "phx1",
		XFRMIfID:      77,
	}
	result := ReconcileLinkInstances(ReconcileInputs{Desired: []TransportLinkSpec{spec}, Now: now})
	if action := firstAction(result, ReconcileActionCreate); action == nil {
		t.Fatalf("create action missing: %+v", result.Actions)
	}
	instance := result.Instances[LinkInstanceID(spec)]
	if instance.Owner.Manager != "photon" || instance.Owner.Token == "" || instance.DesiredSpecHash == "" {
		t.Fatalf("instance = %+v", instance)
	}
	if err := instance.Owner.Validate(instance); err != nil {
		t.Fatalf("owner should validate: %v", err)
	}

	adopted := ReconcileLinkInstances(ReconcileInputs{
		Desired: []TransportLinkSpec{spec},
		SAs:     []SAState{{Name: spec.TransportID, ChildSA: ChildSAName(spec), XFRMIfID: spec.XFRMIfID, Endpoint: "198.51.100.20", Established: true}},
		Now:     now,
	})
	if action := firstAction(adopted, ReconcileActionAdopt); action == nil {
		t.Fatalf("adopt action missing: %+v", adopted.Actions)
	}
	if adopted.Instances[LinkInstanceID(spec)].ActualState != LinkStateUp {
		t.Fatalf("adopted instance = %+v", adopted.Instances[LinkInstanceID(spec)])
	}

	up := NewLinkInstance(spec, LinkStateUp, now)
	repaired := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{up.ID: up},
		Now:       now.Add(time.Minute),
	})
	if action := firstAction(repaired, ReconcileActionRepair); action == nil {
		t.Fatalf("repair action missing: %+v", repaired.Actions)
	}
	if repaired.Instances[up.ID].ActualState != LinkStateDegraded {
		t.Fatalf("repaired instance = %+v", repaired.Instances[up.ID])
	}

	teardown := ReconcileLinkInstances(ReconcileInputs{
		Instances: map[string]LinkInstance{up.ID: up},
		Now:       now.Add(time.Minute),
	})
	if action := firstAction(teardown, ReconcileActionTeardown); action == nil || action.Reason != "no longer desired" {
		t.Fatalf("teardown action = %+v", teardown.Actions)
	}
}

func TestReconcileLinkInstancesRetainsUnmanagedInstances(t *testing.T) {
	now := time.Unix(1717171717, 0)
	inst := LinkInstance{
		ID:            "manual-conn",
		GroupID:       "main",
		PeerZone:      "node-b.catofes.",
		TransportKind: ProviderStrongSwan,
		TransportID:   "manual-conn",
		ActualState:   LinkStateUp,
		InterfaceName: "admin0",
		XFRMIfID:      77,
		Owner: ResourceOwner{
			Manager:     "admin",
			GroupID:     "main",
			InstanceID:  "manual-conn",
			TransportID: "manual-conn",
		},
	}
	result := ReconcileLinkInstances(ReconcileInputs{
		Instances: map[string]LinkInstance{inst.ID: inst},
		Now:       now,
	})
	action := firstAction(result, ReconcileActionNoop)
	if action == nil || !strings.Contains(action.Reason, "unmanaged resource retained") {
		t.Fatalf("actions = %+v, want retained unmanaged noop", result.Actions)
	}
	if result.Instances[inst.ID].ActualState != LinkStateUp {
		t.Fatalf("instance state changed: %+v", result.Instances[inst.ID])
	}
}

func TestReconcileLinkInstancesRevocationWinsOverDesiredState(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "phx1",
		XFRMIfID:      77,
	}
	result := ReconcileLinkInstances(ReconcileInputs{
		Desired: []TransportLinkSpec{spec},
		Revoked: map[zone.ZonePath]bool{
			"node-b.catofes.": true,
		},
		Now: now,
	})
	action := firstAction(result, ReconcileActionTeardown)
	if action == nil || action.Reason != "peer revoked" {
		t.Fatalf("actions = %+v", result.Actions)
	}
	if result.Instances[LinkInstanceID(spec)].ActualState != LinkStateRemoving {
		t.Fatalf("instance = %+v", result.Instances[LinkInstanceID(spec)])
	}
}

func TestReconcileLinkInstancesHonorsApplyBackoff(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "phx1",
		XFRMIfID:      77,
	}
	inst := NewLinkInstance(spec, LinkStateUp, now)
	inst = MarkLinkApplyFailure(inst, BackoffPolicy{InitialSeconds: 2, MaxSeconds: 8}, now, errors.New("load connection: vici unavailable"))
	if inst.FailureCount != 1 || inst.BackoffUntil != now.Add(2*time.Second).Unix() || inst.LastFailure == nil || inst.LastFailure.Error() != "load connection: vici unavailable" {
		t.Fatalf("failed instance = %+v", inst)
	}
	inst = MarkLinkApplyFailure(inst, BackoffPolicy{InitialSeconds: 2, MaxSeconds: 8}, now.Add(time.Second), errors.New("load connection: vici unavailable"))
	if inst.FailureCount != 2 || inst.BackoffUntil != now.Add(5*time.Second).Unix() {
		t.Fatalf("second failed instance = %+v", inst)
	}

	duringBackoff := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: inst},
		Now:       now.Add(3 * time.Second),
	})
	if action := firstAction(duringBackoff, ReconcileActionNoop); action == nil || action.Reason != "apply backoff active" {
		t.Fatalf("during backoff actions = %+v", duringBackoff.Actions)
	}

	afterBackoff := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: inst},
		Now:       now.Add(6 * time.Second),
	})
	if action := firstAction(afterBackoff, ReconcileActionRepair); action == nil {
		t.Fatalf("after backoff actions = %+v", afterBackoff.Actions)
	}
	cleared := MarkLinkApplySuccess(inst, now.Add(6*time.Second))
	if cleared.FailureCount != 0 || cleared.BackoffUntil != 0 || cleared.LastFailure != nil {
		t.Fatalf("cleared instance = %+v", cleared)
	}
}

func TestReconcileLinkInstancesRetriesConnectingWithoutSAAfterBackoff(t *testing.T) {
	now := time.Unix(1717171717, 0)
	policy := BackoffPolicy{InitialSeconds: 2, MaxSeconds: 8}
	autostartGrace := nextLinkBackoff(policy, 1) + nextLinkBackoff(policy, 2)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "phx1",
		XFRMIfID:      77,
	}
	inst := NewLinkInstance(spec, LinkStateConnecting, now)

	waiting := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: inst},
		Now:       now.Add(time.Second),
		GroupBackoff: map[string]BackoffPolicy{
			spec.OverlayID: policy,
		},
	})
	if action := firstAction(waiting, ReconcileActionNoop); action == nil || action.Reason != "awaiting established sa" {
		t.Fatalf("waiting actions = %+v", waiting.Actions)
	}
	waitingInst := waiting.Instances[inst.ID]
	if waitingInst.ActualState != LinkStateConnecting || waitingInst.FailureCount != 0 || waitingInst.BackoffUntil != 0 {
		t.Fatalf("waiting instance = %+v, want connecting without backoff", waitingInst)
	}

	expired := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: waitingInst},
		Now:       now.Add(autostartGrace + time.Second),
		GroupBackoff: map[string]BackoffPolicy{
			spec.OverlayID: policy,
		},
	})
	if action := firstAction(expired, ReconcileActionNoop); action == nil || action.Reason != "awaiting established sa" {
		t.Fatalf("expired actions = %+v", expired.Actions)
	}
	expiredInst := expired.Instances[inst.ID]
	if expiredInst.ActualState != LinkStateError || expiredInst.FailureCount != 1 || expiredInst.BackoffUntil != now.Add(autostartGrace+3*time.Second).Unix() {
		t.Fatalf("expired instance = %+v, want error with backoff", expiredInst)
	}

	duringBackoff := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: expiredInst},
		Now:       now.Add(autostartGrace + 2*time.Second),
	})
	if action := firstAction(duringBackoff, ReconcileActionNoop); action == nil || action.Reason != "apply backoff active" {
		t.Fatalf("during backoff actions = %+v", duringBackoff.Actions)
	}

	afterBackoff := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: expiredInst},
		Now:       now.Add(autostartGrace + 4*time.Second),
	})
	if action := firstAction(afterBackoff, ReconcileActionRepair); action == nil || action.Reason != "previous apply failed" {
		t.Fatalf("after backoff actions = %+v", afterBackoff.Actions)
	}
	if afterBackoff.Instances[inst.ID].ActualState != LinkStateDegraded {
		t.Fatalf("after backoff instance = %+v, want degraded repair", afterBackoff.Instances[inst.ID])
	}
}

func TestReconcileLinkInstancesWaitsForObservedConnectingSA(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "phx1",
		XFRMIfID:      77,
	}
	inst := NewLinkInstance(spec, LinkStateConnecting, now)

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: inst},
		SAs:       []SAState{{Name: spec.TransportID, IKEState: "CONNECTING"}},
		Now:       now.Add(time.Minute),
	})
	if action := firstAction(result, ReconcileActionNoop); action == nil || action.Reason != "awaiting in-progress sa" {
		t.Fatalf("actions = %+v", result.Actions)
	}
	if got := result.Instances[inst.ID]; got.ActualState != LinkStateConnecting || got.FailureCount != 0 {
		t.Fatalf("instance = %+v, want connecting without failure", got)
	}

	expired := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: inst},
		SAs:       []SAState{{Name: spec.TransportID, IKEState: "CONNECTING"}},
		Now:       now.Add(defaultLinkEstablishGrace + time.Second),
	})
	if action := firstAction(expired, ReconcileActionNoop); action == nil || action.Reason != "awaiting in-progress sa" {
		t.Fatalf("expired actions = %+v", expired.Actions)
	}
	if got := expired.Instances[inst.ID]; got.ActualState != LinkStateError || got.FailureCount != 1 {
		t.Fatalf("expired instance = %+v, want in-progress timeout failure", got)
	}
}

func TestReconcileLinkInstancesEstablishedSAWinsOverBackoff(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "phx1",
		XFRMIfID:      77,
	}
	inst := NewLinkInstance(spec, LinkStateConnecting, now)
	inst = MarkLinkApplyFailure(inst, BackoffPolicy{InitialSeconds: 10, MaxSeconds: 10}, now, errors.New("waiting for established SA"))

	recovered := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{inst.ID: inst},
		SAs: []SAState{{
			Name:        spec.TransportID,
			ChildSA:     ChildSAName(spec),
			XFRMIfID:    spec.XFRMIfID,
			Endpoint:    "198.51.100.20",
			Established: true,
		}},
		Now: now.Add(time.Second),
	})
	if action := firstAction(recovered, ReconcileActionAdopt); action == nil || action.Reason != "driver state recovered" {
		t.Fatalf("recovered actions = %+v", recovered.Actions)
	}
	got := recovered.Instances[inst.ID]
	if got.ActualState != LinkStateUp || got.FailureCount != 0 || got.BackoffUntil != 0 || got.LastFailure != nil {
		t.Fatalf("recovered instance = %+v, want up with cleared backoff", got)
	}
}
