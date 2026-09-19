package ipsec

import (
	"errors"
	"net/netip"
	"testing"
	"time"
)

func TestMarkIPsecActionSucceededKeepsSecondaryStandbyDownAfterUpdate(t *testing.T) {
	now := time.Unix(5102, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-b.catofes.",
		PeerZone:      "node-a.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-standby",
		InterfaceName: "phx-standby",
		XFRMIfID:      5102,
	}
	inst := NewLinkInstance(spec, LinkStateDegraded, now)
	inst.InitiatorRole = InitiatorRoleSecondaryStandby
	instances := map[string]LinkInstance{inst.ID: inst}

	RecordActionResult(instances, ReconcileAction{
		Action:   ReconcileActionUpdate,
		Spec:     &spec,
		Instance: &inst,
	}, BackoffPolicy{}, now.Add(time.Second), nil)

	got := instances[inst.ID]
	if got.ActualState != LinkStateDown {
		t.Fatalf("state = %q, want down for standby update", got.ActualState)
	}
}

func TestMarkIPsecRollbackSucceededPreservesRotationBackoff(t *testing.T) {
	now := time.Unix(5103, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-rotate",
		InterfaceName: "phx-rotate",
		XFRMIfID:      5103,
	}
	inst := NewLinkInstance(spec, LinkStateError, now)
	inst.StagedGeneration = 2
	inst.StagedIKEName, inst.StagedChildSAName, inst.StagedInterfaceName = "new-ike", "new-child", "phx-new"
	inst.StagedXFRMIfID = 99
	inst.StagedLocalTunnelAddr, inst.StagedPeerTunnelAddr = netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2")
	inst.StagedAttemptCount, inst.StagedNextAttempt, inst.RotateDeadline = 3, now.Add(time.Second).Unix(), now.Add(time.Minute).Unix()
	inst.RotatePhase = RotatePhaseRollback
	inst.FailureCount = 2
	inst.BackoffUntil = now.Add(10 * time.Second).Unix()
	inst.LastFailure = errors.New("staged sa not established by deadline")
	instances := map[string]LinkInstance{inst.ID: inst}

	RecordActionResult(instances, ReconcileAction{
		Action:   ReconcileActionRollbackRotate,
		Spec:     &spec,
		Instance: &inst,
	}, BackoffPolicy{}, now, nil)

	got := instances[inst.ID]
	if got.FailureCount != inst.FailureCount || got.BackoffUntil != inst.BackoffUntil || got.LastFailure != inst.LastFailure {
		t.Fatalf("rollback cleared failure backoff: %+v", got)
	}
	if got.StagedGeneration != 0 || got.RotatePhase != RotatePhaseIdle ||
		got.StagedIKEName != "" || got.StagedChildSAName != "" || got.StagedInterfaceName != "" || got.StagedXFRMIfID != 0 ||
		got.StagedLocalTunnelAddr.IsValid() || got.StagedPeerTunnelAddr.IsValid() ||
		got.StagedAttemptCount != 0 || got.StagedNextAttempt != 0 || got.RotateDeadline != 0 {
		t.Fatalf("rollback did not clear staged runtime: %+v", got)
	}
}

func TestRecordActionResultRetainsFailedTeardown(t *testing.T) {
	now := time.Unix(5104, 0)
	inst := LinkInstance{ID: "link", InitiatorRole: InitiatorRoleSecondaryTakeover}
	instances := map[string]LinkInstance{}
	action := ReconcileAction{Action: ReconcileActionTeardown, Instance: &inst}
	failure := errors.New("driver unavailable")
	RecordActionResult(instances, action, BackoffPolicy{}, now, failure)
	got := instances[inst.ID]
	if got.ActualState != LinkStateError || !errors.Is(got.LastFailure, failure) || got.FailureCount != 1 || got.BackoffUntil <= now.Unix() || got.TakeoverPhase != TakeoverPhaseCooldown || got.TakeoverUntil <= now.Unix() {
		t.Fatalf("failed teardown lost retry/takeover state: %+v", got)
	}
	RecordActionResult(instances, action, BackoffPolicy{}, now.Add(time.Second), nil)
	if len(instances) != 0 {
		t.Fatal("successful teardown retained instance")
	}
}
