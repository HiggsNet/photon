package ipsec

import (
	"errors"
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

func TestFailedRotateCommitRetainsBothGenerationsForCleanupRetry(t *testing.T) {
	now := time.Unix(5103, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-rotate",
		InterfaceName: "phx-rotate",
		XFRMIfID:      5103,
	}
	spec.Generation = 1
	inst := NewLinkInstance(spec, LinkStateUp, now)
	inst.StagedGeneration = 2
	inst.StagedIKEName, inst.StagedInterfaceName = "ipsec-rotate-r2", "phx-new"
	inst.RotatePhase = RotatePhaseTestingNew
	promoted := inst
	promoted.RemoteGeneration = inst.StagedGeneration
	promoted.IKEName = inst.StagedIKEName
	promoted.clearStaged(RotatePhaseIdle)
	instances := map[string]LinkInstance{inst.ID: promoted}
	failure := errors.New("delete old interface")

	RecordActionResult(instances, ReconcileAction{
		Action:   ReconcileActionCommitRotate,
		Spec:     &spec,
		Instance: &inst,
	}, BackoffPolicy{}, now, failure)

	got := instances[inst.ID]
	if got.RemoteGeneration != 1 || got.IKEName != inst.IKEName || got.StagedGeneration != 2 || got.StagedIKEName != inst.StagedIKEName || got.BackoffUntil <= now.Unix() || !errors.Is(got.LastFailure, failure) {
		t.Fatalf("failed commit lost resource identity or backoff: %+v", got)
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
