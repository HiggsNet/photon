package ipsec

import (
	"context"
	"net/netip"
	"testing"
	"time"
)

func TestReconcileKeepsHealthySAWhileFuturePortArrives(t *testing.T) {
	now := time.Unix(1792120594, 0)
	spec := duplicateGCTestSpec()
	spec.InitiatorRole = InitiatorRolePrimary
	spec.Generation = 68
	spec.ContactPoints = []ContactPoint{{Address: "198.51.100.10", Generation: 68, IKEPort: 33537, NATTPort: 33538}}
	inst := NewLinkInstance(spec, LinkStateUp, now.Add(-time.Hour))
	healthy := duplicateGCTestSA(spec, 12, true, 240)
	healthy.Endpoint, healthy.RemoteEndpoint = "198.51.100.10:33538", "198.51.100.10:33538"
	future := duplicateGCTestSA(spec, 18, false, 0)
	future.Endpoint, future.RemoteEndpoint = "198.51.100.10:33540", "198.51.100.10:33540"
	for _, sas := range [][]SAState{{healthy, future}, {future, healthy}} {
		result := ReconcileLinkInstances(ReconcileInputs{
			Desired: []TransportLinkSpec{spec}, Instances: map[string]LinkInstance{inst.ID: inst},
			SAs: sas, Roles: map[string]string{inst.ID: InitiatorRolePrimary}, Now: now,
		})
		for _, action := range result.Actions {
			if action.Action != ReconcileActionNoop && action.Action != ReconcileActionAdopt {
				t.Fatalf("working old SA was disrupted: %+v", result.Actions)
			}
		}
		if got := findMatchingSA(sas, spec); got.UniqueID != healthy.UniqueID {
			t.Fatalf("selected SA #%d, want healthy #%d", got.UniqueID, healthy.UniqueID)
		}
	}
}

func TestReconcileEndpointRepairOnlyTerminatesObservedSA(t *testing.T) {
	for _, uniqueID := range []uint64{0, 18} {
		now := time.Unix(1792120594, 0)
		spec := duplicateGCTestSpec()
		spec.InitiatorRole = InitiatorRolePrimary
		spec.Generation = 68
		spec.ContactPoints = []ContactPoint{{Address: "198.51.100.10", Generation: 68, IKEPort: 33537, NATTPort: 33538}}
		inst := NewLinkInstance(spec, LinkStateUp, now.Add(-time.Hour))
		stale := duplicateGCTestSA(spec, uniqueID, true, 240)
		result := ReconcileLinkInstances(ReconcileInputs{
			Desired: []TransportLinkSpec{spec}, Instances: map[string]LinkInstance{inst.ID: inst},
			SAs: []SAState{stale}, Roles: map[string]string{inst.ID: InitiatorRolePrimary}, Now: now,
		})
		action := firstAction(result, ReconcileActionRepair)
		if action == nil || action.SAUniqueID != uniqueID {
			t.Fatalf("actions = %+v, want scoped repair of #%d", result.Actions, uniqueID)
		}
		driver := &DryRunDriver{}
		if _, err := ApplyReconcileAction(context.Background(), driver, driver, *action, NetNSSpec{}); err != nil {
			t.Fatal(err)
		}
		if len(driver.Unloaded) != 0 || len(driver.Terminated) > 1 {
			t.Fatalf("unloaded=%v terminated=%v", driver.Unloaded, driver.Terminated)
		}
		if uniqueID == 0 && len(driver.Terminated) != 0 {
			t.Fatalf("missing unique ID must not cause name-wide termination: %v", driver.Terminated)
		}
		if uniqueID != 0 && (len(driver.Terminated) != 1 || driver.Terminated[0] != "#18") {
			t.Fatalf("terminated=%v, want only #18", driver.Terminated)
		}
	}
}

func TestSASelectionPrefersEstablishedRuntime(t *testing.T) {
	spec := duplicateGCTestSpec()
	inst := NewLinkInstance(spec, LinkStateUp, time.Unix(1000, 0))
	inst.StagedIKEName, inst.StagedChildSAName, inst.StagedXFRMIfID = inst.IKEName, inst.ChildSAName, inst.XFRMIfID
	healthy := duplicateGCTestSA(spec, 12, true, 240)
	connecting := healthy
	connecting.UniqueID, connecting.Established = 18, false
	for _, sas := range [][]SAState{{connecting, healthy}, {healthy, connecting}} {
		for name, got := range map[string]SAState{"instance": findInstanceSA(sas, inst), "desired": findMatchingSA(sas, spec), "staged": findStagedSA(sas, inst)} {
			if got.UniqueID != healthy.UniqueID {
				t.Fatalf("%s selected #%d, want established #%d", name, got.UniqueID, healthy.UniqueID)
			}
		}
	}
}

func TestSecondaryTakeoverRotationWaitsForPrimaryWithBoundedFallback(t *testing.T) {
	for _, scenario := range []string{"primary arrives", "wait expires", "old SA disappears", "prepare retry", "restart"} {
		t.Run(scenario, func(t *testing.T) {
			now := time.Unix(1792120593, 0)
			group := LinkGroupSpec{ID: "main", Reconcile: ReconcilePolicy{RotateRetentionSeconds: 30}}
			base := TransportLinkSpec{LocalZone: "node-b.catofes.", PeerZone: "node-a.catofes.", OverlayID: group.ID,
				Provider: ProviderStrongSwan, LinkID: "link-secondary", PathKey: "family:ipv6", Generation: 69, InitiatorRole: InitiatorRoleSecondaryStandby,
				ContactPoints: []ContactPoint{{Address: "2001:db8::30", Family: FamilyIPv6, Generation: 68, IKEPort: 33537, NATTPort: 33538}},
			}
			desired, err := RuntimeSpecForPortGeneration(base, group, 69)
			if err != nil {
				t.Fatal(err)
			}
			desired.ContactPoints = base.ContactPoints
			previous, err := RuntimeSpecForPortGeneration(base, group, 68)
			if err != nil {
				t.Fatal(err)
			}
			inst := NewLinkInstance(previous, LinkStateUp, now.Add(-time.Hour))
			inst.RemoteGeneration, inst.InitiatorRole = 68, InitiatorRoleSecondaryTakeover
			oldSA := duplicateGCTestSA(previous, 12, true, 240)
			oldSA.RemoteEndpoint, oldSA.Endpoint = "[2001:db8::30]:33538", "[2001:db8::30]:33538"
			input := ReconcileInputs{Desired: []TransportLinkSpec{desired}, Instances: map[string]LinkInstance{inst.ID: inst}, SAs: []SAState{oldSA},
				Roles: map[string]string{inst.ID: InitiatorRoleSecondaryStandby}, GroupSpecs: map[string]LinkGroupSpec{group.ID: group}, Now: now}
			first := ReconcileLinkInstances(input)
			prepare := firstAction(first, ReconcileActionPrepareRotate)
			if prepare == nil || prepare.Spec.InitiatorRole != InitiatorRoleSecondaryStandby {
				t.Fatalf("initial actions=%+v", first.Actions)
			}
			driver := &DryRunDriver{}
			if _, err := ApplyReconcileAction(context.Background(), driver, driver, *prepare, NetNSSpec{}); err != nil {
				t.Fatal(err)
			}
			if len(driver.Initiated) != 0 || len(driver.Terminated) != 0 {
				t.Fatalf("initial initiate=%v terminate=%v", driver.Initiated, driver.Terminated)
			}
			RecordActionResult(first.Instances, *prepare, group.Reconcile.Backoff, now, nil)
			input.Instances = first.Instances
			pending := first.Instances[inst.ID]
			input.Now = now.Add(time.Second)
			waiting := ReconcileLinkInstances(input)
			if len(waiting.Actions) != 1 || waiting.Actions[0].Reason != "awaiting primary rotation" {
				t.Fatalf("waiting actions=%+v", waiting.Actions)
			}
			switch scenario {
			case "primary arrives":
				staged := duplicateGCTestSA(desired, 18, false, 0)
				staged.RemoteEndpoint, staged.Endpoint = oldSA.RemoteEndpoint, oldSA.Endpoint
				input.SAs = []SAState{oldSA, staged}
			case "wait expires":
				input.Now = time.Unix(pending.StagedNextAttempt, 0)
			case "old SA disappears":
				input.SAs = nil
			case "prepare retry":
				pending.RotatePhase = RotatePhasePreparing
				input.Instances[inst.ID] = pending
			case "restart":
				connections := []ConnectionState{{Name: desired.TransportID, LocalIdentity: string(desired.LocalZone), RemoteIdentity: string(desired.PeerZone)}}
				var links []XFRMLinkState
				for _, runtime := range []TransportLinkSpec{desired, previous} {
					links = append(links, XFRMLinkState{NetNS: group.Normalized().NetNS, NamespaceExists: true, InterfaceExists: true,
						InterfaceName: runtime.InterfaceName, XFRMIfID: runtime.XFRMIfID,
						Addresses: []netip.Prefix{netip.PrefixFrom(runtime.LocalTunnelAddr, 64)}})
				}
				recovered, ok, err := RecoverObservedLinkInstance(desired, group, []uint64{69, 68}, connections, []SAState{oldSA}, links, input.Now)
				if err != nil || !ok || recovered.InitiatorRole != InitiatorRoleSecondaryTakeover || recovered.StagedNextAttempt == 0 {
					t.Fatalf("recovery=%+v ok=%v err=%v", recovered, ok, err)
				}
				input.Instances[inst.ID] = recovered
				resumed := ReconcileLinkInstances(input)
				if len(resumed.Actions) != 1 || resumed.Actions[0].Reason != "awaiting primary rotation" {
					t.Fatalf("resumed actions=%+v", resumed.Actions)
				}
				input.Now = time.Unix(recovered.StagedNextAttempt, 0)
			}
			next := ReconcileLinkInstances(input)
			fallback := firstAction(next, ReconcileActionPrepareRotate)
			if scenario == "primary arrives" {
				if fallback != nil || next.Instances[inst.ID].StagedGeneration != 69 {
					t.Fatalf("primary arrival lost staged ownership: %+v", next.Actions)
				}
				return
			}
			if fallback == nil {
				t.Fatalf("next actions=%+v", next.Actions)
			}
			driver = &DryRunDriver{}
			if _, err := ApplyReconcileAction(context.Background(), driver, driver, *fallback, NetNSSpec{}); err != nil {
				t.Fatal(err)
			}
			want := 1
			if scenario == "prepare retry" {
				want = 0
			}
			if len(driver.Initiated) != want || len(driver.Terminated) != 0 {
				t.Fatalf("fallback initiate=%v terminate=%v want=%d", driver.Initiated, driver.Terminated, want)
			}
			if scenario != "prepare retry" && next.Instances[inst.ID].StagedAttemptCount != 1 {
				t.Fatal("first real fallback attempt was not recorded")
			}
		})
	}
}
