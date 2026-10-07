package ipsec

import (
	"context"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestRoleForSpecPreservesExplicitResponder(t *testing.T) {
	spec := TransportLinkSpec{TransportID: "ipsec-runtime"}
	for _, tt := range []struct {
		name  string
		roles map[string]string
		want  string
	}{
		{name: "legacy default", want: InitiatorRolePrimary},
		{name: "missing role", roles: map[string]string{}, want: InitiatorRolePrimary},
		{name: "responder by link", roles: map[string]string{"link-a": ""}},
		{name: "responder by runtime", roles: map[string]string{spec.TransportID: ""}},
		{name: "link takes precedence", roles: map[string]string{"link-a": "", spec.TransportID: InitiatorRolePrimary}},
		{name: "primary", roles: map[string]string{"link-a": InitiatorRolePrimary}, want: InitiatorRolePrimary},
		{name: "standby", roles: map[string]string{"link-a": InitiatorRoleSecondaryStandby}, want: InitiatorRoleSecondaryStandby},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if got := roleForSpec("link-a", spec, tt.roles); got != tt.want {
				t.Fatalf("role = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestReconcileResponderPortRotation(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, nil, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleOut, []AddressAdvertisement{
		{ID: "b-v4", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100},
		{ID: "b-v6", Source: SourceManualAddress, Address: "2001:db8::20", Priority: 100},
	}, now)
	ns.Zones["node-a.catofes."].Records[RecordKeyPorts] = record(t, "node-a.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1, Mode: PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: 500},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil || len(plan.Desired) != 2 {
		t.Fatalf("plan = %+v, error = %v, want two passive family paths", plan, err)
	}
	for _, desired := range plan.Desired {
		t.Run(desired.PathKey, func(t *testing.T) {
			previous, err := RuntimeSpecForPortGeneration(desired, group, 1)
			if err != nil {
				t.Fatal(err)
			}
			existing := NewLinkInstance(previous, LinkStateUp, now)
			existing.RemoteGeneration = 1
			oldSA := SAState{Name: existing.IKEName, Established: true}
			inputs := ReconcileInputs{
				Desired:    []TransportLinkSpec{desired},
				Roles:      plan.Roles,
				Instances:  map[string]LinkInstance{existing.ID: existing},
				SAs:        []SAState{oldSA},
				GroupSpecs: map[string]LinkGroupSpec{group.ID: group},
				Now:        now,
			}
			result := ReconcileLinkInstances(inputs)
			action := firstAction(result, ReconcileActionPrepareRotate)
			if action == nil || action.Spec == nil {
				t.Fatalf("actions = %+v, want prepare_rotate", result.Actions)
			}
			if action.Spec.InitiatorRole != "" || len(action.Spec.ContactPoints) != 0 {
				t.Fatalf("staged role = %q, contacts = %+v, want passive responder", action.Spec.InitiatorRole, action.Spec.ContactPoints)
			}
			if _, err := BuildStrongSwanConnection(*action.Spec); err != nil {
				t.Fatalf("staged connection: %v", err)
			}
			driver := &DryRunDriver{}
			if _, err := ApplyReconcileAction(context.Background(), driver, driver, *action, NetNSSpec{}); err != nil {
				t.Fatal(err)
			}
			if len(driver.Connections) != 1 || len(driver.Initiated) != 0 {
				t.Fatalf("loaded = %d, initiated = %v, want one passive connection", len(driver.Connections), driver.Initiated)
			}
			staged := result.Instances[existing.ID]
			if staged.IKEName != existing.IKEName || staged.StagedGeneration != 2 {
				t.Fatalf("instance = %+v, want old runtime retained and generation 2 staged", staged)
			}
			staged.RotatePhase = RotatePhaseTestingNew
			inputs.Instances[existing.ID] = staged
			inputs.Now = now.Add(10 * time.Second)
			waiting := ReconcileLinkInstances(inputs)
			if len(waiting.Actions) != 1 || waiting.Actions[0].Action != ReconcileActionNoop || waiting.Actions[0].Reason != "awaiting staged sa" {
				t.Fatalf("actions = %+v, want responder to await peer negotiation", waiting.Actions)
			}
		})
	}
}
