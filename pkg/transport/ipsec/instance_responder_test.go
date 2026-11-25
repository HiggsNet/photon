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

func TestReconcileResponderWaitsForPeerWithoutReapplying(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone: "gateway.catofes.", PeerZone: "client.catofes.", OverlayID: "ipsec-main",
		TransportID: "ipsec-mobile", InterfaceName: "phx-mobile", XFRMIfID: 12, Generation: 1,
	}
	id := LinkInstanceID(spec)
	inputs := ReconcileInputs{Desired: []TransportLinkSpec{spec}, Roles: map[string]string{id: ""}, Now: now}
	driver := &DryRunDriver{}
	created := ReconcileLinkInstances(inputs)
	create := firstAction(created, ReconcileActionCreate)
	if create == nil {
		t.Fatalf("first pass = %+v, want create", created.Actions)
	}
	if _, err := ApplyReconcileAction(t.Context(), driver, driver, *create, NetNSSpec{}); err != nil {
		t.Fatal(err)
	}
	RecordActionResult(created.Instances, *create, BackoffPolicy{}, now, nil)
	initial := created.Instances[id]
	if initial.ActualState != LinkStateWaitingInbound || len(driver.Initiated) != 0 {
		t.Fatalf("after loading responder: state=%q initiated=%v", initial.ActualState, driver.Initiated)
	}
	inputs.Connections, _ = driver.ListConnections(t.Context())
	inputs.Instances = created.Instances
	inputs.Now = now.Add(24 * time.Hour)

	waiting := ReconcileLinkInstances(inputs)
	if len(waiting.Actions) != 1 || waiting.Actions[0].Action != ReconcileActionNoop || waiting.Instances[id] != initial {
		t.Fatalf("offline responder changed after 24h: instance=%+v actions=%+v", waiting.Instances[id], waiting.Actions)
	}

	// An instance left in connecting by the old lifecycle converges to waiting.
	legacy := initial
	legacy.ActualState = LinkStateConnecting
	inputs.Instances[id] = legacy
	waiting = ReconcileLinkInstances(inputs)
	if firstAction(waiting, ReconcileActionNoop) == nil || waiting.Instances[id].ActualState != LinkStateWaitingInbound {
		t.Fatalf("legacy connecting responder = %+v actions=%+v", waiting.Instances[id], waiting.Actions)
	}

	// A restart can adopt the already loaded responder without a peer SA.
	inputs.Instances = nil
	recovered := ReconcileLinkInstances(inputs)
	if firstAction(recovered, ReconcileActionAdopt) == nil || recovered.Instances[id].ActualState != LinkStateWaitingInbound {
		t.Fatalf("recovered responder = %+v actions=%+v", recovered.Instances[id], recovered.Actions)
	}

	inputs.Instances = recovered.Instances
	inputs.SAs = []SAState{{Name: spec.TransportID, Established: true, Endpoint: "192.0.2.2:4500"}}
	connected := ReconcileLinkInstances(inputs)
	if firstAction(connected, ReconcileActionAdopt) == nil || connected.Instances[id].ActualState != LinkStateUp {
		t.Fatalf("inbound SA = %+v actions=%+v", connected.Instances[id], connected.Actions)
	}
	inputs.Instances, inputs.SAs = connected.Instances, nil
	disconnected := ReconcileLinkInstances(inputs)
	if got := disconnected.Instances[id]; firstAction(disconnected, ReconcileActionNoop) == nil || got.ActualState != LinkStateWaitingInbound || got.Endpoint != "" {
		t.Fatalf("SA disappeared: instance=%+v actions=%+v", got, disconnected.Actions)
	}

	inputs.Instances = disconnected.Instances
	for _, change := range []struct {
		name string
		edit func(*ReconcileInputs)
	}{
		{"missing configuration", func(in *ReconcileInputs) { in.Connections = nil }},
		{"missing xfrm", func(in *ReconcileInputs) { in.MissingXFRMLinks = map[string]TransportLinkSpec{id: spec} }},
	} {
		t.Run(change.name, func(t *testing.T) {
			broken := inputs
			change.edit(&broken)
			result := ReconcileLinkInstances(broken)
			if repair := firstAction(result, ReconcileActionRepair); repair == nil || IsActiveInitiatorRole(repair.Spec.InitiatorRole) {
				t.Fatalf("actions = %+v, want passive repair", result.Actions)
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
	peer := ns.Zones["node-b.catofes."]
	profile, err := ParseProfileRecord(peer.Records[RecordKeyProfile])
	if err != nil {
		t.Fatal(err)
	}
	profile.MOBIKE = true
	peer.Records[RecordKeyProfile] = record(t, peer.Path, RecordKeyProfile, RecordTypeProfile, profile)
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
			if !action.Spec.MOBIKE || action.Spec.Generation == previous.Generation {
				t.Fatalf("rotate did not retain MOBIKE on a separate generation: %+v", action.Spec)
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
			RecordActionResult(result.Instances, *action, BackoffPolicy{}, now, nil)
			staged := result.Instances[existing.ID]
			if staged.IKEName != existing.IKEName || staged.StagedGeneration != 2 || staged.ActualState != LinkStateUp || staged.RotateDeadline != 0 {
				t.Fatalf("instance = %+v, want old runtime retained and generation 2 staged", staged)
			}
			inputs.Connections, _ = driver.ListConnections(t.Context())
			inputs.Connections[0].DPDDelay = mobikeDPDDelay(desired)
			// Also cover a deadline recorded by the previous implementation.
			staged.RotateDeadline = now.Add(rotateTimeout()).Unix()
			inputs.Instances[existing.ID] = staged
			inputs.Now = now.Add(24 * time.Hour)
			waiting := ReconcileLinkInstances(inputs)
			if len(waiting.Actions) != 1 || waiting.Actions[0].Action != ReconcileActionNoop || waiting.Actions[0].Reason != "awaiting staged sa" {
				t.Fatalf("actions = %+v, want responder to await peer negotiation", waiting.Actions)
			}
			inputs.SAs = nil
			inputs.MissingDesiredXFRM = map[string]bool{existing.ID: true}
			repair := ReconcileLinkInstances(inputs)
			if firstAction(repair, ReconcileActionPrepareRotate) == nil || firstAction(repair, ReconcileActionCommitRotate) != nil {
				t.Fatalf("actions = %+v, want to repair the missing new interface before promoting", repair.Actions)
			}
			inputs.MissingDesiredXFRM = nil
			waiting = ReconcileLinkInstances(inputs)
			commit := firstAction(waiting, ReconcileActionCommitRotate)
			if commit == nil || commit.Spec.TransportID != previous.TransportID {
				t.Fatalf("actions = %+v, want to retire only the old generation", waiting.Actions)
			}
			_, err = ApplyReconcileAction(t.Context(), driver, driver, *commit, NetNSSpec{})
			if err != nil {
				t.Fatal(err)
			}
			RecordActionResult(waiting.Instances, *commit, BackoffPolicy{}, inputs.Now, nil)
			got := waiting.Instances[existing.ID]
			if got.ActualState != LinkStateWaitingInbound || got.RemoteGeneration != 2 || got.StagedGeneration != 0 || got.FailureCount != 0 {
				t.Fatalf("instance = %+v, want generation 2 ready for inbound with no SA", got)
			}
			if len(driver.Connections) != 1 || driver.Connections[0].TransportID != staged.StagedIKEName || len(driver.Initiated) != 0 {
				t.Fatalf("connections = %+v, initiated = %v, want the same passive config", driver.Connections, driver.Initiated)
			}
			inputs.Instances = waiting.Instances
			inputs.Now = now.Add(48 * time.Hour)
			inputs.SAs = []SAState{{Name: got.IKEName, XFRMIfID: got.XFRMIfID, Established: true}}
			connected := ReconcileLinkInstances(inputs)
			if firstAction(connected, ReconcileActionAdopt) == nil || connected.Instances[existing.ID].ActualState != LinkStateUp {
				t.Fatalf("late inbound SA = %+v, actions = %+v", connected.Instances[existing.ID], connected.Actions)
			}
		})
	}
}

func TestReconcileRecoveredConnectionAppliesMOBIKEPolicy(t *testing.T) {
	now := time.Unix(1717171717, 0)
	for _, enable := range []bool{false, true} {
		spec := TransportLinkSpec{
			LocalZone: "gateway.catofes.", PeerZone: "client.catofes.",
			TransportID: "ipsec-mobile", Generation: 1, MOBIKE: enable,
		}
		recovered := NewLinkInstance(spec, LinkStateUp, now)
		previous := spec
		previous.MOBIKE = !enable
		result := ReconcileLinkInstances(ReconcileInputs{
			Desired:     []TransportLinkSpec{spec},
			Instances:   map[string]LinkInstance{recovered.ID: recovered},
			Roles:       map[string]string{recovered.ID: ""},
			Connections: []ConnectionState{{Name: spec.TransportID, DPDDelay: mobikeDPDDelay(previous)}},
			Now:         now,
		})
		action := firstAction(result, ReconcileActionUpdate)
		if action == nil || action.Spec == nil || action.Spec.MOBIKE != enable {
			t.Fatalf("MOBIKE enable=%t: expected update, got %+v", enable, result.Actions)
		}
	}
}
