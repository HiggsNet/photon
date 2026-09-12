package ipsec

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestReconcileRepairsLoadedConnectionWithoutSA(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone: "node-a.catofes.", PeerZone: "node-b.catofes.", OverlayID: "main",
		Provider: ProviderStrongSwan, LinkID: "link-a", TransportID: "ipsec-a", InitiatorRole: InitiatorRolePrimary,
	}
	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:     []TransportLinkSpec{spec},
		Connections: []ConnectionState{{Name: spec.TransportID, LocalIdentity: string(spec.LocalZone), RemoteIdentity: string(spec.PeerZone)}},
		Now:         now,
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionRepair || result.Actions[0].Reason != "loaded connection has no established sa" {
		t.Fatalf("actions = %+v, want repair of loaded connection", result.Actions)
	}

	result = ReconcileLinkInstances(ReconcileInputs{
		Desired:     []TransportLinkSpec{spec},
		Connections: []ConnectionState{{Name: spec.TransportID, RemoteIdentity: "other.catofes."}},
		Now:         now,
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionCreate {
		t.Fatalf("identity-mismatched actions = %+v, want create", result.Actions)
	}

	result = ReconcileLinkInstances(ReconcileInputs{
		Desired:     []TransportLinkSpec{spec},
		Connections: []ConnectionState{{Name: spec.TransportID}},
		Now:         now,
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionCreate {
		t.Fatalf("identity-missing actions = %+v, want create", result.Actions)
	}
}

func TestReconcileRotateReportsRuntimeDerivationError(t *testing.T) {
	now := time.Unix(1717171717, 0)
	group := LinkGroupSpec{
		ID: "main",
		TunnelAddressSpec: TunnelAddressSpec{
			Mode:   TunnelAddressDerivedPool,
			Family: FamilyIPv6,
		},
	}
	desired := TransportLinkSpec{
		LocalZone: "node-a.catofes.", PeerZone: "node-b.catofes.", OverlayID: group.ID,
		Provider: ProviderStrongSwan, LinkID: "link-a", Generation: 2, InitiatorRole: InitiatorRolePrimary,
	}
	existing := NewLinkInstance(desired, LinkStateUp, now)
	existing.RemoteGeneration = 1

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:    []TransportLinkSpec{desired},
		Instances:  map[string]LinkInstance{existing.ID: existing},
		Now:        now,
		GroupSpecs: map[string]LinkGroupSpec{group.ID: group},
	})
	if result.Err == nil || !strings.Contains(result.Err.Error(), "derived-pool requires a valid pool") {
		t.Fatalf("reconcile error = %v, want runtime derivation failure", result.Err)
	}
	if len(result.Actions) != 0 {
		t.Fatalf("actions = %+v, want no action with an invalid runtime spec", result.Actions)
	}
}

func TestReconcileRecoversPreviousGenerationBeforeRotating(t *testing.T) {
	now := time.Unix(1717171717, 0)
	group := LinkGroupSpec{ID: "main"}
	linkID := StableLinkID("node-a.catofes.", "node-b.catofes.", group.ID, DefaultPathKey)
	desired := TransportLinkSpec{
		LocalZone: "node-a.catofes.", PeerZone: "node-b.catofes.", OverlayID: group.ID,
		Provider: ProviderStrongSwan, LinkID: linkID, PathKey: DefaultPathKey,
		Generation: 2, InitiatorRole: InitiatorRolePrimary,
		ContactPoints: []ContactPoint{
			{Address: "198.51.100.20", Generation: 2, Current: true, IKEPort: 500, NATTPort: 4500},
			{Address: "198.51.100.20", Generation: 1, IKEPort: 500, NATTPort: 4501},
		},
	}
	var err error
	desired, err = RuntimeSpecForPortGeneration(desired, group, 2)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(current): %v", err)
	}
	previous, err := RuntimeSpecForPortGeneration(desired, group, 1)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(previous): %v", err)
	}
	previous.ContactPoints = desired.ContactPoints[1:]
	previousSA := SAState{
		Name: previous.TransportID, ChildSA: ChildSAName(previous), XFRMIfID: previous.XFRMIfID,
		LocalIdentity: string(desired.LocalZone), RemoteIdentity: string(desired.PeerZone),
		RemoteEndpoint: "198.51.100.20:4501", Endpoint: "198.51.100.20:4501", Established: true,
	}
	previousLink := XFRMLinkState{
		NetNS: NetNSSpec{Kind: NetNSName, Name: DefaultNetNSName}, NamespaceExists: true, InterfaceExists: true,
		InterfaceName: previous.InterfaceName, XFRMIfID: previous.XFRMIfID,
		Addresses: []netip.Prefix{netip.PrefixFrom(previous.LocalTunnelAddr, 64)},
	}

	recovered, ok, err := RecoverObservedLinkInstance(desired, group, []uint64{2, 1}, nil, []SAState{previousSA}, []XFRMLinkState{previousLink}, now)
	if err != nil {
		t.Fatalf("RecoverObservedLinkInstance(previous): %v", err)
	}
	if !ok {
		t.Fatal("previous generation was not recovered")
	}
	if recovered.RemoteGeneration != 1 || recovered.IKEName != previous.TransportID {
		t.Fatalf("recovered instance = %+v, want generation 1 runtime", recovered)
	}

	if _, ok, err := RecoverObservedLinkInstance(desired, group, []uint64{1}, nil, []SAState{previousSA}, nil, now); err != nil || ok {
		t.Fatal("previous generation recovered without matching xfrm")
	}
	loaded := ConnectionState{Name: previous.TransportID, LocalIdentity: string(previous.LocalZone), RemoteIdentity: string(previous.PeerZone)}
	connecting, ok, err := RecoverObservedLinkInstance(desired, group, []uint64{2, 1}, []ConnectionState{loaded}, nil, []XFRMLinkState{previousLink}, now)
	if err != nil {
		t.Fatalf("RecoverObservedLinkInstance(loaded): %v", err)
	}
	if !ok || connecting.ActualState != LinkStateConnecting || connecting.RemoteGeneration != 1 {
		t.Fatalf("loaded previous generation = (%+v, %v), want connecting generation 1", connecting, ok)
	}
	loaded.RemoteIdentity = "other.catofes."
	if _, ok, err := RecoverObservedLinkInstance(desired, group, []uint64{2, 1}, []ConnectionState{loaded}, nil, []XFRMLinkState{previousLink}, now); err != nil || ok {
		t.Fatal("previous generation recovered from mismatched connection identity")
	}

	rotating := ReconcileLinkInstances(ReconcileInputs{
		Desired: []TransportLinkSpec{desired}, Instances: map[string]LinkInstance{recovered.ID: recovered}, SAs: []SAState{previousSA}, Now: now.Add(time.Second),
		GroupSpecs: map[string]LinkGroupSpec{group.ID: group},
	})
	if len(rotating.Actions) != 1 || rotating.Actions[0].Action != ReconcileActionPrepareRotate {
		t.Fatalf("post-recovery actions = %+v, want prepare rotate", rotating.Actions)
	}

	standbyDesired := desired
	standbyDesired.InitiatorRole = InitiatorRoleSecondaryStandby
	standbySA := previousSA
	standbyRecovered, ok, err := RecoverObservedLinkInstance(standbyDesired, group, []uint64{2, 1}, nil, []SAState{standbySA}, []XFRMLinkState{previousLink}, now)
	if err != nil {
		t.Fatalf("RecoverObservedLinkInstance(standby): %v", err)
	}
	if !ok {
		t.Fatal("standby previous generation was not recovered")
	}
	standbyRotating := ReconcileLinkInstances(ReconcileInputs{
		Desired: []TransportLinkSpec{standbyDesired}, Instances: map[string]LinkInstance{standbyRecovered.ID: standbyRecovered}, SAs: []SAState{standbySA}, Now: now.Add(time.Second),
		Roles:      map[string]string{LinkInstanceID(standbyDesired): InitiatorRoleSecondaryStandby},
		GroupSpecs: map[string]LinkGroupSpec{group.ID: group},
	})
	if len(standbyRotating.Actions) != 1 || standbyRotating.Actions[0].Action != ReconcileActionPrepareRotate || len(standbyRotating.Actions[0].Spec.ContactPoints) != 0 {
		t.Fatalf("standby post-recovery actions = %+v, want responder-only prepare rotate", standbyRotating.Actions)
	}
}

func TestReconcileRestartRecoversDualGenerationFromObservation(t *testing.T) {
	now := time.Unix(1717171717, 0)
	group := LinkGroupSpec{ID: "main", Reconcile: ReconcilePolicy{RotateRetentionSeconds: 30}}
	linkID := StableLinkID("node-a.catofes.", "node-b.catofes.", group.ID, DefaultPathKey)
	desired := TransportLinkSpec{
		LocalZone: "node-a.catofes.", PeerZone: "node-b.catofes.", OverlayID: group.ID,
		Provider: ProviderStrongSwan, LinkID: linkID, PathKey: DefaultPathKey,
		Generation: 2, InitiatorRole: InitiatorRolePrimary,
		ContactPoints: []ContactPoint{
			{Address: "198.51.100.20", Generation: 2, Current: true, IKEPort: 500, NATTPort: 4500},
			{Address: "198.51.100.20", Generation: 1, IKEPort: 500, NATTPort: 4501},
		},
	}
	current, err := RuntimeSpecForPortGeneration(desired, group, 2)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(current): %v", err)
	}
	previous, err := RuntimeSpecForPortGeneration(desired, group, 1)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(previous): %v", err)
	}
	currentSA := SAState{Name: current.TransportID, ChildSA: ChildSAName(current), XFRMIfID: current.XFRMIfID, Established: true}
	previousSA := SAState{Name: previous.TransportID, ChildSA: ChildSAName(previous), XFRMIfID: previous.XFRMIfID, Established: true}
	currentLink := XFRMLinkState{
		NetNS: group.Normalized().NetNS, NamespaceExists: true, InterfaceExists: true,
		InterfaceName: current.InterfaceName, XFRMIfID: current.XFRMIfID,
		Addresses: []netip.Prefix{netip.PrefixFrom(current.LocalTunnelAddr, current.LocalTunnelAddr.BitLen())},
	}
	previousLink := XFRMLinkState{
		NetNS: group.Normalized().NetNS, NamespaceExists: true, InterfaceExists: true,
		InterfaceName: previous.InterfaceName, XFRMIfID: previous.XFRMIfID,
		Addresses: []netip.Prefix{netip.PrefixFrom(previous.LocalTunnelAddr, previous.LocalTunnelAddr.BitLen())},
	}

	recovered, ok, err := RecoverObservedLinkInstance(
		desired, group, []uint64{2, 1}, nil,
		[]SAState{currentSA, previousSA}, []XFRMLinkState{currentLink, previousLink}, now,
	)
	if err != nil {
		t.Fatalf("RecoverObservedLinkInstance: %v", err)
	}
	if !ok {
		t.Fatal("dual-generation runtime was not recovered")
	}
	if recovered.RemoteGeneration != 1 || recovered.IKEName != previous.TransportID {
		t.Fatalf("active runtime = %+v, want previous generation", recovered)
	}
	if recovered.StagedGeneration != 2 || recovered.StagedIKEName != current.TransportID || recovered.RotatePhase != RotatePhaseTestingNew {
		t.Fatalf("staged runtime = %+v, want current generation reconstructed", recovered)
	}

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:              []TransportLinkSpec{desired},
		Instances:            map[string]LinkInstance{recovered.ID: recovered},
		SAs:                  []SAState{currentSA, previousSA},
		Now:                  now,
		GroupSpecs:           map[string]LinkGroupSpec{group.ID: group},
		GroupRotateRetention: map[string]int{group.ID: 30},
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionNoop || result.Actions[0].Reason != "rotate retention active" {
		t.Fatalf("restart actions = %+v, want restarted rotation retention", result.Actions)
	}
	retained := result.Instances[recovered.ID]
	if retained.RemoteGeneration != 1 || retained.StagedGeneration != 2 || retained.RotatePhase != RotatePhaseDualRunning || retained.RotateDeadline <= now.Unix() {
		t.Fatalf("retained runtime = %+v, want bounded dual-running rotation", retained)
	}
}

func TestRecoverObservedDualGenerationLoadedCurrentRestartsDeadline(t *testing.T) {
	now := time.Unix(1717171717, 0)
	group := LinkGroupSpec{ID: "main"}
	desired := TransportLinkSpec{
		LocalZone: "node-a.catofes.", PeerZone: "node-b.catofes.", OverlayID: group.ID,
		Provider: ProviderStrongSwan, LinkID: "link-a", Generation: 2, InitiatorRole: InitiatorRolePrimary,
		ContactPoints: []ContactPoint{
			{Address: "198.51.100.20", Generation: 2, Current: true},
			{Address: "198.51.100.20", Generation: 1},
		},
	}
	current, err := RuntimeSpecForPortGeneration(desired, group, 2)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(current): %v", err)
	}
	previous, err := RuntimeSpecForPortGeneration(desired, group, 1)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(previous): %v", err)
	}
	connections := []ConnectionState{{Name: current.TransportID, LocalIdentity: string(current.LocalZone), RemoteIdentity: string(current.PeerZone)}}
	previousSA := SAState{Name: previous.TransportID, ChildSA: ChildSAName(previous), XFRMIfID: previous.XFRMIfID, Established: true}
	links := []XFRMLinkState{
		{NetNS: group.Normalized().NetNS, NamespaceExists: true, InterfaceExists: true, InterfaceName: current.InterfaceName, XFRMIfID: current.XFRMIfID, Addresses: []netip.Prefix{netip.PrefixFrom(current.LocalTunnelAddr, current.LocalTunnelAddr.BitLen())}},
		{NetNS: group.Normalized().NetNS, NamespaceExists: true, InterfaceExists: true, InterfaceName: previous.InterfaceName, XFRMIfID: previous.XFRMIfID, Addresses: []netip.Prefix{netip.PrefixFrom(previous.LocalTunnelAddr, previous.LocalTunnelAddr.BitLen())}},
	}

	recovered, ok, err := RecoverObservedLinkInstance(desired, group, []uint64{2, 1}, connections, []SAState{previousSA}, links, now)
	if err != nil || !ok {
		t.Fatalf("RecoverObservedLinkInstance = (%+v, %v, %v)", recovered, ok, err)
	}
	if recovered.RemoteGeneration != 1 || recovered.StagedGeneration != 2 || recovered.RotatePhase != RotatePhaseTestingNew {
		t.Fatalf("recovered runtime = %+v, want previous active and current staged", recovered)
	}
	if recovered.RotateDeadline != now.Add(rotateTimeout()).Unix() {
		t.Fatalf("rotate deadline = %d, want fresh bounded deadline %d", recovered.RotateDeadline, now.Add(rotateTimeout()).Unix())
	}
}

func TestReconcilePrepareRotateOnGenerationChange(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d", len(plan.Desired))
	}
	spec := plan.Desired[0]

	// Existing instance is on generation 1.
	existing := NewLinkInstance(spec, LinkStateUp, now)
	if existing.RemoteGeneration != 1 {
		t.Fatalf("existing.RemoteGeneration = %d, want 1", existing.RemoteGeneration)
	}

	// Planner now sees generation 2 (peer published a rotated port record).
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	plan2, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan2.Desired) != 1 {
		t.Fatalf("desired len = %d", len(plan2.Desired))
	}
	newSpec := plan2.Desired[0]
	if contactGeneration(newSpec) != 2 {
		t.Fatalf("new spec generation = %d, want 2", contactGeneration(newSpec))
	}

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
	})

	action := firstAction(result, ReconcileActionPrepareRotate)
	if action == nil {
		t.Fatalf("expected prepare_rotate action, got %+v", result.Actions)
	}
	if action.Spec == nil {
		t.Fatalf("prepare_rotate action missing spec")
	}
	if action.Spec.TransportID != RuntimeConnectionID(existing.LinkID, 2, existing.TransportKind) {
		t.Fatalf("staged transport id = %q, want %q", action.Spec.TransportID, RuntimeConnectionID(existing.LinkID, 2, existing.TransportKind))
	}
	inst := result.Instances[existing.ID]
	if inst.RotatePhase != RotatePhasePreparing {
		t.Fatalf("rotate phase = %q, want preparing", inst.RotatePhase)
	}
	if inst.StagedGeneration != 2 {
		t.Fatalf("staged generation = %d, want 2", inst.StagedGeneration)
	}
	if inst.StagedIKEName != RuntimeConnectionID(existing.LinkID, 2, existing.TransportKind) {
		t.Fatalf("staged ike name = %q", inst.StagedIKEName)
	}
	if inst.StagedInterfaceName == "" || inst.StagedInterfaceName == existing.InterfaceName {
		t.Fatalf("staged interface = %q, want independent from %q", inst.StagedInterfaceName, existing.InterfaceName)
	}
	if inst.StagedXFRMIfID == 0 || inst.StagedXFRMIfID == existing.XFRMIfID {
		t.Fatalf("staged if_id = %d, want independent from %d", inst.StagedXFRMIfID, existing.XFRMIfID)
	}
	if inst.LocalTunnelAddr != existing.LocalTunnelAddr || inst.PeerTunnelAddr != existing.PeerTunnelAddr {
		t.Fatalf("active tunnel addrs changed before commit: local=%s peer=%s", inst.LocalTunnelAddr, inst.PeerTunnelAddr)
	}
	if inst.StagedLocalTunnelAddr != action.Spec.LocalTunnelAddr || inst.StagedPeerTunnelAddr != action.Spec.PeerTunnelAddr {
		t.Fatalf("staged tunnel addrs = %s/%s, want %s/%s", inst.StagedLocalTunnelAddr, inst.StagedPeerTunnelAddr, action.Spec.LocalTunnelAddr, action.Spec.PeerTunnelAddr)
	}
	if inst.RemoteGeneration != 1 {
		t.Fatalf("remote generation changed before commit = %d", inst.RemoteGeneration)
	}
}

func TestReconcileForceUpdateRebuildsEstablishedSA(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{LocalZone: "node-a.", PeerZone: "node-b.", OverlayID: "main", Provider: ProviderStrongSwan, TransportID: "link-a", InitiatorRole: InitiatorRolePrimary}
	instance := NewLinkInstance(spec, LinkStateUp, now.Add(-time.Hour))
	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{instance.ID: instance},
		SAs:          []SAState{{Name: instance.IKEName, Established: true}},
		Now:          now,
		ForceUpdates: map[string]string{instance.ID: "local announce DNS changed after inbound idle"},
	})
	action := firstAction(result, ReconcileActionUpdate)
	if action == nil || action.Reason != "local announce DNS changed after inbound idle" {
		t.Fatalf("actions = %+v, want forced update", result.Actions)
	}
}

func TestReconcileForceUpdateWaitsForRotateToFinish(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{LocalZone: "node-a.", PeerZone: "node-b.", OverlayID: "main", Provider: ProviderStrongSwan, TransportID: "link-a", InitiatorRole: InitiatorRolePrimary}
	instance := NewLinkInstance(spec, LinkStateUp, now.Add(-time.Hour))
	instance.RotatePhase = RotatePhaseDualRunning
	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{instance.ID: instance},
		SAs:          []SAState{{Name: instance.IKEName, Established: true}},
		Now:          now,
		ForceUpdates: map[string]string{instance.ID: "local announce DNS changed after inbound idle"},
	})
	if action := firstAction(result, ReconcileActionUpdate); action != nil {
		t.Fatalf("actions = %+v, DNS update must wait for rotate", result.Actions)
	}
}

func TestReconcileSecondaryStandbyPreparesResponderRotate(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 || plan.Roles[plan.Desired[0].TransportID] != InitiatorRoleSecondaryStandby {
		t.Fatalf("expected secondary standby plan: %+v", plan)
	}
	spec := plan.Desired[0]
	existing := NewLinkInstance(spec, LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.InitiatorRole = InitiatorRoleConverged

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
		Roles:     plan.Roles,
	})

	action := firstAction(result, ReconcileActionPrepareRotate)
	if action == nil || action.Spec == nil {
		t.Fatalf("expected prepare_rotate, got %+v", result.Actions)
	}
	if action.Spec.InitiatorRole != InitiatorRoleSecondaryStandby {
		t.Fatalf("staged role = %q, want secondary-standby", action.Spec.InitiatorRole)
	}
	if len(action.Spec.ContactPoints) != 0 {
		t.Fatalf("staged contacts = %+v, want responder-only config", action.Spec.ContactPoints)
	}
	inst := result.Instances[existing.ID]
	if inst.RotatePhase != RotatePhasePreparing || inst.StagedGeneration != 2 {
		t.Fatalf("instance = %+v", inst)
	}
}

func TestReconcileRetainsOldGenerationAfterStagedSAObserved(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]
	stagedSpec := mustRuntimeSpecForPortGeneration(newSpec, 2)

	existing := NewLinkInstance(mustRuntimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedSpec.TransportID
	existing.StagedChildSAName = existing.StagedIKEName + "-child"
	existing.StagedInterfaceName = stagedSpec.InterfaceName
	existing.StagedXFRMIfID = stagedSpec.XFRMIfID
	existing.StagedLocalTunnelAddr = stagedSpec.LocalTunnelAddr
	existing.StagedPeerTunnelAddr = stagedSpec.PeerTunnelAddr
	existing.RotatePhase = RotatePhaseTestingNew
	existing.RotateDeadline = now.Add(time.Minute).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{Name: existing.IKEName, Established: true},
			{Name: existing.StagedIKEName, Established: true},
		},
		Now: now,
	})

	action := firstAction(result, ReconcileActionNoop)
	if action == nil {
		t.Fatalf("expected noop while rotate retention is active, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 1 {
		t.Fatalf("remote generation changed during retention = %d", inst.RemoteGeneration)
	}
	if inst.StagedGeneration != 2 {
		t.Fatalf("staged generation = %d, want retained staged generation", inst.StagedGeneration)
	}
	if inst.IKEName != existing.IKEName {
		t.Fatalf("ike name = %q, want old generation %q", inst.IKEName, existing.IKEName)
	}
	if inst.InterfaceName != existing.InterfaceName {
		t.Fatalf("interface = %q, want old interface %q", inst.InterfaceName, existing.InterfaceName)
	}
	if inst.RotatePhase != RotatePhaseDualRunning {
		t.Fatalf("rotate phase = %q, want dual_running", inst.RotatePhase)
	}
	if inst.RotateDeadline != now.Add(time.Hour).Unix() {
		t.Fatalf("rotate deadline = %d, want default 1h retention", inst.RotateDeadline)
	}
}

func TestReconcileSecondaryStandbyDoesNotTakeoverDuringRotateRetention(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 || plan.Roles[plan.Desired[0].TransportID] != InitiatorRoleSecondaryStandby {
		t.Fatalf("expected secondary standby plan: %+v", plan)
	}
	spec := plan.Desired[0]
	inst := NewLinkInstance(spec, LinkStateDown, now)
	inst.InitiatorRole = InitiatorRoleSecondaryStandby
	inst.LastTransition = now.Add(-10 * time.Minute).Unix()
	inst.StagedGeneration = 2
	inst.StagedIKEName = RotateConnectionName(inst.TransportID, 2)
	inst.StagedChildSAName = RotateChildSAName(inst.TransportID, 2)
	inst.RotatePhase = RotatePhaseDualRunning
	inst.RotateDeadline = now.Add(time.Hour).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{spec},
		Instances:    map[string]LinkInstance{inst.ID: inst},
		SAs:          nil,
		Now:          now,
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})
	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionNoop || result.Actions[0].Reason != "rotate_retention_active" {
		t.Fatalf("expected rotate retention noop, got %+v", result.Actions)
	}
	got := result.Instances[inst.ID]
	if got.InitiatorRole != InitiatorRoleSecondaryStandby || got.TakeoverPhase != TakeoverPhaseIdle {
		t.Fatalf("takeover state changed during rotate retention: %+v", got)
	}
}

func TestReconcileCommitsRotateAfterRetentionExpires(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]

	oldSpec, err := RuntimeSpecForPortGeneration(newSpec, group, 1)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(old): %v", err)
	}
	stagedSpec, err := RuntimeSpecForPortGeneration(newSpec, group, 2)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(staged): %v", err)
	}
	existing := NewLinkInstance(oldSpec, LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedSpec.TransportID
	existing.StagedChildSAName = existing.StagedIKEName + "-child"
	existing.StagedInterfaceName = stagedSpec.InterfaceName
	existing.StagedXFRMIfID = stagedSpec.XFRMIfID
	existing.StagedLocalTunnelAddr = oldSpec.LocalTunnelAddr
	existing.StagedPeerTunnelAddr = oldSpec.PeerTunnelAddr
	existing.RotatePhase = RotatePhaseDualRunning
	existing.RotateDeadline = now.Add(-time.Second).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{Name: existing.IKEName, Established: true},
			{Name: existing.StagedIKEName, Established: true},
		},
		Now:        now,
		GroupSpecs: map[string]LinkGroupSpec{group.ID: group},
	})

	action := firstAction(result, ReconcileActionCommitRotate)
	if action == nil {
		t.Fatalf("expected commit_rotate after retention expiry, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 2 {
		t.Fatalf("remote generation = %d, want 2", inst.RemoteGeneration)
	}
	if inst.StagedGeneration != 0 {
		t.Fatalf("staged generation not cleared = %d", inst.StagedGeneration)
	}
	if inst.IKEName != stagedSpec.TransportID {
		t.Fatalf("ike name = %q, want rotated", inst.IKEName)
	}
	if inst.InterfaceName != stagedSpec.InterfaceName {
		t.Fatalf("interface = %q, want promoted staged interface %q", inst.InterfaceName, stagedSpec.InterfaceName)
	}
	if inst.XFRMIfID != stagedSpec.XFRMIfID {
		t.Fatalf("if_id = %d, want promoted staged if_id %d", inst.XFRMIfID, stagedSpec.XFRMIfID)
	}
	if inst.LocalTunnelAddr != stagedSpec.LocalTunnelAddr || inst.PeerTunnelAddr != stagedSpec.PeerTunnelAddr {
		t.Fatalf("promoted tunnel addrs = %s/%s, want derived staged %s/%s", inst.LocalTunnelAddr, inst.PeerTunnelAddr, stagedSpec.LocalTunnelAddr, stagedSpec.PeerTunnelAddr)
	}
}

func TestReconcileCommitsRotateWhenStagedSAAlreadyCurrent(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]
	stagedSpec := mustRuntimeSpecForPortGeneration(newSpec, 2)

	existing := NewLinkInstance(mustRuntimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.IKEName = stagedSpec.TransportID
	existing.ChildSAName = ChildSAName(stagedSpec)
	existing.InterfaceName = stagedSpec.InterfaceName
	existing.XFRMIfID = stagedSpec.XFRMIfID
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedSpec.TransportID
	existing.StagedChildSAName = ChildSAName(stagedSpec)
	existing.StagedInterfaceName = stagedSpec.InterfaceName
	existing.StagedXFRMIfID = stagedSpec.XFRMIfID
	existing.RotatePhase = RotatePhaseDualRunning
	existing.RotateDeadline = now.Add(time.Hour).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{{
			Name:        stagedSpec.TransportID,
			ChildSA:     ChildSAName(stagedSpec),
			XFRMIfID:    stagedSpec.XFRMIfID,
			Established: true,
		}},
		Now: now,
	})

	action := firstAction(result, ReconcileActionNoop)
	if action == nil || action.Reason != "staged sa already current" {
		t.Fatalf("expected noop self-heal action, got %+v", result.Actions)
	}
	if firstAction(result, ReconcileActionCommitRotate) != nil {
		t.Fatalf("unexpected commit_rotate for already-current staged SA: %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 2 || inst.StagedGeneration != 0 || inst.RotatePhase != RotatePhaseIdle {
		t.Fatalf("instance not self-healed: %+v", inst)
	}
	if inst.IKEName != stagedSpec.TransportID || inst.InterfaceName != stagedSpec.InterfaceName || inst.XFRMIfID != stagedSpec.XFRMIfID {
		t.Fatalf("runtime not preserved: %+v", inst)
	}
}

func TestReconcileHoldsRotateWhenRouteCutoverPending(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]
	stagedSpec := mustRuntimeSpecForPortGeneration(newSpec, 2)

	existing := NewLinkInstance(mustRuntimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedSpec.TransportID
	existing.StagedChildSAName = ChildSAName(stagedSpec)
	existing.StagedInterfaceName = stagedSpec.InterfaceName
	existing.StagedXFRMIfID = stagedSpec.XFRMIfID
	existing.RotatePhase = RotatePhaseDualRunning
	existing.RotateDeadline = now.Add(-time.Second).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{Name: existing.IKEName, Established: true},
			{Name: existing.StagedIKEName, Established: true},
		},
		Now:                   now,
		RotateActivationReady: map[string]bool{existing.ID: false},
		RotateCutoverReady:    map[string]bool{existing.ID: false},
	})

	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionNoop || result.Actions[0].Reason != "route_activation_pending" {
		t.Fatalf("expected route activation pending noop, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 1 || inst.StagedGeneration != 2 {
		t.Fatalf("rotate generation changed before route cutover: %+v", inst)
	}
	if inst.IKEName != existing.IKEName || inst.InterfaceName != existing.InterfaceName {
		t.Fatalf("old generation was promoted before route cutover: %+v", inst)
	}
	if inst.RotatePhase != RotatePhaseDualRunning {
		t.Fatalf("rotate phase = %q, want dual_running", inst.RotatePhase)
	}

	result = ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{Name: existing.IKEName, Established: true},
			{Name: existing.StagedIKEName, Established: true},
		},
		Now:                   now,
		RotateActivationReady: map[string]bool{existing.ID: true},
		RotateCutoverReady:    map[string]bool{existing.ID: false},
	})
	if len(result.Actions) != 1 || result.Actions[0].Reason != "route_cutover_pending" {
		t.Fatalf("actions = %+v, want route cutover pending", result.Actions)
	}
	if phase := result.Instances[existing.ID].RotatePhase; phase != RotatePhaseDraining {
		t.Fatalf("rotate phase = %q, want draining", phase)
	}
}

func TestReconcileCommitsRotateWhenOldSADisappearsDuringRetention(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]
	stagedSpec := mustRuntimeSpecForPortGeneration(newSpec, 2)

	existing := NewLinkInstance(mustRuntimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedSpec.TransportID
	existing.StagedChildSAName = ChildSAName(stagedSpec)
	existing.StagedInterfaceName = stagedSpec.InterfaceName
	existing.StagedXFRMIfID = stagedSpec.XFRMIfID
	existing.RotatePhase = RotatePhaseDualRunning
	existing.RotateDeadline = now.Add(time.Hour).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{Name: existing.StagedIKEName, Established: true},
		},
		Now: now,
	})

	action := firstAction(result, ReconcileActionCommitRotate)
	if action == nil {
		t.Fatalf("expected commit_rotate when old SA disappeared, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 2 || inst.IKEName != stagedSpec.TransportID || inst.InterfaceName != stagedSpec.InterfaceName {
		t.Fatalf("instance not promoted to staged generation: %+v", inst)
	}
}

func TestReconcileSecondaryConvergedCommitsRotateWhenOldSADisappears(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-a.catofes."].Records[RecordKeyPorts] = record(t, "node-a.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 || plan.Roles[plan.Desired[0].TransportID] != InitiatorRoleSecondaryStandby {
		t.Fatalf("expected one secondary-standby desired spec: %+v", plan)
	}
	newSpec := plan.Desired[0]
	newSpec.Generation = 2
	stagedSpec := rotateSpecForRole(newSpec, 2, InitiatorRoleSecondaryStandby)

	existing := NewLinkInstance(mustRuntimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.InitiatorRole = InitiatorRoleConverged
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedSpec.TransportID
	existing.StagedChildSAName = ChildSAName(stagedSpec)
	existing.StagedInterfaceName = stagedSpec.InterfaceName
	existing.StagedXFRMIfID = stagedSpec.XFRMIfID
	existing.RotatePhase = RotatePhaseTestingNew
	existing.RotateDeadline = now.Add(-time.Minute).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:      []TransportLinkSpec{newSpec},
		Instances:    map[string]LinkInstance{existing.ID: existing},
		SAs:          []SAState{{Name: existing.StagedIKEName, Established: true, Endpoint: "198.51.100.20:4501"}},
		Now:          now,
		Roles:        plan.Roles,
		GroupBackoff: map[string]BackoffPolicy{group.ID: group.Reconcile.Backoff},
	})

	action := firstAction(result, ReconcileActionCommitRotate)
	if action == nil {
		t.Fatalf("expected commit_rotate when secondary old SA disappeared, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 2 || inst.StagedGeneration != 0 || inst.IKEName != stagedSpec.TransportID {
		t.Fatalf("instance not promoted to staged generation: %+v", inst)
	}
	if inst.InterfaceName != stagedSpec.InterfaceName || inst.XFRMIfID != stagedSpec.XFRMIfID {
		t.Fatalf("staged xfrm not promoted: %+v", inst)
	}
}

func TestReconcileRecoversRotatedRuntimeMetadataFromSA(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		LinkID:        "link-stable",
		TransportID:   RuntimeConnectionID("link-stable", 0, ProviderStrongSwan),
		InterfaceName: "phx-old",
		XFRMIfID:      1001,
		Generation:    2,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	stagedSpec := mustRuntimeSpecForPortGeneration(spec, 2)
	existing := NewLinkInstance(spec, LinkStateUp, now)
	existing.RemoteGeneration = 2
	existing.IKEName = stagedSpec.TransportID
	existing.ChildSAName = ChildSAName(stagedSpec)
	existing.InterfaceName = spec.InterfaceName
	existing.XFRMIfID = spec.XFRMIfID
	existing.DesiredSpecHash = TransportLinkSpecHash(spec)

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{{
			Name:        stagedSpec.TransportID,
			ChildSA:     ChildSAName(stagedSpec),
			XFRMIfID:    stagedSpec.XFRMIfID,
			Endpoint:    "198.51.100.20:4500",
			Established: true,
		}},
		Now: now,
	})

	if len(result.Actions) != 1 || result.Actions[0].Action != ReconcileActionAdopt || result.Actions[0].Reason != "driver runtime metadata recovered" {
		t.Fatalf("expected runtime metadata recovery adopt, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.InterfaceName != stagedSpec.InterfaceName || inst.XFRMIfID != stagedSpec.XFRMIfID {
		t.Fatalf("runtime metadata not recovered: %+v, want interface %s if_id %d", inst, stagedSpec.InterfaceName, stagedSpec.XFRMIfID)
	}
}

func TestReconcileUpdatesWhenEstablishedSAEndpointPortIsStale(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		LinkID:        "link-stable",
		TransportID:   RuntimeConnectionID("link-stable", 0, ProviderStrongSwan),
		InterfaceName: "phx1",
		XFRMIfID:      1001,
		Generation:    1,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 1,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	existing := NewLinkInstance(spec, LinkStateUp, now)
	existing.DesiredSpecHash = TransportLinkSpecHash(spec)

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{{
			Name:           spec.TransportID,
			ChildSA:        ChildSAName(spec),
			XFRMIfID:       spec.XFRMIfID,
			RemoteEndpoint: "198.51.100.20:14500",
			Endpoint:       "198.51.100.20:14500",
			Established:    true,
		}},
		Now: now,
	})

	action := firstAction(result, ReconcileActionUpdate)
	if action == nil || action.Reason != "driver endpoint mismatch" {
		t.Fatalf("actions = %+v, want update for stale endpoint port", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.ActualState != LinkStateConfiguring || inst.Endpoint != "198.51.100.20" {
		t.Fatalf("instance = %+v, want reconfigured desired endpoint", inst)
	}
}

func TestReconcileDoesNotAdoptEstablishedSAWithWrongRemoteIdentity(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-new.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		LinkID:        "link-stable",
		TransportID:   RuntimeConnectionID("link-stable", 0, ProviderStrongSwan),
		InterfaceName: "phx1",
		XFRMIfID:      1001,
		Generation:    1,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 1,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired: []TransportLinkSpec{spec},
		SAs: []SAState{{
			Name:           spec.TransportID,
			ChildSA:        ChildSAName(spec),
			XFRMIfID:       spec.XFRMIfID,
			LocalIdentity:  string(spec.LocalZone),
			RemoteIdentity: "node-old.catofes.",
			Endpoint:       "198.51.100.20:4500",
			Established:    true,
		}},
		Now: now,
	})

	action := firstAction(result, ReconcileActionCreate)
	if action == nil || action.Reason != "missing instance" {
		t.Fatalf("actions = %+v, want create instead of adopting wrong identity", result.Actions)
	}
	inst := result.Instances[LinkInstanceID(spec)]
	if inst.ActualState != LinkStateConfiguring {
		t.Fatalf("instance = %+v, want configuring", inst)
	}
}

func TestReconcileUpdatesWhenEstablishedSAIdentityIsStale(t *testing.T) {
	now := time.Unix(1717171717, 0)
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-new.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		LinkID:        "link-stable",
		TransportID:   RuntimeConnectionID("link-stable", 0, ProviderStrongSwan),
		InterfaceName: "phx1",
		XFRMIfID:      1001,
		Generation:    1,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 1,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	existing := NewLinkInstance(spec, LinkStateUp, now)
	existing.DesiredSpecHash = TransportLinkSpecHash(spec)

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{spec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{{
			Name:           spec.TransportID,
			ChildSA:        ChildSAName(spec),
			XFRMIfID:       spec.XFRMIfID,
			LocalIdentity:  string(spec.LocalZone),
			RemoteIdentity: "node-old.catofes.",
			Endpoint:       "198.51.100.20:4500",
			Established:    true,
		}},
		Now: now,
	})

	action := firstAction(result, ReconcileActionUpdate)
	if action == nil || action.Reason != "driver identity mismatch" {
		t.Fatalf("actions = %+v, want update for stale identity", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.ActualState != LinkStateConfiguring {
		t.Fatalf("instance = %+v, want configuring", inst)
	}
}

func TestReconcileRollbackRotateOnTimeout(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]
	stagedSpec := mustRuntimeSpecForPortGeneration(newSpec, 2)

	existing := NewLinkInstance(mustRuntimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedSpec.TransportID
	existing.StagedChildSAName = existing.StagedIKEName + "-child"
	existing.RotatePhase = RotatePhaseTestingNew
	existing.RotateDeadline = now.Add(-time.Second).Unix()

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
	})

	action := firstAction(result, ReconcileActionRollbackRotate)
	if action == nil {
		t.Fatalf("expected rollback_rotate action, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 1 {
		t.Fatalf("remote generation changed on rollback = %d", inst.RemoteGeneration)
	}
	if inst.StagedGeneration != 0 {
		t.Fatalf("staged generation not cleared = %d", inst.StagedGeneration)
	}
	if inst.RotatePhase != RotatePhaseRollback {
		t.Fatalf("rotate phase = %q, want rollback", inst.RotatePhase)
	}
}

func TestReconcileCleanupStaleStagedGeneration(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 5,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4504},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]
	staleSpec := mustRuntimeSpecForPortGeneration(newSpec, 3)

	existing := NewLinkInstance(newSpec, LinkStateUp, now)
	existing.RemoteGeneration = 2
	existing.StagedGeneration = 3 // stale; desired is 5
	existing.StagedIKEName = staleSpec.TransportID
	existing.StagedChildSAName = existing.StagedIKEName + "-child"
	existing.RotatePhase = RotatePhaseTestingNew

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
	})

	action := firstAction(result, ReconcileActionCleanupRotate)
	if action == nil {
		t.Fatalf("expected cleanup_rotate action, got %+v", result.Actions)
	}
	if action.Spec == nil || action.Spec.TransportID != staleSpec.TransportID {
		t.Fatalf("cleanup spec = %+v", action.Spec)
	}
	inst := result.Instances[existing.ID]
	if inst.RotatePhase != RotatePhaseCleanup {
		t.Fatalf("rotate phase = %q, want cleanup", inst.RotatePhase)
	}
}

func TestReconcileRestartRecoversRotationPhase(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan.Desired[0]
	stagedSpec := mustRuntimeSpecForPortGeneration(newSpec, 2)

	// Simulate the testing_new phase reconstructed from runtime observation.
	existing := NewLinkInstance(mustRuntimeSpecForPortGeneration(newSpec, 1), LinkStateUp, now)
	existing.RemoteGeneration = 1
	existing.IKEName = existing.TransportID
	existing.ChildSAName = ChildSAName(newSpec)
	existing.StagedGeneration = 2
	existing.StagedIKEName = stagedSpec.TransportID
	existing.StagedChildSAName = existing.StagedIKEName + "-child"
	existing.StagedInterfaceName = stagedSpec.InterfaceName
	existing.StagedXFRMIfID = stagedSpec.XFRMIfID
	existing.StagedLocalTunnelAddr = stagedSpec.LocalTunnelAddr
	existing.StagedPeerTunnelAddr = stagedSpec.PeerTunnelAddr
	existing.RotatePhase = RotatePhaseTestingNew
	existing.RotateDeadline = now.Add(time.Minute).Unix()

	// On restart, the staged SA is already observed.
	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs: []SAState{
			{Name: existing.StagedIKEName, Established: true},
		},
		Now: now,
	})

	action := firstAction(result, ReconcileActionCommitRotate)
	if action == nil {
		t.Fatalf("expected commit_rotate after restart when old SA is missing, got %+v", result.Actions)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 2 || inst.StagedGeneration != 0 {
		t.Fatalf("instance not recovered: %+v", inst)
	}
	if inst.IKEName != existing.StagedIKEName {
		t.Fatalf("ike name = %q, want %q", inst.IKEName, existing.StagedIKEName)
	}
	if inst.InterfaceName != stagedSpec.InterfaceName || inst.XFRMIfID != stagedSpec.XFRMIfID {
		t.Fatalf("runtime interface = %s/%d, want staged %s/%d", inst.InterfaceName, inst.XFRMIfID, stagedSpec.InterfaceName, stagedSpec.XFRMIfID)
	}
	if inst.LocalTunnelAddr != stagedSpec.LocalTunnelAddr || inst.PeerTunnelAddr != stagedSpec.PeerTunnelAddr {
		t.Fatalf("tunnel addrs = %s/%s, want staged %s/%s", inst.LocalTunnelAddr, inst.PeerTunnelAddr, stagedSpec.LocalTunnelAddr, stagedSpec.PeerTunnelAddr)
	}
}

func TestReconcileNormalUpdateWhenNoGenerationChange(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	spec := plan.Desired[0]
	existing := NewLinkInstance(spec, LinkStateUp, now)

	// Spec hash differs because tunnel address changed by adding a new address.
	ns.Zones["node-b.catofes."].Records[RecordKeyAddresses] = record(t, "node-b.catofes.", RecordKeyAddresses, RecordTypeAddresses, AddressRecord{
		Version: 1,
		Addresses: []AddressAdvertisement{{
			ID: "b-public2", Source: SourceManualAddress, Address: "198.51.100.21", Priority: 200, TTLSeconds: 300,
		}},
		UpdatedAt: now.Unix(),
	})
	plan2, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan2.Desired[0]
	if contactGeneration(newSpec) != existing.RemoteGeneration {
		t.Fatalf("generation mismatch before normal update test")
	}

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
	})

	if firstAction(result, ReconcileActionPrepareRotate) != nil {
		t.Fatalf("unexpected prepare_rotate action")
	}
	if firstAction(result, ReconcileActionUpdate) == nil {
		t.Fatalf("expected update action, got %+v", result.Actions)
	}
}

func TestReconcileRotateUsesUpdatedEndpointWhenGenerationChanges(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	spec := plan.Desired[0]
	existing := NewLinkInstance(spec, LinkStateUp, now)
	if existing.RemoteGeneration != 1 {
		t.Fatalf("existing.RemoteGeneration = %d, want 1", existing.RemoteGeneration)
	}

	ns.Zones["node-b.catofes."].Records[RecordKeyAddresses] = record(t, "node-b.catofes.", RecordKeyAddresses, RecordTypeAddresses, AddressRecord{
		Version: 1,
		Addresses: []AddressAdvertisement{{
			ID: "b-public2", Source: SourceManualAddress, Address: "198.51.100.21", Priority: 200, TTLSeconds: 300,
		}},
		UpdatedAt: now.Unix(),
	})
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	plan2, err := PlanTransportLinks(context.TODO(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	newSpec := plan2.Desired[0]
	if contactGeneration(newSpec) != 2 {
		t.Fatalf("new spec generation = %d, want 2", contactGeneration(newSpec))
	}

	result := ReconcileLinkInstances(ReconcileInputs{
		Desired:   []TransportLinkSpec{newSpec},
		Instances: map[string]LinkInstance{existing.ID: existing},
		SAs:       []SAState{{Name: existing.IKEName, Established: true}},
		Now:       now,
	})

	action := firstAction(result, ReconcileActionPrepareRotate)
	if action == nil || action.Spec == nil {
		t.Fatalf("expected prepare_rotate action, got %+v", result.Actions)
	}
	if len(action.Spec.ContactPoints) != 1 {
		t.Fatalf("staged contact points = %+v", action.Spec.ContactPoints)
	}
	point := action.Spec.ContactPoints[0]
	if point.Address != "198.51.100.21" || point.Generation != 2 || point.NATTPort != 4501 {
		t.Fatalf("staged contact point = %+v, want new endpoint generation", point)
	}
	inst := result.Instances[existing.ID]
	if inst.RemoteGeneration != 1 || inst.StagedGeneration != 2 || inst.RotatePhase != RotatePhasePreparing {
		t.Fatalf("instance = %+v", inst)
	}
}
