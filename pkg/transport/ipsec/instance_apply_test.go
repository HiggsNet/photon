package ipsec

import (
	"context"
	"net/netip"
	"slices"
	"testing"
	"time"
)

func TestApplyReconcileActionPrepareRotateSkipsPrivateKeyLoad(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:                "node-a.catofes.",
		PeerZone:                 "node-b.catofes.",
		OverlayID:                "ipsec-main",
		Provider:                 ProviderStrongSwan,
		TransportID:              "ipsec-main-ab",
		InterfaceName:            "phx1",
		XFRMIfID:                 77,
		LocalPrivateKey:          []byte("private-key-material"),
		LocalPrivateKeyAlgorithm: AlgorithmEd25519,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   4501,
		}},
	}
	stagedSpec := mustRuntimeSpecForPortGeneration(spec, 2)
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	_, err := ApplyReconcileAction(context.TODO(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action: ReconcileActionPrepareRotate,
		Spec:   &stagedSpec,
	}, NetNSSpec{Kind: NetNSName, Name: "photontesth2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.PrivateKeys) != 0 {
		t.Fatalf("prepare_rotate loaded private keys: %+v", ipsecDrv.PrivateKeys)
	}
	if len(ipsecDrv.Connections) != 1 || ipsecDrv.Connections[0].TransportID != stagedSpec.TransportID {
		t.Fatalf("connections = %+v", ipsecDrv.Connections)
	}
	if len(xfrmDrv.Interfaces) != 1 {
		t.Fatalf("interfaces = %+v", xfrmDrv.Interfaces)
	}
}

func TestApplyReconcileActionPrepareRotateKeepsOldSA(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "phx1",
		XFRMIfID:      77,
		InitiatorRole: InitiatorRolePrimary,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	stagedSpec := mustRuntimeSpecForPortGeneration(spec, 2)
	inst := NewLinkInstance(spec, LinkStateUp, time.Unix(4100, 0))
	inst.IKEName = spec.TransportID
	inst.StagedIKEName = stagedSpec.TransportID
	inst.StagedGeneration = 2

	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	plan, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action:   ReconcileActionPrepareRotate,
		Spec:     &stagedSpec,
		Instance: &inst,
	}, NetNSSpec{Kind: NetNSName, Name: "photontesth2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Terminated) != 0 {
		t.Fatalf("prepare_rotate terminated old SA: %+v", ipsecDrv.Terminated)
	}
	if len(ipsecDrv.Connections) != 1 || ipsecDrv.Connections[0].TransportID != stagedSpec.TransportID {
		t.Fatalf("connections = %+v", ipsecDrv.Connections)
	}
	if len(xfrmDrv.Interfaces) != 1 || xfrmDrv.Interfaces[0].InterfaceName != stagedSpec.InterfaceName {
		t.Fatalf("interfaces = %+v, want staged interface %s", xfrmDrv.Interfaces, stagedSpec.InterfaceName)
	}
	if len(plan.Operations) == 0 || plan.Operations[0].Action == "terminate_sa" {
		t.Fatalf("plan operations = %+v, want no old SA termination", plan.Operations)
	}
}

func TestApplyReconcileActionPrepareResponderRotateKeepsOldSA(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:     "node-b.catofes.",
		PeerZone:      "node-a.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ba",
		InterfaceName: "phx-old",
		XFRMIfID:      77,
	}
	stagedSpec := rotateSpecForRole(spec, 2, InitiatorRoleSecondaryStandby)
	inst := NewLinkInstance(spec, LinkStateUp, time.Unix(4100, 0))
	inst.IKEName = spec.TransportID
	inst.StagedIKEName = stagedSpec.TransportID
	inst.StagedGeneration = 2

	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	_, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action:   ReconcileActionPrepareRotate,
		Spec:     &stagedSpec,
		Instance: &inst,
	}, NetNSSpec{Kind: NetNSName, Name: "photontesth2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Terminated) != 0 {
		t.Fatalf("prepare_rotate terminated old SA: %+v", ipsecDrv.Terminated)
	}
	if len(ipsecDrv.Unloaded) == 0 || ipsecDrv.Unloaded[0] != spec.TransportID {
		t.Fatalf("unloaded = %+v, want old %s", ipsecDrv.Unloaded, spec.TransportID)
	}
	if len(ipsecDrv.Connections) != 1 || ipsecDrv.Connections[0].TransportID != stagedSpec.TransportID {
		t.Fatalf("connections = %+v, want staged %s", ipsecDrv.Connections, stagedSpec.TransportID)
	}
}

func TestApplyReconcileActionRepairInitiatesChild(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		OverlayID:       "ipsec-main",
		Provider:        ProviderStrongSwan,
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "phx1",
		XFRMIfID:        77,
		InitiatorRole:   InitiatorRolePrimary,
		LocalTunnelAddr: netip.MustParseAddr("fd00:1234::1"),
		ContactPoints: []ContactPoint{{
			Address:  "198.51.100.20",
			Family:   FamilyIPv4,
			IKEPort:  DefaultIKEPort,
			NATTPort: DefaultNATTPort,
		}},
	}
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	plan, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action: ReconcileActionRepair,
		Spec:   &spec,
	}, NetNSSpec{Kind: NetNSName, Name: "photontesth2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Initiated) != 1 || ipsecDrv.Initiated[0] != ChildSAName(spec) {
		t.Fatalf("initiated = %+v", ipsecDrv.Initiated)
	}
	last := plan.Operations[len(plan.Operations)-1]
	if last.Action != "initiate_child" || last.Target != ChildSAName(spec) {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestApplyReconcileActionCreateInitiatesActiveChild(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		OverlayID:       "ipsec-main",
		Provider:        ProviderStrongSwan,
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "phx1",
		XFRMIfID:        77,
		InitiatorRole:   InitiatorRoleSecondaryTakeover,
		LocalTunnelAddr: netip.MustParseAddr("fd00:1234::1"),
		ContactPoints: []ContactPoint{{
			Address:  "198.51.100.20",
			Family:   FamilyIPv4,
			IKEPort:  DefaultIKEPort,
			NATTPort: DefaultNATTPort,
		}},
	}
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	plan, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action: ReconcileActionCreate,
		Spec:   &spec,
	}, NetNSSpec{Kind: NetNSName, Name: "photontesth2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Initiated) != 1 || ipsecDrv.Initiated[0] != ChildSAName(spec) {
		t.Fatalf("initiated = %+v", ipsecDrv.Initiated)
	}
	last := plan.Operations[len(plan.Operations)-1]
	if last.Action != "initiate_child" || last.Target != ChildSAName(spec) {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestApplyReconcileActionUpdateReplacesOldConnectionBeforeLoad(t *testing.T) {
	oldSpec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "phx1",
		XFRMIfID:      77,
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 1,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	newSpec := oldSpec
	newSpec.InitiatorRole = InitiatorRolePrimary
	newSpec.ContactPoints = []ContactPoint{{
		Address:    "198.51.100.20",
		Family:     FamilyIPv4,
		Generation: 2,
		IKEPort:    30001,
		NATTPort:   30002,
	}}
	inst := NewLinkInstance(oldSpec, LinkStateUp, time.Unix(4100, 0))

	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	plan, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action:   ReconcileActionUpdate,
		Spec:     &newSpec,
		Instance: &inst,
	}, NetNSSpec{Kind: NetNSName, Name: "photontesth2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Terminated) != 1 || ipsecDrv.Terminated[0] != oldSpec.TransportID {
		t.Fatalf("terminated = %+v, want old %s", ipsecDrv.Terminated, oldSpec.TransportID)
	}
	if len(ipsecDrv.Unloaded) != 1 || ipsecDrv.Unloaded[0] != oldSpec.TransportID {
		t.Fatalf("unloaded = %+v, want old %s", ipsecDrv.Unloaded, oldSpec.TransportID)
	}
	if len(ipsecDrv.Connections) != 1 || ipsecDrv.Connections[0].ContactPoints[0].IKEPort != 30001 {
		t.Fatalf("connections = %+v, want new port spec", ipsecDrv.Connections)
	}
	if len(ipsecDrv.Initiated) != 1 || ipsecDrv.Initiated[0] != ChildSAName(newSpec) {
		t.Fatalf("initiated = %+v, want updated child", ipsecDrv.Initiated)
	}
	last := plan.Operations[len(plan.Operations)-1]
	if last.Action != "initiate_child" || last.Target != ChildSAName(newSpec) {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestApplyReconcileActionPrepareRotateUnloadsBaseConfig(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		OverlayID:       "ipsec-main",
		Provider:        ProviderStrongSwan,
		LinkID:          "link-stable",
		TransportID:     RuntimeConnectionID("link-stable", 2, ProviderStrongSwan),
		InterfaceName:   "phx2",
		XFRMIfID:        78,
		InitiatorRole:   InitiatorRolePrimary,
		LocalTunnelAddr: netip.MustParseAddr("fd00:1234::2"),
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	inst := LinkInstance{IKEName: RuntimeConnectionID("link-stable", 0, ProviderStrongSwan)}
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	if _, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action:   ReconcileActionPrepareRotate,
		Spec:     &spec,
		Instance: &inst,
	}, NetNSSpec{Kind: NetNSName, Name: "photontesth2", Create: true}); err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if !slices.Contains(ipsecDrv.Unloaded, inst.IKEName) {
		t.Fatalf("unloaded = %+v, want base config %s", ipsecDrv.Unloaded, inst.IKEName)
	}
	if len(ipsecDrv.Terminated) != 0 {
		t.Fatalf("prepare_rotate terminated old SA: %+v", ipsecDrv.Terminated)
	}
}

func TestApplyReconcileActionCommitRotateTeardownsOldGeneration(t *testing.T) {
	oldSpec := TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ab",
		InterfaceName: "phx1",
		XFRMIfID:      77,
	}
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	_, err := ApplyReconcileAction(context.TODO(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action: ReconcileActionCommitRotate,
		Spec:   &oldSpec,
	}, NetNSSpec{})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Terminated) != 1 || ipsecDrv.Terminated[0] != oldSpec.TransportID {
		t.Fatalf("terminated = %+v", ipsecDrv.Terminated)
	}
	if len(ipsecDrv.Unloaded) != 1 || ipsecDrv.Unloaded[0] != oldSpec.TransportID {
		t.Fatalf("unloaded = %+v", ipsecDrv.Unloaded)
	}
	if len(xfrmDrv.DeletedIFs) != 1 || xfrmDrv.DeletedIFs[0] != oldSpec.InterfaceName {
		t.Fatalf("deleted interfaces = %+v", xfrmDrv.DeletedIFs)
	}
}

func TestApplyReconcileActionPrepareRotateInitiatesActiveChild(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		OverlayID:       "ipsec-main",
		Provider:        ProviderStrongSwan,
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "phx1",
		XFRMIfID:        77,
		InitiatorRole:   InitiatorRolePrimary,
		LocalTunnelAddr: netip.MustParseAddr("fd00:1234::1"),
		ContactPoints: []ContactPoint{{
			Address:    "198.51.100.20",
			Family:     FamilyIPv4,
			Generation: 2,
			IKEPort:    DefaultIKEPort,
			NATTPort:   DefaultNATTPort,
		}},
	}
	stagedSpec := mustRuntimeSpecForPortGeneration(spec, 2)
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	plan, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action: ReconcileActionPrepareRotate,
		Spec:   &stagedSpec,
	}, NetNSSpec{Kind: NetNSName, Name: "photontesth2", Create: true})
	if err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Initiated) != 1 || ipsecDrv.Initiated[0] != ChildSAName(stagedSpec) {
		t.Fatalf("initiated = %+v, want %s", ipsecDrv.Initiated, ChildSAName(stagedSpec))
	}
	last := plan.Operations[len(plan.Operations)-1]
	if last.Action != "initiate_child" || last.Target != ChildSAName(stagedSpec) {
		t.Fatalf("plan = %+v", plan)
	}
}

func TestApplyReconcileActionPrepareRotateResponderDoesNotInitiate(t *testing.T) {
	spec := TransportLinkSpec{
		LocalZone:     "node-b.catofes.",
		PeerZone:      "node-a.catofes.",
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		TransportID:   "ipsec-main-ba",
		InterfaceName: "phx1",
		XFRMIfID:      77,
	}
	stagedSpec := rotateSpecForRole(spec, 2, InitiatorRoleSecondaryStandby)
	ipsecDrv := &DryRunDriver{}
	xfrmDrv := &DryRunDriver{}
	if _, err := ApplyReconcileAction(context.Background(), ipsecDrv, xfrmDrv, ReconcileAction{
		Action: ReconcileActionPrepareRotate,
		Spec:   &stagedSpec,
	}, NetNSSpec{Kind: NetNSName, Name: "photontesth2", Create: true}); err != nil {
		t.Fatalf("ApplyReconcileAction: %v", err)
	}
	if len(ipsecDrv.Initiated) != 0 {
		t.Fatalf("responder initiated = %+v, want none", ipsecDrv.Initiated)
	}
}
