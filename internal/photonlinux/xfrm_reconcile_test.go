package photonlinux

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type observedXFRMDriver struct {
	ipsec.DryRunDriver
	linkState *ipsec.XFRMLinkState
}

func (d *observedXFRMDriver) InspectLink(_ context.Context, spec ipsec.TransportLinkSpec) (ipsec.XFRMLinkState, error) {
	if d.linkState != nil {
		return *d.linkState, nil
	}
	state := ipsec.XFRMLinkState{
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: spec.NetNS}.Normalized(),
		NamespaceExists: true,
		InterfaceExists: true,
	}
	if spec.LocalTunnelAddr.IsValid() {
		state.Addresses = []netip.Prefix{netip.PrefixFrom(spec.LocalTunnelAddr, 128)}
	}
	return state, nil
}

type batchObservedIPsecDriver struct {
	observedXFRMDriver
	batchErr           error
	batchCalls         int
	inspectCalls       int
	observedEnsureCall int
}

func (d *batchObservedIPsecDriver) InspectLinks(_ context.Context, specs []ipsec.TransportLinkSpec, _ []ipsec.NetNSSpec) ([]ipsec.XFRMLinkState, []ipsec.XFRMLinkState, error) {
	d.batchCalls++
	if d.batchErr != nil {
		return nil, nil, d.batchErr
	}
	states := make([]ipsec.XFRMLinkState, len(specs))
	for i, spec := range specs {
		states[i] = healthyObservedXFRMState(spec)
	}
	inventory := append([]ipsec.XFRMLinkState(nil), states...)
	return states, inventory, nil
}

func (d *batchObservedIPsecDriver) InspectLink(ctx context.Context, spec ipsec.TransportLinkSpec) (ipsec.XFRMLinkState, error) {
	d.inspectCalls++
	return d.observedXFRMDriver.InspectLink(ctx, spec)
}

func (d *batchObservedIPsecDriver) EnsureObservedInterfaces(context.Context, []ipsec.XFRMObservedInterface) error {
	d.observedEnsureCall++
	return nil
}

func healthyObservedXFRMState(spec ipsec.TransportLinkSpec) ipsec.XFRMLinkState {
	state := ipsec.XFRMLinkState{
		NetNS:                    ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: spec.NetNS}.Normalized(),
		NamespaceExists:          true,
		InterfaceExists:          true,
		FlagsKnown:               true,
		InterfaceUp:              true,
		Multicast:                true,
		IPv6AddrGenModeKnown:     true,
		IPv6AddrGenDisabled:      true,
		NamespaceForwardingKnown: true,
		NamespaceForwarding:      true,
		InterfaceForwardingKnown: true,
		InterfaceForwarding:      true,
	}
	if spec.LocalTunnelAddr.IsValid() {
		state.Addresses = []netip.Prefix{netip.PrefixFrom(spec.LocalTunnelAddr, 128)}
	}
	return state
}

func TestXFRMReconcileReusesHealthyBatchObservation(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		LocalZone:       "node-a.catofes.",
		PeerZone:        "node-b.catofes.",
		OverlayID:       "main",
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "phx1",
		NetNS:           "photon",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, time.Unix(4000, 0))
	driver := &batchObservedIPsecDriver{}
	platformDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})
	instances := map[string]ipsec.LinkInstance{inst.ID: inst}

	observed, err := platformDriver.ObserveXFRMLinks(context.Background(), []ipsec.TransportLinkSpec{spec}, instances, nil)
	if err != nil {
		t.Fatalf("ObserveXFRMLinks: %v", err)
	}
	if observed == nil || driver.batchCalls != 1 {
		t.Fatalf("batch observation = %v, calls = %d", observed, driver.batchCalls)
	}
	if _, missing, err := platformDriver.FilterSAsWithMissingXFRMLinks(context.Background(), []ipsec.TransportLinkSpec{spec}, instances, nil, observed); err != nil {
		t.Fatalf("filterSAsWithMissingXFRMLinks: %v", err)
	} else if len(missing) != 0 {
		t.Fatalf("missing = %+v, want none", missing)
	}
	if err := platformDriver.MaintainXFRMInterfaces(context.Background(), []ipsec.TransportLinkSpec{spec}, instances, []ipsec.ReconcileAction{{Action: ipsec.ReconcileActionNoop, Instance: &inst}}, nil, nil, observed); err != nil {
		t.Fatalf("maintainExistingXFRMInterfaces: %v", err)
	}
	if driver.inspectCalls != 0 || driver.observedEnsureCall != 0 || len(driver.Interfaces) != 0 || len(driver.Addresses) != 0 {
		t.Fatalf("healthy batch caused work: inspect=%d ensure=%d interfaces=%v addresses=%v", driver.inspectCalls, driver.observedEnsureCall, driver.Interfaces, driver.Addresses)
	}
}

func TestXFRMReconcileFallsBackWhenBatchObservationFails(t *testing.T) {
	spec := ipsec.TransportLinkSpec{TransportID: "ipsec-main-ab", InterfaceName: "phx1", NetNS: "photon", LocalTunnelAddr: netip.MustParseAddr("fe80::1")}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, time.Unix(4000, 0))
	driver := &batchObservedIPsecDriver{batchErr: errors.New("unsupported iproute2 JSON")}
	platformDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})
	instances := map[string]ipsec.LinkInstance{inst.ID: inst}

	observed, err := platformDriver.ObserveXFRMLinks(context.Background(), []ipsec.TransportLinkSpec{spec}, instances, nil)
	if err != nil {
		t.Fatalf("ObserveXFRMLinks: %v", err)
	}
	if observed != nil {
		t.Fatal("failed batch observation should return nil for fail-closed fallback")
	}
	if _, _, err := platformDriver.FilterSAsWithMissingXFRMLinks(context.Background(), []ipsec.TransportLinkSpec{spec}, instances, nil, observed); err != nil {
		t.Fatalf("fallback filter: %v", err)
	}
	if driver.inspectCalls == 0 {
		t.Fatal("fallback did not use per-interface inspection")
	}
}

func TestXFRMObservationReportsRuntimeDerivationError(t *testing.T) {
	group := ipsec.LinkGroupSpec{
		ID: "main",
		TunnelAddressSpec: ipsec.TunnelAddressSpec{
			Mode:   ipsec.TunnelAddressDerivedPool,
			Family: ipsec.FamilyIPv6,
		},
	}
	spec := ipsec.TransportLinkSpec{
		LocalZone: "node-a.catofes.", PeerZone: "node-b.catofes.",
		OverlayID: group.ID, Provider: ipsec.ProviderStrongSwan,
		LinkID: "link-a", Generation: 2,
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, time.Unix(4000, 0))
	inst.RemoteGeneration = 1
	inst.InterfaceName = "phx-old"
	inst.XFRMIfID = 42
	driver := &batchObservedIPsecDriver{}
	platformDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})

	observed, err := platformDriver.ObserveXFRMLinks(
		context.Background(), []ipsec.TransportLinkSpec{spec},
		map[string]ipsec.LinkInstance{inst.ID: inst}, []ipsec.LinkGroupSpec{group},
	)
	if err == nil {
		t.Fatal("ObserveXFRMLinks error = nil, want runtime derivation error")
	}
	if observed != nil || driver.batchCalls != 0 {
		t.Fatalf("observation = %v, batch calls = %d, want fail before platform inspection", observed, driver.batchCalls)
	}
}

func TestMaintainXFRMInterfacesSkipsMatchedLink(t *testing.T) {
	for _, action := range []string{ipsec.ReconcileActionNoop, ipsec.ReconcileActionAdopt} {
		t.Run(action, func(t *testing.T) {
			spec := ipsec.TransportLinkSpec{TransportID: "ipsec-main-ab", InterfaceName: "phx1", XFRMIfID: 42, NetNS: "photontesth2", LocalTunnelAddr: netip.MustParseAddr("fe80::1")}
			inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, time.Unix(4000, 0))
			driver := &observedXFRMDriver{}
			platformDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})
			reconcileAction := ipsec.ReconcileAction{Action: action, Instance: &inst}
			if action == ipsec.ReconcileActionAdopt {
				reconcileAction.Spec = &spec
			}
			if err := platformDriver.MaintainXFRMInterfaces(context.Background(), []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{inst.ID: inst}, []ipsec.ReconcileAction{reconcileAction}, nil, nil, nil); err != nil {
				t.Fatal(err)
			}
			if len(driver.Interfaces) != 0 || len(driver.Addresses) != 0 {
				t.Fatalf("matched link caused redundant maintenance: interfaces=%v addresses=%v", driver.Interfaces, driver.Addresses)
			}
		})
	}
}

func TestMaintainExistingXFRMInterfacesUsesRuntimeAddressDuringRotate(t *testing.T) {
	group := ipsec.LinkGroupSpec{ID: "main"}
	base := ipsec.TransportLinkSpec{
		LocalZone: "node-a.catofes.",
		PeerZone:  "node-b.catofes.",
		OverlayID: "main",
		Provider:  ipsec.ProviderStrongSwan,
		LinkID:    "link-stable",
		NetNS:     "photontesth2",
	}
	desired, err := ipsec.RuntimeSpecForPortGeneration(base, group, 2)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(desired): %v", err)
	}
	oldRuntime, err := ipsec.RuntimeSpecForPortGeneration(base, group, 1)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(old): %v", err)
	}
	inst := ipsec.NewLinkInstance(oldRuntime, ipsec.LinkStateUp, time.Unix(4000, 0))
	inst.RemoteGeneration = 1
	inst.RotatePhase = ipsec.RotatePhaseDualRunning
	inst.StagedIKEName = desired.TransportID
	inst.StagedInterfaceName = desired.InterfaceName
	inst.StagedXFRMIfID = desired.XFRMIfID
	inst.StagedLocalTunnelAddr = desired.LocalTunnelAddr
	inst.StagedPeerTunnelAddr = desired.PeerTunnelAddr
	inst.LocalTunnelAddr = desired.LocalTunnelAddr
	inst.PeerTunnelAddr = desired.PeerTunnelAddr
	driver := &observedXFRMDriver{
		linkState: &ipsec.XFRMLinkState{
			NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2"}.Normalized(),
			NamespaceExists: true,
			InterfaceExists: true,
			FlagsKnown:      true,
			InterfaceUp:     false,
			Multicast:       true,
		},
	}
	platformDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})

	if err := platformDriver.MaintainXFRMInterfaces(context.Background(), []ipsec.TransportLinkSpec{desired}, map[string]ipsec.LinkInstance{inst.ID: inst}, []ipsec.ReconcileAction{{Action: ipsec.ReconcileActionNoop, Reason: "route_cutover_pending", Instance: &inst}}, []ipsec.LinkGroupSpec{group}, nil, nil); err != nil {
		t.Fatalf("maintainExistingXFRMInterfaces: %v", err)
	}
	if len(driver.Interfaces) != 1 || driver.Interfaces[0].InterfaceName != oldRuntime.InterfaceName {
		t.Fatalf("interfaces = %+v, want old runtime interface maintenance", driver.Interfaces)
	}
	wantAddress := oldRuntime.InterfaceName + "=" + netip.PrefixFrom(oldRuntime.LocalTunnelAddr, 64).String()
	if len(driver.Addresses) != 1 || driver.Addresses[0] != wantAddress {
		t.Fatalf("addresses = %+v, want old runtime address preserved", driver.Addresses)
	}
}

func TestMaintainExistingXFRMInterfacesSkipsLinkWithActiveAction(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "phx1",
		XFRMIfID:        42,
		NetNS:           "photontesth2",
		LocalTunnelAddr: netip.MustParseAddr("fd00::1"),
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateConnecting, time.Unix(4000, 0))
	driver := &observedXFRMDriver{}
	platformDriver := mustNewLinuxDriver(t, LinuxDriverOptions{IPsecDriver: driver, XFRMDriver: driver})

	if err := platformDriver.MaintainXFRMInterfaces(context.Background(), []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{inst.ID: inst}, []ipsec.ReconcileAction{{Action: ipsec.ReconcileActionCreate, Spec: &spec}}, nil, nil, nil); err != nil {
		t.Fatalf("maintainExistingXFRMInterfaces: %v", err)
	}
	if len(driver.Interfaces) != 0 || len(driver.Addresses) != 0 {
		t.Fatalf("maintenance ran despite active action: interfaces=%+v addresses=%+v", driver.Interfaces, driver.Addresses)
	}
}
