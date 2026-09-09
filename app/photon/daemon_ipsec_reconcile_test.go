package main

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type batchObservedIPsecDriver struct {
	observedIPsecDriver
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
	return states, states, nil
}

func (d *batchObservedIPsecDriver) InspectLink(ctx context.Context, spec ipsec.TransportLinkSpec) (ipsec.XFRMLinkState, error) {
	d.inspectCalls++
	return d.observedIPsecDriver.InspectLink(ctx, spec)
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
	platformDriver := newTestLinuxDriver(driver, driver)
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
	platformDriver := newTestLinuxDriver(driver, driver)
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
	platformDriver := newTestLinuxDriver(driver, driver)

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

func TestIPsecReconcileSummaryEqualityIgnoresLiveObservations(t *testing.T) {
	base := &ipsecObservationSummary{
		LastRunUnix:    100,
		SourceRevision: 7,
		DesiredLinks:   1,
		ActualSAs: []linkSAState{
			{Name: "z", UniqueID: 2, IKEState: "ESTABLISHED", IKEAgeSeconds: 10, InboundBytes: 100},
			{Name: "a", UniqueID: 1, IKEState: "ESTABLISHED", ChildAgeSeconds: 20, InboundPackets: 4},
		},
	}
	next := cloneIPsecObservationSummary(base)
	next.LastRunUnix = 200
	next.SourceRevision = 12
	next.ActualSAs[0].IKEAgeSeconds = 110
	next.ActualSAs[0].InboundBytes = 1000
	next.ActualSAs[1].ChildAgeSeconds = 120
	next.ActualSAs[1].InboundPackets = 40
	next.ActualSAs[0], next.ActualSAs[1] = next.ActualSAs[1], next.ActualSAs[0]
	if !ipsecReconcileSummaryEqual(base, next) {
		t.Fatal("live timestamp/counter/order changes should be equivalent")
	}
	next.ActualSAs[0].IKEState = "DOWN"
	if ipsecReconcileSummaryEqual(base, next) {
		t.Fatal("stable SA state change should not be equivalent")
	}
}

func TestRecordIPsecReconcileErrorDeduplicatesRepeatedError(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(3990, 0)
	rt := &AppContext{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	firstRev := service.StateStore.Meta().Revision
	service.recordIPsecReconcileError(firstRev, now.Unix(), errors.New("vici unavailable"))
	committedRev := service.StateStore.Meta().Revision
	if committedRev != firstRev {
		t.Fatalf("first error verified revision = %d, want %d", committedRev, firstRev)
	}

	now = now.Add(time.Minute)
	service.recordIPsecReconcileError(committedRev, now.Unix(), errors.New("vici unavailable"))
	if got := service.StateStore.Meta().Revision; got != committedRev {
		t.Fatalf("repeated identical error revision = %d, want unchanged %d", got, committedRev)
	}

	service.recordIPsecReconcileError(committedRev, now.Unix(), errors.New("vici timeout"))
	if got := service.StateStore.Meta().Revision; got != committedRev {
		t.Fatalf("changed runtime error verified revision = %d, want %d", got, committedRev)
	}
}

func TestDaemonStateChangedReconcilesIPsecLinks(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4000, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)

	service.notifyStateChanged()

	latestLinks, latestReconcile := readTestIPsecObservation(service)
	if len(latestLinks) != 1 {
		t.Fatalf("link instances len = %d, want 1", len(latestLinks))
	}
	if latestReconcile == nil || latestReconcile.DesiredLinks != 1 {
		t.Fatalf("ipsec reconcile = %+v, want one desired link", latestReconcile)
	}
	if len(latestReconcile.Actions) != 1 || latestReconcile.Actions[0].Action != ipsec.ReconcileActionCreate {
		t.Fatalf("actions = %+v, want create", latestReconcile.Actions)
	}
	for _, inst := range latestLinks {
		if inst.Owner.Manager != "photon" || inst.ActualState != ipsec.LinkStateConnecting {
			t.Fatalf("instance = %+v, want photon connecting", inst)
		}
	}

	service.notifyStateChanged()
	reloadedLinks, reloadedReconcile := readTestIPsecObservation(service)
	if len(reloadedLinks) != 1 {
		t.Fatalf("second link instances len = %d, want 1", len(reloadedLinks))
	}
	if len(reloadedReconcile.Actions) != 1 || reloadedReconcile.Actions[0].Action != ipsec.ReconcileActionNoop {
		t.Fatalf("second actions = %+v, want noop", reloadedReconcile.Actions)
	}
}

func TestMaintainExistingXFRMInterfacesSkipsNoopUpLinkWhenMatched(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "phx1",
		XFRMIfID:        42,
		NetNS:           "photontesth2",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, time.Unix(4000, 0))
	driver := &observedIPsecDriver{}
	platformDriver := newTestLinuxDriver(driver, driver)

	if err := platformDriver.MaintainXFRMInterfaces(context.Background(), []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{inst.ID: inst}, []ipsec.ReconcileAction{{Action: ipsec.ReconcileActionNoop, Instance: &inst}}, nil, nil, nil); err != nil {
		t.Fatalf("maintainExistingXFRMInterfaces: %v", err)
	}
	if len(driver.Interfaces) != 0 {
		t.Fatalf("interfaces = %+v, want no redundant maintenance when state matches", driver.Interfaces)
	}
	if len(driver.Addresses) != 0 {
		t.Fatalf("addresses = %+v, want no redundant maintenance when state matches", driver.Addresses)
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
	driver := &observedIPsecDriver{
		linkState: &ipsec.XFRMLinkState{
			NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2"}.Normalized(),
			NamespaceExists: true,
			InterfaceExists: true,
			FlagsKnown:      true,
			InterfaceUp:     false,
			Multicast:       true,
		},
	}
	platformDriver := newTestLinuxDriver(driver, driver)

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

func TestMaintainExistingXFRMInterfacesSkipsAdoptedLinkWhenMatched(t *testing.T) {
	spec := ipsec.TransportLinkSpec{
		TransportID:     "ipsec-main-ab",
		InterfaceName:   "phx1",
		XFRMIfID:        42,
		NetNS:           "photontesth2",
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"),
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, time.Unix(4000, 0))
	driver := &observedIPsecDriver{}
	platformDriver := newTestLinuxDriver(driver, driver)

	if err := platformDriver.MaintainXFRMInterfaces(context.Background(), []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{inst.ID: inst}, []ipsec.ReconcileAction{{Action: ipsec.ReconcileActionAdopt, Spec: &spec, Instance: &inst}}, nil, nil, nil); err != nil {
		t.Fatalf("maintainExistingXFRMInterfaces: %v", err)
	}
	if len(driver.Interfaces) != 0 {
		t.Fatalf("interfaces = %+v, want no redundant maintenance when state matches", driver.Interfaces)
	}
	if len(driver.Addresses) != 0 {
		t.Fatalf("addresses = %+v, want no redundant maintenance when state matches", driver.Addresses)
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
	driver := &observedIPsecDriver{}
	platformDriver := newTestLinuxDriver(driver, driver)

	if err := platformDriver.MaintainXFRMInterfaces(context.Background(), []ipsec.TransportLinkSpec{spec}, map[string]ipsec.LinkInstance{inst.ID: inst}, []ipsec.ReconcileAction{{Action: ipsec.ReconcileActionCreate, Spec: &spec}}, nil, nil, nil); err != nil {
		t.Fatalf("maintainExistingXFRMInterfaces: %v", err)
	}
	if len(driver.Interfaces) != 0 || len(driver.Addresses) != 0 {
		t.Fatalf("maintenance ran despite active action: interfaces=%+v addresses=%+v", driver.Interfaces, driver.Addresses)
	}
}

func TestDaemonIPsecReconcileDiscardsResultWhenRevisionChanged(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4050, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	baseRev := service.StateStore.Meta().Revision
	driver := &staleCommitIPsecDriver{}
	driver.onLoadConnection = func(ipsec.TransportLinkSpec) {
		if _, err := advanceTestVerifiedRevision(service.StateStore, now.Add(time.Nanosecond)); err != nil {
			t.Fatalf("advance state revision during apply: %v", err)
		}
	}
	installTestIPsecDrivers(service, driver, driver)

	if err := service.reconcileIPsecLinks(context.Background()); err != nil {
		t.Fatalf("reconcileIPsecLinks: %v", err)
	}
	if !service.ipsecDirty {
		t.Fatal("ipsecDirty = false, want stale reconcile to be retried")
	}
	common, runtime := service.StateStore.readCommonAndRuntime()
	observationLinks, observationReconcile := readTestIPsecObservation(service)
	rev := uint64(common.Revision)
	if rev != baseRev+1 {
		t.Fatalf("state revision = %d, want only external update at %d", rev, baseRev+1)
	}
	if len(observationLinks) != 0 {
		t.Fatalf("link instances = %+v, want stale result discarded", observationLinks)
	}
	if observationReconcile != nil {
		t.Fatalf("ipsec reconcile summary = %+v, want stale summary discarded", observationReconcile)
	}
}

func TestLongIPsecReconcileDoesNotBlockCommittedReaders(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4060, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	started := make(chan struct{})
	unblock := make(chan struct{})
	driver := &staleCommitIPsecDriver{}
	driver.onLoadConnection = func(ipsec.TransportLinkSpec) {
		close(started)
		<-unblock
	}
	installTestIPsecDrivers(service, driver, driver)

	done := make(chan error, 1)
	go func() {
		done <- service.reconcileIPsecLinks(context.Background())
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("ipsec reconcile did not enter blocking LoadConnection")
	}

	committedRev := service.StateStore.Meta().Revision
	statusDone := make(chan controlViewResponse[inspect.DaemonStatusView], 1)
	go func() {
		statusDone <- controlViewRequestViaPipe[inspect.DaemonStatusView](t, service, controlRequest{Method: "daemon_status_view"})
	}()
	select {
	case status := <-statusDone:
		if !status.OK || status.View.StateRevision != committedRev {
			close(unblock)
			t.Fatalf("status response = %#v, want committed revision %d", status, committedRev)
		}
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("control status blocked behind IPsec reconcile apply")
	}

	linksDone := make(chan controlViewResponse[inspect.LinksDebugView], 1)
	go func() {
		linksDone <- controlViewRequestViaPipe[inspect.LinksDebugView](t, service, controlRequest{Method: "links_view"})
	}()
	select {
	case links := <-linksDone:
		if !links.OK {
			close(unblock)
			t.Fatalf("links_view response = %#v", links)
		}
	case <-time.After(time.Second):
		close(unblock)
		t.Fatal("links_view blocked behind IPsec reconcile apply")
	}

	close(unblock)
	if err := <-done; err != nil {
		t.Fatalf("reconcileIPsecLinks: %v", err)
	}
}

func TestDaemonStateChangedReconcilesIPsecPortRotation(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4000, 0)
	verified.Network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", nil)
	addTestIPsecRecords(t, verified.Network.Zones["node-a.catofes."], "node-a.catofes.", now, ipsec.RoleOut)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	service.notifyStateChanged()

	common, persistedRuntime := service.StateStore.readCommonAndRuntime()
	latestLinks, latestReconcile := readTestIPsecObservation(service)
	var inst linkInstanceState
	for _, v := range latestLinks {
		inst = v
	}
	if inst.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("initial state = %q, want connecting", inst.ActualState)
	}

	// Simulate peer publishing generation 2 port record.
	zs := common.State.Network.Zones["node-b.catofes."]
	zs.Records[ipsec.RecordKeyPorts] = unsignedIPsecRecord(t, "node-b.catofes.", ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 2,
			IKE:        ipsec.PortBinding{Advertised: ipsec.DefaultIKEPort},
			NATT:       ipsec.PortBinding{Advertised: 4501},
		},
		UpdatedAt: now.Unix(),
	})
	service = newTestDaemonFromOwners(rt, common.State, common.Gossip, persistedRuntime, config, time.Second)
	service.linuxObservation.replaceIPsec(latestLinks, latestReconcile)
	service.notifyStateChanged()

	rotatedLinks, rotatedReconcile := readTestIPsecObservation(service)
	for _, v := range rotatedLinks {
		inst = v
	}
	if inst.RotatePhase != ipsec.RotatePhaseTestingNew {
		t.Fatalf("rotate phase = %q, want testing_new", inst.RotatePhase)
	}
	if inst.StagedGeneration != 2 {
		t.Fatalf("staged generation = %d, want 2", inst.StagedGeneration)
	}
	if inst.StagedIKEName != ipsec.RuntimeConnectionID(inst.LinkID, 2, inst.TransportKind) {
		t.Fatalf("staged ike name = %q", inst.StagedIKEName)
	}
	foundPrepare := false
	for _, action := range rotatedReconcile.Actions {
		if action.Action == ipsec.ReconcileActionPrepareRotate {
			foundPrepare = true
		}
	}
	if !foundPrepare {
		t.Fatalf("expected prepare_rotate action, got %+v", rotatedReconcile.Actions)
	}
}

func TestDaemonProcessEventsCoalescesIPsecReconcile(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4150, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	driver := &countingIPsecDriver{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	service.Events <- daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  "node-b.catofes.",
			Key:   "coalesce-a",
			Value: []byte("a"),
			Type:  "policy.string",
		},
	}
	service.Events <- daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone:  "node-b.catofes.",
			Key:   "coalesce-b",
			Value: []byte("b"),
			Type:  "policy.string",
		},
	}

	syncNow, shutdown, ipsecFlushed, _, _ := service.processEvents(context.Background())
	if !syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want true/false", syncNow, shutdown)
	}
	if !ipsecFlushed {
		t.Fatalf("ipsecFlushed = false, want true")
	}
	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	if len(driver.Connections) != 1 {
		t.Fatalf("connections = %d, want one coalesced apply", len(driver.Connections))
	}
	common, _ := service.StateStore.readCommonAndRuntime()
	_, latestReconcile := readTestIPsecObservation(service)
	if common.State.Network.Zones["node-b.catofes."].Records["coalesce-a"] == nil || common.State.Network.Zones["node-b.catofes."].Records["coalesce-b"] == nil {
		t.Fatalf("queued record puts were not both persisted")
	}
	if latestReconcile == nil || len(latestReconcile.Actions) != 1 || latestReconcile.Actions[0].Action != ipsec.ReconcileActionCreate {
		t.Fatalf("ipsec reconcile = %+v, want one create", latestReconcile)
	}
}

func TestDaemonVICILifecycleEventsOnlyTriggerCoalescedIPsecReconcile(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4160, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	driver := &countingIPsecDriver{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	service.Events <- daemonEvent{Type: daemonEventIPsecLifecycle, VICIEvent: ipsec.VICIEvent{Name: "child-updown", Connection: "ipsec-main-ab", ChildSA: "ipsec-main-ab-child", Up: true, XFRMIfID: 77}}
	service.Events <- daemonEvent{Type: daemonEventIPsecLifecycle, VICIEvent: ipsec.VICIEvent{Name: "child-updown", Connection: "ipsec-main-ab", ChildSA: "ipsec-main-ab-child", Up: false, XFRMIfID: 77}}

	syncNow, shutdown, ipsecFlushed, _, _ := service.processEvents(context.Background())
	if syncNow || shutdown {
		t.Fatalf("syncNow/shutdown = %v/%v, want false/false", syncNow, shutdown)
	}
	if !ipsecFlushed {
		t.Fatalf("ipsecFlushed = false, want true")
	}
	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want one coalesced reconcile", driver.listCalls)
	}
	if len(driver.Connections) != 1 {
		t.Fatalf("connections = %d, want one apply through reconcile", len(driver.Connections))
	}
	if len(driver.Interfaces) != 1 {
		t.Fatalf("interfaces = %d, want one apply through xfrm reconcile", len(driver.Interfaces))
	}
}

func TestDaemonIPsecReconcileInterval(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	appConfig := defaultAppConfig()
	service := newTestDaemonFromOwners(&AppContext{Config: appConfig}, verified, checkpoint, runtime, config, time.Second)
	if interval := service.ipsecReconcileInterval(); interval != 0 {
		t.Fatalf("interval without link groups = %s, want 0", interval)
	}

	service.linuxObservation.replaceIPsec(map[string]ipsec.LinkInstance{"stale": {ID: "stale"}}, nil)
	if interval := service.ipsecReconcileInterval(); interval != defaultIPsecReconcileInterval {
		t.Fatalf("interval with observed instances = %s, want %s", interval, defaultIPsecReconcileInterval)
	}
	service.linuxObservation.replaceIPsec(nil, nil)

	defaultGroup := testIPsecLinkGroup()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{defaultGroup}
	if interval := service.ipsecReconcileInterval(); interval != defaultIPsecReconcileInterval {
		t.Fatalf("default interval = %s, want %s", interval, defaultIPsecReconcileInterval)
	}

	fastGroup := testIPsecLinkGroup()
	fastGroup.ID = "fast"
	fastGroup.Reconcile.IntervalSeconds = 5
	slowGroup := testIPsecLinkGroup()
	slowGroup.ID = "slow"
	slowGroup.Reconcile.IntervalSeconds = 60
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{slowGroup, fastGroup}
	if interval := service.ipsecReconcileInterval(); interval != 5*time.Second {
		t.Fatalf("minimum interval = %s, want 5s", interval)
	}
}

func TestNextIPsecReconcileTime(t *testing.T) {
	now := time.Unix(4200, 0)
	if next := nextIPsecReconcileTime(now, 0); !next.IsZero() {
		t.Fatalf("next disabled = %s, want zero", next)
	}
	if next := nextIPsecReconcileTime(now, 30*time.Second); !next.Equal(now.Add(30 * time.Second)) {
		t.Fatalf("next = %s, want %s", next, now.Add(30*time.Second))
	}
}

func TestMarkIPsecActionSucceededKeepsSecondaryStandbyDownAfterUpdate(t *testing.T) {
	now := time.Unix(5102, 0)
	spec := ipsec.TransportLinkSpec{
		LocalZone:     "node-b.catofes.",
		PeerZone:      "node-a.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-standby",
		InterfaceName: "phx-standby",
		XFRMIfID:      5102,
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateDegraded, now)
	inst.InitiatorRole = ipsec.InitiatorRoleSecondaryStandby
	instances := map[string]ipsec.LinkInstance{inst.ID: inst}

	markIPsecActionSucceeded(instances, ipsec.ReconcileAction{
		Action:   ipsec.ReconcileActionUpdate,
		Spec:     &spec,
		Instance: &inst,
	}, now.Add(time.Second))

	got := instances[inst.ID]
	if got.ActualState != ipsec.LinkStateDown {
		t.Fatalf("state = %q, want down for standby update", got.ActualState)
	}
}
