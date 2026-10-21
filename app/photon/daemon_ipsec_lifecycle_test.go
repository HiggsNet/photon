package main

import (
	"bytes"
	"context"
	"errors"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestDaemonStateChangedRemovesTeardownIPsecLinks(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4050, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)

	service.notifyStateChanged()
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(latest.LinkInstances) != 1 {
		t.Fatalf("link instances len = %d, want 1", len(latest.LinkInstances))
	}

	appConfig.IPsec.LinkGroups = nil
	service.setState(latest)
	service.notifyStateChanged()
	removed, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(after teardown): %v", err)
	}
	if len(removed.LinkInstances) != 0 {
		t.Fatalf("link instances after teardown = %+v, want none", removed.LinkInstances)
	}
	if len(removed.IPsecReconcile.Actions) != 1 || removed.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionTeardown {
		t.Fatalf("teardown actions = %+v, want one teardown", removed.IPsecReconcile.Actions)
	}

	service.setState(removed)
	service.notifyStateChanged()
	stable, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(stable): %v", err)
	}
	if len(stable.LinkInstances) != 0 {
		t.Fatalf("stable link instances = %+v, want none", stable.LinkInstances)
	}
	if len(stable.IPsecReconcile.Actions) != 0 {
		t.Fatalf("stable actions = %+v, want no repeated teardown", stable.IPsecReconcile.Actions)
	}
}

func TestDaemonStateChangedAdoptsObservedIPsecSA(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4100, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	driver := &observedIPsecDriver{
		sas: []ipsec.SAState{{
			Name:        spec.TransportID,
			ChildSA:     ipsec.ChildSAName(spec),
			XFRMIfID:    spec.XFRMIfID,
			Endpoint:    "198.51.100.20",
			Established: true,
		}},
	}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.notifyStateChanged()

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionAdopt {
		t.Fatalf("actions = %+v, want adopt", latest.IPsecReconcile.Actions)
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp || inst.Endpoint != "198.51.100.20" {
		t.Fatalf("instance = %+v, want up adopted endpoint", inst)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Desired) != 1 || len(latest.IPsecReconcile.ActualSAs) != 1 {
		t.Fatalf("ipsec reconcile detail = %+v, want desired and actual sa snapshots", latest.IPsecReconcile)
	}
	var out bytes.Buffer
	if err := writeDebugLinks(&out, rt, latest, ""); err != nil {
		t.Fatalf("writeDebugLinks: %v", err)
	}
	output := out.String()
	for _, want := range []string{
		"planned_desired_links: 1",
		"actual_sas: 1",
		"  planner:\n",
		"    desired_hash: ",
		"  xfrm:\n",
		"    interface: ",
		"  strongswan:\n",
		"    sa_state: established",
		"    remote_endpoint: 198.51.100.20",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("debug links output missing %q:\n%s", want, output)
		}
	}
	if len(driver.Connections) != 0 {
		t.Fatalf("adopt should not load connections, got %+v", driver.Connections)
	}
	if len(driver.Interfaces) != 1 || driver.Interfaces[0].InterfaceName != spec.InterfaceName {
		t.Fatalf("adopt should EnsureInterface, interfaces=%+v", driver.Interfaces)
	}
}

func TestDaemonStartupRecoversIPsecLinkState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4125, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	persisted := ipsec.NewLinkInstance(spec, ipsec.LinkStateConnecting, now.Add(-time.Minute))
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{
		persisted.ID: persisted,
	})
	driver := &observedIPsecDriver{
		sas: []ipsec.SAState{{
			Name:        spec.TransportID,
			ChildSA:     ipsec.ChildSAName(spec),
			XFRMIfID:    spec.XFRMIfID,
			Endpoint:    "198.51.100.20",
			Established: true,
		}},
	}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.recoverIPsecLinksOnStart(context.Background())

	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp || inst.Endpoint != "198.51.100.20" {
		t.Fatalf("startup recovered instance = %+v, want up adopted endpoint", inst)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionAdopt {
		t.Fatalf("startup reconcile = %+v, want adopt", latest.IPsecReconcile)
	}
	if len(driver.Connections) != 0 {
		t.Fatalf("startup adopt should not load connections, got %+v", driver.Connections)
	}
	if len(driver.Interfaces) != 1 || driver.Interfaces[0].InterfaceName != spec.InterfaceName {
		t.Fatalf("startup adopt should EnsureInterface, interfaces=%+v", driver.Interfaces)
	}
}

func TestDaemonStartupRepairsEstablishedSAWhenXFRMLinkMissing(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4126, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	persisted := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now.Add(-time.Minute))
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{
		persisted.ID: persisted,
	})
	driver := &observedIPsecDriver{
		sas: []ipsec.SAState{{
			Name:        spec.TransportID,
			ChildSA:     ipsec.ChildSAName(spec),
			XFRMIfID:    spec.XFRMIfID,
			Endpoint:    "198.51.100.20",
			Established: true,
		}},
		linkState: &ipsec.XFRMLinkState{
			NetNS:           group.NetNS,
			NamespaceExists: false,
			InterfaceExists: false,
		},
	}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.recoverIPsecLinksOnStart(context.Background())

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionRepair {
		t.Fatalf("startup reconcile = %+v, want repair", latest.IPsecReconcile)
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("instance = %+v, want connecting after repair apply", inst)
	}
	assertDryRunApply(t, driver, spec, group.NetNS)
	if len(latest.IPsecReconcile.ActualSAs) != 0 {
		t.Fatalf("actual SAs = %+v, want missing xfrm link to suppress matching SA", latest.IPsecReconcile.ActualSAs)
	}
}

func TestDaemonStartupKeepsRotatedRuntimeSAWhenActiveXFRMLinkExists(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4128, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	baseSpec := plan.Desired[0]
	updateDaemonTestPortRecord(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", 2, ipsec.DefaultNATTPort, now.Add(time.Minute))
	rotatedPlan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now.Add(time.Minute)})
	if err != nil {
		t.Fatalf("PlanTransportLinks(rotated): %v", err)
	}
	if len(rotatedPlan.Desired) != 1 {
		t.Fatalf("rotated desired links = %d, want 1", len(rotatedPlan.Desired))
	}
	rotatedDesired := rotatedPlan.Desired[0]
	rotatedIKE := ipsec.RuntimeConnectionID(ipsec.LinkInstanceID(rotatedDesired), 2, rotatedDesired.Provider)
	rotatedIfID := ipsec.RuntimeXFRMIfID(ipsec.LinkInstanceID(rotatedDesired), 2, rotatedDesired.Provider)
	rotatedInterface := ipsec.StableInterfaceName(rotatedIfID)
	persisted := ipsec.NewLinkInstance(rotatedDesired, ipsec.LinkStateUp, now)
	persisted.RemoteGeneration = 2
	persisted.IKEName = rotatedIKE
	persisted.ChildSAName = rotatedIKE + "-child"
	persisted.InterfaceName = rotatedInterface
	persisted.XFRMIfID = rotatedIfID
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{
		persisted.ID: persisted,
	})
	driver := &observedIPsecDriver{
		sas: []ipsec.SAState{{
			Name:        rotatedIKE,
			ChildSA:     rotatedIKE + "-child",
			XFRMIfID:    rotatedIfID,
			Endpoint:    "203.0.113.10",
			Established: true,
		}},
		linkStates: map[string]ipsec.XFRMLinkState{
			baseSpec.InterfaceName: {
				NetNS:           group.NetNS,
				NamespaceExists: true,
				InterfaceExists: false,
			},
			rotatedInterface: {
				NetNS:           group.NetNS,
				NamespaceExists: true,
				InterfaceExists: true,
				Addresses:       []netip.Prefix{netip.PrefixFrom(rotatedDesired.LocalTunnelAddr, 128)},
			},
		},
	}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now.Add(time.Minute) },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.recoverIPsecLinksOnStart(context.Background())

	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.ActualSAs) != 1 {
		t.Fatalf("startup reconcile actual SAs = %+v, want rotated SA retained", latest.IPsecReconcile)
	}
	for _, action := range latest.IPsecReconcile.Actions {
		if action.Action == ipsec.ReconcileActionRepair {
			t.Fatalf("startup reconcile action = %+v, want no repair for existing rotated xfrm link", action)
		}
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(rotatedDesired)]
	if inst.InterfaceName != rotatedInterface || inst.XFRMIfID != rotatedIfID || inst.RemoteGeneration != 2 {
		t.Fatalf("instance = %+v, want rotated runtime interface %s/%d generation 2", inst, rotatedInterface, rotatedIfID)
	}
	if len(driver.Interfaces) != 0 {
		t.Fatalf("interfaces applied = %+v, want no redundant xfrm maintenance when rotated state matches", driver.Interfaces)
	}
}

func TestDaemonStartupRepairsMissingObservedSA(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4135, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	persisted := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now.Add(-time.Minute))
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{
		persisted.ID: persisted,
	})
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &observedIPsecDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.recoverIPsecLinksOnStart(context.Background())

	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	assertDryRunApply(t, driver, spec, group.NetNS)
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("startup repaired instance = %+v, want connecting", inst)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionRepair {
		t.Fatalf("startup reconcile = %+v, want repair", latest.IPsecReconcile)
	}
}

func TestDaemonStartupRetriesConnectingWithoutObservedSA(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4137, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	group.Reconcile.Backoff = ipsec.BackoffPolicy{InitialSeconds: 1, MaxSeconds: 1}
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	persisted := ipsec.NewLinkInstance(spec, ipsec.LinkStateConnecting, now.Add(-time.Minute))
	persisted = ipsec.MarkLinkApplyFailure(persisted, group.Reconcile.Backoff, now.Add(-2*time.Second), errors.New("waiting for established SA"))
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{
		persisted.ID: persisted,
	})
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &observedIPsecDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.recoverIPsecLinksOnStart(context.Background())

	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	assertDryRunApply(t, driver, spec, group.NetNS)
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	inst := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateConnecting || inst.FailureCount != 0 || inst.BackoffUntil != 0 {
		t.Fatalf("startup retried instance = %+v, want connecting with cleared backoff", inst)
	}
	if latest.IPsecReconcile == nil || len(latest.IPsecReconcile.Actions) != 1 || latest.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionRepair {
		t.Fatalf("startup reconcile = %+v, want repair", latest.IPsecReconcile)
	}
}

func TestDaemonRevocationTearsDownIPsecLinkAndBlocksRecreate(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(4140, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &observedIPsecDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	service.notifyStateChanged()
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(create): %v", err)
	}
	spec := singleDesiredSpec(t, latest)
	if len(latest.LinkInstances) != 1 {
		t.Fatalf("link instances after create = %+v, want one", latest.LinkInstances)
	}

	parent := latest.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "ipsec smoke revoke",
		RevokedAt:             now.Add(-time.Second).Unix(),
	}
	if err := rt.SaveState(latest); err != nil {
		t.Fatalf("SaveState(revoked): %v", err)
	}
	service.setState(latest)
	service.notifyStateChanged()

	revoked, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(revoked): %v", err)
	}
	if len(revoked.LinkInstances) != 0 {
		t.Fatalf("link instances after revoke = %+v, want none", revoked.LinkInstances)
	}
	if revoked.IPsecReconcile == nil || len(revoked.IPsecReconcile.Actions) != 1 || revoked.IPsecReconcile.Actions[0].Action != ipsec.ReconcileActionTeardown {
		t.Fatalf("revoke reconcile = %+v, want teardown", revoked.IPsecReconcile)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID || len(driver.Unloaded) != 1 || driver.Unloaded[0] != spec.TransportID || len(driver.DeletedIFs) != 1 || driver.DeletedIFs[0] != spec.InterfaceName {
		t.Fatalf("teardown driver state terminated=%+v unloaded=%+v deleted=%+v", driver.Terminated, driver.Unloaded, driver.DeletedIFs)
	}
	if !hasDebugSkip(revoked.IPsecReconcile.Skipped, "node-b.catofes.", ipsec.SkipRevokedZone) {
		t.Fatalf("skips = %+v, want revoked zone", revoked.IPsecReconcile.Skipped)
	}

	service.setState(revoked)
	service.notifyStateChanged()
	stable, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState(stable): %v", err)
	}
	if len(stable.LinkInstances) != 0 || len(stable.IPsecReconcile.Actions) != 0 || stable.IPsecReconcile.DesiredLinks != 0 {
		t.Fatalf("stable revoked reconcile = %+v instances=%+v, want no recreate", stable.IPsecReconcile, stable.LinkInstances)
	}
}

func TestCleanupIPsecLinkInstancesTearsDownManagedLinks(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(5100, 0)
	spec := ipsec.TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-cleanup",
		InterfaceName: "phx-clean0",
		XFRMIfID:      5100,
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{inst.ID: inst})
	driver := &ipsec.DryRunDriver{}

	cleaned, err := cleanupIPsecLinkInstances(context.Background(), state, driver, driver, now)
	if err != nil {
		t.Fatalf("cleanupIPsecLinkInstances: %v", err)
	}
	if cleaned != 1 {
		t.Fatalf("cleaned = %d, want 1", cleaned)
	}
	if len(state.LinkInstances) != 0 {
		t.Fatalf("link instances = %+v, want empty", state.LinkInstances)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID {
		t.Fatalf("terminated = %+v, want %s", driver.Terminated, spec.TransportID)
	}
	if len(driver.Unloaded) != 1 || driver.Unloaded[0] != spec.TransportID {
		t.Fatalf("unloaded = %+v, want %s", driver.Unloaded, spec.TransportID)
	}
	if len(driver.DeletedIFs) != 1 || driver.DeletedIFs[0] != spec.InterfaceName {
		t.Fatalf("deleted interfaces = %+v, want %s", driver.DeletedIFs, spec.InterfaceName)
	}
	if state.IPsecReconcile == nil || state.IPsecReconcile.LastRunUnix != now.Unix() || state.IPsecReconcile.LastError != "" {
		t.Fatalf("ipsec reconcile = %+v, want cleanup timestamp and no error", state.IPsecReconcile)
	}
}

func TestRecoveryPurgeRevokedApplyCleansIPsecLinksBeforeDeletingState(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(5101, 0)
	addRevocationTombstoneForTest(t, state, "node-b.catofes.", "catofes.")
	spec := ipsec.TransportLinkSpec{
		LocalZone:     state.ManagedZone,
		PeerZone:      "node-b.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-purge-revoked",
		InterfaceName: "phx-purge0",
		XFRMIfID:      5101,
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{inst.ID: inst})
	state.SyncPeers = map[string]syncPeerState{"node-b.catofes.": {}}
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &ipsec.DryRunDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	plan, err := service.handleRecoveryPurgeRevokedEvent(context.Background(), "", true)
	if err != nil {
		t.Fatalf("handleRecoveryPurgeRevokedEvent: %v", err)
	}
	if len(plan.LinkInstances) != 1 || plan.LinkInstances[0] != inst.ID {
		t.Fatalf("plan link instances = %+v, want %s", plan.LinkInstances, inst.ID)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID {
		t.Fatalf("terminated = %+v, want %s", driver.Terminated, spec.TransportID)
	}
	if len(driver.Unloaded) != 1 || driver.Unloaded[0] != spec.TransportID {
		t.Fatalf("unloaded = %+v, want %s", driver.Unloaded, spec.TransportID)
	}
	if len(driver.DeletedIFs) != 1 || driver.DeletedIFs[0] != spec.InterfaceName {
		t.Fatalf("deleted interfaces = %+v, want %s", driver.DeletedIFs, spec.InterfaceName)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.Network.Zones["node-b.catofes."] != nil {
		t.Fatalf("revoked zone still present after purge")
	}
	if _, ok := latest.LinkInstances[inst.ID]; ok {
		t.Fatalf("revoked link instance still present after purge")
	}
	if _, ok := latest.SyncPeers["node-b.catofes."]; ok {
		t.Fatalf("revoked sync peer still present after purge")
	}
	if latest.IPsecReconcile == nil || latest.IPsecReconcile.LastRunUnix != now.Unix() {
		t.Fatalf("ipsec cleanup snapshot = %+v, want timestamp", latest.IPsecReconcile)
	}
}

func TestRecoveryCleanupIPsecDirectNoLinksDoesNotRequireVICI(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	state.LinkInstances = nil
	now := time.Unix(5105, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	cleaned, orphans, err := recoveryCleanupIPsecDirect(context.Background(), rt, false)
	if err != nil {
		t.Fatalf("recoveryCleanupIPsecDirect: %v", err)
	}
	if cleaned != 0 {
		t.Fatalf("cleaned = %d, want 0", cleaned)
	}
	if orphans != 0 {
		t.Fatalf("orphans = %d, want 0", orphans)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if latest.IPsecReconcile == nil || latest.IPsecReconcile.LastRunUnix != now.Unix() {
		t.Fatalf("ipsec reconcile = %+v, want cleanup timestamp", latest.IPsecReconcile)
	}
}

func TestCleanupIPsecOrphanConnectionsOnlyRemovesUnreferencedPhotonConnections(t *testing.T) {
	state, _ := buildTestNetworkState(t)
	now := time.Unix(5111, 0)
	spec := ipsec.TransportLinkSpec{
		LocalZone:     "node-a.catofes.",
		PeerZone:      "node-b.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-managed",
		InterfaceName: "phx-managed",
		XFRMIfID:      5111,
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{inst.ID: inst})
	driver := &ipsec.DryRunDriver{
		LoadedConnections: []ipsec.ConnectionState{
			{Name: "ipsec-managed"},
			{Name: "ipsec-orphan-r3"},
			{Name: "manual-vpn"},
		},
	}

	cleaned, err := cleanupIPsecOrphanConnections(context.Background(), state, driver)
	if err != nil {
		t.Fatalf("cleanupIPsecOrphanConnections: %v", err)
	}
	if cleaned != 1 {
		t.Fatalf("cleaned = %d, want 1", cleaned)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != "ipsec-orphan-r3" {
		t.Fatalf("terminated = %+v, want orphan only", driver.Terminated)
	}
	if len(driver.Unloaded) != 1 || driver.Unloaded[0] != "ipsec-orphan-r3" {
		t.Fatalf("unloaded = %+v, want orphan only", driver.Unloaded)
	}
}

func TestDaemonIPsecCleanupEventTearsDownManagedLinks(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(5110, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{inst.ID: inst})
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &observedIPsecDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventIPsecCleanup, Reply: reply}
	syncNow, shutdown, ipsecFlushed, _, _ := service.processEvents(context.Background())
	result := <-reply
	if result.Error != nil {
		t.Fatalf("processEvents(ipsec_cleanup): %v", result.Error)
	}
	if result.CleanedLinks != 1 || syncNow || shutdown {
		t.Fatalf("result=%+v syncNow=%v shutdown=%v, want one cleaned and no sync/shutdown", result, syncNow, shutdown)
	}
	if !ipsecFlushed {
		t.Fatal("ipsec cleanup did not flush reconcile")
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(latest.LinkInstances) != 1 {
		t.Fatalf("persisted link instances = %+v, want recreated link", latest.LinkInstances)
	}
	recreated := latest.LinkInstances[ipsec.LinkInstanceID(spec)]
	if recreated.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("recreated instance = %+v, want connecting", recreated)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID || len(driver.Unloaded) != 1 || driver.Unloaded[0] != spec.TransportID || len(driver.DeletedIFs) != 1 || driver.DeletedIFs[0] != spec.InterfaceName {
		t.Fatalf("driver cleanup: terminated=%+v unloaded=%+v deleted=%+v", driver.Terminated, driver.Unloaded, driver.DeletedIFs)
	}
	if len(driver.Connections) != 1 || driver.Connections[0].TransportID != spec.TransportID || len(driver.Interfaces) != 1 || driver.Interfaces[0].InterfaceName != spec.InterfaceName {
		t.Fatalf("driver recreate: connections=%+v interfaces=%+v", driver.Connections, driver.Interfaces)
	}
}

func TestDaemonIPsecCleanupUsesStateStoreWhileConstructorInputLocked(t *testing.T) {
	state, config := buildTestNetworkState(t)
	now := time.Unix(5111, 0)
	addTestIPsecRecords(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, state.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), state.Network, state.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
	state.LinkInstances = linkInstancesFromIPsec(map[string]ipsec.LinkInstance{inst.ID: inst})
	rt := &Runtime{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &observedIPsecDriver{}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	state.Lock()
	unlock := state.Unlock
	cleaned, orphans, err := service.handleIPsecCleanupEvent(context.Background(), false)
	if err != nil {
		unlock()
		t.Fatalf("handleIPsecCleanupEvent: %v", err)
	}
	current := service.currentState()
	if current == state {
		unlock()
		t.Fatal("committed snapshot still aliases constructor input")
	}
	unlock()
	if cleaned != 1 || orphans != 0 {
		t.Fatalf("cleanup result = %d/%d, want 1/0", cleaned, orphans)
	}
	latest, err := rt.LoadState()
	if err != nil {
		t.Fatalf("LoadState: %v", err)
	}
	if len(latest.LinkInstances) != 1 {
		t.Fatalf("persisted link instances = %+v, want reconciled link", latest.LinkInstances)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID || len(driver.Unloaded) != 1 || driver.Unloaded[0] != spec.TransportID {
		t.Fatalf("driver cleanup: terminated=%+v unloaded=%+v", driver.Terminated, driver.Unloaded)
	}
	if len(driver.Connections) != 1 || driver.Connections[0].TransportID != spec.TransportID {
		t.Fatalf("driver recreate connections=%+v, want reconciled link", driver.Connections)
	}
}

func TestDaemonIPsecCleanupEventCanCleanOrphanConnections(t *testing.T) {
	state, config := buildTestNetworkState(t)
	state.LinkInstances = nil
	now := time.Unix(5112, 0)
	rt := &Runtime{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	if err := rt.SaveState(state); err != nil {
		t.Fatalf("SaveState: %v", err)
	}
	driver := &ipsec.DryRunDriver{
		LoadedConnections: []ipsec.ConnectionState{{Name: "ipsec-orphan-r3"}},
	}
	service := newDaemonService(rt, state, config, time.Second)
	service.IPsecDriver = driver
	service.XFRMDriver = driver

	reply := make(chan daemonEventResult, 1)
	service.Events <- daemonEvent{Type: daemonEventIPsecCleanup, Orphans: true, Reply: reply}
	_, _, ipsecFlushed, _, _ := service.processEvents(context.Background())
	result := <-reply
	if result.Error != nil {
		t.Fatalf("processEvents(ipsec_cleanup --orphans): %v", result.Error)
	}
	if result.CleanedLinks != 0 || result.CleanedOrphans != 1 {
		t.Fatalf("result = %+v, want one orphan only", result)
	}
	if !ipsecFlushed {
		t.Fatal("ipsec cleanup did not flush reconcile")
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != "ipsec-orphan-r3" || len(driver.Unloaded) != 1 || driver.Unloaded[0] != "ipsec-orphan-r3" {
		t.Fatalf("driver cleanup: terminated=%+v unloaded=%+v", driver.Terminated, driver.Unloaded)
	}
}
