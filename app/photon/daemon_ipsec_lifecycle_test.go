package main

import (
	"bytes"
	"context"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDaemonStateChangedRemovesTeardownIPsecLinks(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4050, 0)
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
	latestLinks, _ := readTestIPsecObservation(service)
	if len(latestLinks) != 1 {
		t.Fatalf("link instances len = %d, want 1", len(latestLinks))
	}

	appConfig.IPsec.LinkGroups = nil
	service.notifyStateChanged()
	removedLinks, removedReconcile := readTestIPsecObservation(service)
	if len(removedLinks) != 0 {
		t.Fatalf("link instances after teardown = %+v, want none", removedLinks)
	}
	if len(removedReconcile.Actions) != 1 || removedReconcile.Actions[0].Action != ipsec.ReconcileActionTeardown {
		t.Fatalf("teardown actions = %+v, want one teardown", removedReconcile.Actions)
	}

	service.notifyStateChanged()
	stableLinks, stableReconcile := readTestIPsecObservation(service)
	if len(stableLinks) != 0 {
		t.Fatalf("stable link instances = %+v, want none", stableLinks)
	}
	if len(stableReconcile.Actions) != 0 {
		t.Fatalf("stable actions = %+v, want no repeated teardown", stableReconcile.Actions)
	}
}

func TestDaemonStateChangedAdoptsObservedIPsecSA(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4100, 0)
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
	plan, err := ipsec.PlanTransportLinks(context.Background(), verified.Network, verified.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
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
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	service.notifyStateChanged()

	latestLinks, latestReconcile := readTestIPsecObservation(service)
	if len(latestReconcile.Actions) != 1 || latestReconcile.Actions[0].Action != ipsec.ReconcileActionAdopt {
		t.Fatalf("actions = %+v, want adopt", latestReconcile.Actions)
	}
	inst := latestLinks[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp || inst.Endpoint != "198.51.100.20" {
		t.Fatalf("instance = %+v, want up adopted endpoint", inst)
	}
	if latestReconcile == nil || len(latestReconcile.Desired) != 1 || len(latestReconcile.ActualSAs) != 1 {
		t.Fatalf("ipsec reconcile detail = %+v, want desired and actual sa snapshots", latestReconcile)
	}
	var out bytes.Buffer
	view := buildStoredLinkInspection(rt, latestLinks, latestReconcile, nil, nil)
	if err := inspecttext.WriteLinksDebug(&out, view); err != nil {
		t.Fatalf("WriteLinksDebug: %v", err)
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
	if len(driver.Connections) != 0 || len(driver.Interfaces) != 0 {
		t.Fatalf("adopt maintenance = connections:%d interfaces:%+v, want no redundant apply when observed state matches", len(driver.Connections), driver.Interfaces)
	}
}

func TestDaemonStartupRecoversIPsecLinkState(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4125, 0)
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
	plan, err := ipsec.PlanTransportLinks(context.Background(), verified.Network, verified.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
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
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	service.recoverIPsecLinksOnStart(context.Background())

	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	latestLinks, latestReconcile := readTestIPsecObservation(service)
	inst := latestLinks[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp || inst.Endpoint != "198.51.100.20" {
		t.Fatalf("startup recovered instance = %+v, want up adopted endpoint", inst)
	}
	if latestReconcile == nil || len(latestReconcile.Actions) != 1 || latestReconcile.Actions[0].Action != ipsec.ReconcileActionAdopt {
		t.Fatalf("startup reconcile = %+v, want adopt", latestReconcile)
	}
	if len(driver.Connections) != 0 || len(driver.Interfaces) != 0 {
		t.Fatalf("startup adopt maintenance = connections:%d interfaces:%+v, want no redundant apply when observed state matches", len(driver.Connections), driver.Interfaces)
	}
}

func TestDaemonStartupRecreatesWhenEstablishedSAHasNoXFRMLink(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4126, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), verified.Network, verified.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
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
		linkState: &ipsec.XFRMLinkState{
			NetNS:           group.NetNS,
			NamespaceExists: false,
			InterfaceExists: false,
		},
	}
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	service.recoverIPsecLinksOnStart(context.Background())

	latestLinks, latestReconcile := readTestIPsecObservation(service)
	if latestReconcile == nil || len(latestReconcile.Actions) != 1 || latestReconcile.Actions[0].Action != ipsec.ReconcileActionCreate {
		t.Fatalf("startup reconcile = %+v, want create", latestReconcile)
	}
	inst := latestLinks[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("instance = %+v, want connecting after repair apply", inst)
	}
	assertDryRunApply(t, driver, spec, group.NetNS)
	if len(latestReconcile.ActualSAs) != 0 {
		t.Fatalf("actual SAs = %+v, want missing xfrm link to suppress matching SA", latestReconcile.ActualSAs)
	}
}

func TestDaemonStartupKeepsRotatedRuntimeSAWhenActiveXFRMLinkExists(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4128, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), verified.Network, verified.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	baseSpec := plan.Desired[0]
	updateDaemonTestPortRecord(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", 2, ipsec.DefaultNATTPort, now.Add(time.Minute))
	rotatedPlan, err := ipsec.PlanTransportLinks(context.Background(), verified.Network, verified.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now.Add(time.Minute)})
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
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now.Add(time.Minute) },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	service.recoverIPsecLinksOnStart(context.Background())

	latestLinks, latestReconcile := readTestIPsecObservation(service)
	if latestReconcile == nil || len(latestReconcile.ActualSAs) != 1 {
		t.Fatalf("startup reconcile actual SAs = %+v, want rotated SA retained", latestReconcile)
	}
	for _, action := range latestReconcile.Actions {
		if action.Action == ipsec.ReconcileActionRepair {
			t.Fatalf("startup reconcile action = %+v, want no repair for existing rotated xfrm link", action)
		}
	}
	inst := latestLinks[ipsec.LinkInstanceID(rotatedDesired)]
	if inst.InterfaceName != rotatedInterface || inst.XFRMIfID != rotatedIfID || inst.RemoteGeneration != 2 {
		t.Fatalf("instance = %+v, want rotated runtime interface %s/%d generation 2", inst, rotatedInterface, rotatedIfID)
	}
	if len(driver.Interfaces) != 0 {
		t.Fatalf("interfaces applied = %+v, want no redundant xfrm maintenance when rotated state matches", driver.Interfaces)
	}
}

func TestDaemonStartupRecoversDualGenerationRotationFromObservation(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4130, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	updateDaemonTestPortRecord(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", 2, ipsec.DefaultNATTPort, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), verified.Network, verified.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	desired := plan.Desired[0]
	current, err := ipsec.RuntimeSpecForPortGeneration(desired, group, 2)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(current): %v", err)
	}
	previous, err := ipsec.RuntimeSpecForPortGeneration(desired, group, 1)
	if err != nil {
		t.Fatalf("RuntimeSpecForPortGeneration(previous): %v", err)
	}
	driver := &batchObservedIPsecDriver{
		observedIPsecDriver: observedIPsecDriver{sas: []ipsec.SAState{
			{Name: current.TransportID, ChildSA: ipsec.ChildSAName(current), XFRMIfID: current.XFRMIfID, Endpoint: "198.51.100.20", Established: true},
			{Name: previous.TransportID, ChildSA: ipsec.ChildSAName(previous), XFRMIfID: previous.XFRMIfID, Endpoint: "198.51.100.20", Established: true},
		}, linkStates: map[string]ipsec.XFRMLinkState{
			current.InterfaceName:  healthyObservedXFRMState(current),
			previous.InterfaceName: healthyObservedXFRMState(previous),
		}},
		inventory: []ipsec.XFRMLinkState{
			{
				NetNS: group.NetNS, NamespaceExists: true, InterfaceExists: true,
				InterfaceName: current.InterfaceName, XFRMIfID: current.XFRMIfID,
				Addresses: []netip.Prefix{netip.PrefixFrom(current.LocalTunnelAddr, current.LocalTunnelAddr.BitLen())},
			},
			{
				NetNS: group.NetNS, NamespaceExists: true, InterfaceExists: true,
				InterfaceName: previous.InterfaceName, XFRMIfID: previous.XFRMIfID,
				Addresses: []netip.Prefix{netip.PrefixFrom(previous.LocalTunnelAddr, previous.LocalTunnelAddr.BitLen())},
			},
		},
	}
	rt := &AppContext{
		Config: appConfig, StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock: func() time.Time { return now },
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	service.recoverIPsecLinksOnStart(context.Background())

	latestLinks, latestReconcile := readTestIPsecObservation(service)
	inst := latestLinks[ipsec.LinkInstanceID(desired)]
	if inst.RemoteGeneration != 1 || inst.IKEName != previous.TransportID {
		t.Fatalf("active runtime = %+v, want previous generation retained", inst)
	}
	if inst.StagedGeneration != 2 || inst.StagedIKEName != current.TransportID || inst.RotatePhase != ipsec.RotatePhaseDualRunning || inst.RotateDeadline <= now.Unix() {
		t.Fatalf("rotation runtime = %+v, want current staged with restarted retention", inst)
	}
	if latestReconcile == nil || len(latestReconcile.Actions) != 1 || latestReconcile.Actions[0].Action != ipsec.ReconcileActionNoop || latestReconcile.Actions[0].Reason != "rotate retention active" {
		t.Fatalf("startup reconcile = %+v, want rotation retention", latestReconcile)
	}
	if len(driver.Connections) != 0 || len(driver.Interfaces) != 0 || len(driver.Terminated) != 0 || len(driver.Unloaded) != 0 {
		t.Fatalf("startup mutated dual runtime: connections=%+v interfaces=%+v terminated=%+v unloaded=%+v", driver.Connections, driver.Interfaces, driver.Terminated, driver.Unloaded)
	}

	// A crash after current became established but before previous cleanup must
	// reconstruct both generations long enough for the normal commit action to
	// retire the loaded previous connection and its XFRM interface.
	cleanupDriver := &batchObservedIPsecDriver{
		observedIPsecDriver: observedIPsecDriver{
			DryRunDriver: ipsec.DryRunDriver{LoadedConnections: []ipsec.ConnectionState{{
				Name: previous.TransportID, LocalIdentity: string(previous.LocalZone), RemoteIdentity: string(previous.PeerZone),
			}}},
			sas: []ipsec.SAState{{
				Name: current.TransportID, ChildSA: ipsec.ChildSAName(current), XFRMIfID: current.XFRMIfID,
				Endpoint: "198.51.100.20", Established: true,
			}},
			linkStates: map[string]ipsec.XFRMLinkState{
				current.InterfaceName:  healthyObservedXFRMState(current),
				previous.InterfaceName: healthyObservedXFRMState(previous),
			},
		},
		inventory: append([]ipsec.XFRMLinkState(nil), driver.inventory...),
	}
	cleanupService := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(cleanupService, cleanupDriver, cleanupDriver)

	cleanupService.recoverIPsecLinksOnStart(context.Background())

	cleanedLinks, cleanedReconcile := readTestIPsecObservation(cleanupService)
	cleaned := cleanedLinks[ipsec.LinkInstanceID(desired)]
	if cleaned.RemoteGeneration != 2 || cleaned.IKEName != current.TransportID || cleaned.StagedGeneration != 0 || cleaned.RotatePhase != ipsec.RotatePhaseIdle {
		t.Fatalf("cleaned runtime = %+v, want current-only idle", cleaned)
	}
	if cleanedReconcile == nil || len(cleanedReconcile.Actions) != 1 || cleanedReconcile.Actions[0].Action != ipsec.ReconcileActionCommitRotate {
		t.Fatalf("cleanup reconcile = %+v, want commit_rotate", cleanedReconcile)
	}
	if len(cleanupDriver.Terminated) != 1 || cleanupDriver.Terminated[0] != previous.TransportID || len(cleanupDriver.Unloaded) != 1 || cleanupDriver.Unloaded[0] != previous.TransportID || len(cleanupDriver.DeletedIFs) != 1 || cleanupDriver.DeletedIFs[0] != previous.InterfaceName {
		t.Fatalf("previous cleanup: terminated=%+v unloaded=%+v deleted=%+v", cleanupDriver.Terminated, cleanupDriver.Unloaded, cleanupDriver.DeletedIFs)
	}
}

func TestDaemonStartupRecoversSecondaryTakeoverFromObservation(t *testing.T) {
	now := time.Unix(4132, 0)
	verifiedA, _, verifiedB, configB := buildTestABVerifiedStates(t)
	_, recordA := daemonTestTransportKey(t, now)
	keyB, recordB := daemonTestTransportKey(t, now)
	addDaemonTestIPsecRecords(t, verifiedA.Network.Zones["node-a.catofes."], "node-a.catofes.", "192.0.2.1", recordA, ipsec.RoleBoth, now)
	addDaemonTestIPsecRecords(t, verifiedB.Network.Zones["node-b.catofes."], "node-b.catofes.", "192.0.2.2", recordB, ipsec.RoleBoth, now)
	verifiedB.Network.Zones["node-a.catofes."] = verifiedA.Network.Zones["node-a.catofes."]
	group := testIPsecLinkGroup()
	group.ConnectRules = nil
	setTestIPsecOverlayIntent(t, verifiedB.Network.Zones["node-a.catofes."], "node-a.catofes.", group, now)
	setTestIPsecOverlayIntent(t, verifiedB.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := testDaemonIPsecAppConfig(t.TempDir(), "127.0.0.1:0", group)
	appConfig.PeerID = configB.PeerID
	plan, err := ipsec.PlanTransportLinks(context.Background(), verifiedB.Network, verifiedB.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	if plan.Roles[ipsec.LinkInstanceID(spec)] != ipsec.InitiatorRoleSecondaryStandby {
		t.Fatalf("role = %q, want secondary standby", plan.Roles[ipsec.LinkInstanceID(spec)])
	}
	driver := &batchObservedIPsecDriver{
		observedIPsecDriver: observedIPsecDriver{
			sas: []ipsec.SAState{{
				Name: spec.TransportID, ChildSA: ipsec.ChildSAName(spec), XFRMIfID: spec.XFRMIfID,
				Endpoint: "192.0.2.1:4500", Established: true, Initiator: true, InitiatorKnown: true,
			}},
			linkStates: map[string]ipsec.XFRMLinkState{spec.InterfaceName: healthyObservedXFRMState(spec)},
		},
		inventory: []ipsec.XFRMLinkState{{
			NetNS: group.NetNS, NamespaceExists: true, InterfaceExists: true,
			InterfaceName: spec.InterfaceName, XFRMIfID: spec.XFRMIfID,
			Addresses: []netip.Prefix{netip.PrefixFrom(spec.LocalTunnelAddr, spec.LocalTunnelAddr.BitLen())},
		}},
	}
	rt := &AppContext{Config: appConfig, StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
	service := newTestDaemonFromOwners(rt, verifiedB, nil, &photonlinux.LinuxState{IPsecTransportKey: keyB}, configB, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	service.recoverIPsecLinksOnStart(context.Background())

	links, reconcile := readTestIPsecObservation(service)
	inst := links[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateUp || inst.InitiatorRole != ipsec.InitiatorRoleSecondaryTakeover || inst.TakeoverPhase != ipsec.TakeoverPhaseActive {
		t.Fatalf("takeover runtime = %+v, want active recovered takeover", inst)
	}
	if inst.TakeoverStartedAt != now.Unix() || inst.TakeoverUntil <= now.Unix() {
		t.Fatalf("takeover lease = started:%d until:%d, want fresh bounded lease", inst.TakeoverStartedAt, inst.TakeoverUntil)
	}
	if inst.BackoffUntil != 0 || inst.FailureCount != 0 || inst.LastTakeoverFailure != nil {
		t.Fatalf("takeover recovered stale retry state: %+v", inst)
	}
	if reconcile == nil || len(reconcile.Actions) != 1 || reconcile.Actions[0].Action != ipsec.ReconcileActionAdopt {
		t.Fatalf("startup reconcile = %+v, want adopt", reconcile)
	}
}

func TestDaemonStartupCreatesWhenNoRuntimeResourcesObserved(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4135, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig := defaultAppConfig()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), verified.Network, verified.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	driver := &observedIPsecDriver{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	service.recoverIPsecLinksOnStart(context.Background())

	if driver.listCalls != 1 {
		t.Fatalf("ListSAs calls = %d, want 1", driver.listCalls)
	}
	assertDryRunApply(t, driver, spec, group.NetNS)
	latestLinks, latestReconcile := readTestIPsecObservation(service)
	inst := latestLinks[ipsec.LinkInstanceID(spec)]
	if inst.ActualState != ipsec.LinkStateConnecting {
		t.Fatalf("startup repaired instance = %+v, want connecting", inst)
	}
	if latestReconcile == nil || len(latestReconcile.Actions) != 1 || latestReconcile.Actions[0].Action != ipsec.ReconcileActionCreate {
		t.Fatalf("startup reconcile = %+v, want create", latestReconcile)
	}
}

func TestDaemonRevocationTearsDownIPsecLinkAndBlocksRecreate(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(4140, 0)
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
	driver := &observedIPsecDriver{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

	service.notifyStateChanged()
	common := service.State.Common.ReadView()
	persistedRuntime := service.State.ReadLinux()
	latestLinks, latestReconcile := readTestIPsecObservation(service)
	spec := singleDesiredSpec(t, common.State.ManagedZone, latestReconcile)
	if len(latestLinks) != 1 {
		t.Fatalf("link instances after create = %+v, want one", latestLinks)
	}

	parent := common.State.Network.Zones["catofes."]
	delegation := parent.Delegations["node-b.catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node-b.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  delegation.AuthorityHash,
		Reason:                "ipsec smoke revoke",
		RevokedAt:             now.Add(-time.Second).Unix(),
	}
	service = newTestDaemonFromOwners(rt, common.State, common.Gossip, persistedRuntime, config, time.Second)
	service.linuxObservation.replaceIPsec(latestLinks, latestReconcile)
	installTestIPsecDrivers(service, driver, driver)
	service.notifyStateChanged()

	revokedLinks, revokedReconcile := readTestIPsecObservation(service)
	if len(revokedLinks) != 0 {
		t.Fatalf("link instances after revoke = %+v, want none", revokedLinks)
	}
	if revokedReconcile == nil || len(revokedReconcile.Actions) != 1 || revokedReconcile.Actions[0].Action != ipsec.ReconcileActionTeardown {
		t.Fatalf("revoke reconcile = %+v, want teardown", revokedReconcile)
	}
	if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID || len(driver.Unloaded) != 1 || driver.Unloaded[0] != spec.TransportID || len(driver.DeletedIFs) != 1 || driver.DeletedIFs[0] != spec.InterfaceName {
		t.Fatalf("teardown driver state terminated=%+v unloaded=%+v deleted=%+v", driver.Terminated, driver.Unloaded, driver.DeletedIFs)
	}
	if !hasDebugSkip(revokedReconcile.Skipped, "node-b.catofes.", ipsec.SkipRevokedZone) {
		t.Fatalf("skips = %+v, want revoked zone", revokedReconcile.Skipped)
	}

	service.notifyStateChanged()
	stableLinks, stableReconcile := readTestIPsecObservation(service)
	if len(stableLinks) != 0 || len(stableReconcile.Actions) != 0 || stableReconcile.DesiredLinks != 0 {
		t.Fatalf("stable revoked reconcile = %+v instances=%+v, want no recreate", stableReconcile, stableLinks)
	}
}

func TestDaemonRestartRequiresExplicitOrphanCleanupAfterDesiredLinkRemoval(t *testing.T) {
	for _, mode := range []string{"revoked", "config_removed"} {
		t.Run(mode, func(t *testing.T) {
			verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
			now := time.Unix(4145, 0)
			addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
			group := testIPsecLinkGroup()
			setTestIPsecOverlayIntent(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
			appConfig := defaultAppConfig()
			appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
			plan, err := ipsec.PlanTransportLinks(context.Background(), verified.Network, verified.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
			if err != nil {
				t.Fatalf("PlanTransportLinks: %v", err)
			}
			if len(plan.Desired) != 1 {
				t.Fatalf("desired links = %d, want 1 before removal", len(plan.Desired))
			}
			spec := plan.Desired[0]

			switch mode {
			case "revoked":
				parent := verified.Network.Zones["catofes."]
				delegation := parent.Delegations["node-b.catofes."]
				parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
					ChildZone: "node-b.catofes.", ParentZone: "catofes.",
					RevokedAuthorityEpoch: delegation.AuthorityEpoch, RevokedAuthorityHash: delegation.AuthorityHash,
					Reason: "restart cleanup test", RevokedAt: now.Add(-time.Second).Unix(),
				}
			case "config_removed":
				appConfig.IPsec.LinkGroups = nil
			}

			driver := &observedIPsecDriver{DryRunDriver: ipsec.DryRunDriver{LoadedConnections: []ipsec.ConnectionState{
				{Name: spec.TransportID, LocalIdentity: string(spec.LocalZone), RemoteIdentity: string(spec.PeerZone)},
				{Name: "manual-vpn"},
			}}}
			rt := &AppContext{Config: appConfig, StatePath: filepath.Join(t.TempDir(), "photon.db"), Clock: func() time.Time { return now }}
			service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
			installTestIPsecDrivers(service, driver, driver)

			service.recoverIPsecLinksOnStart(context.Background())

			links, reconcile := readTestIPsecObservation(service)
			if len(links) != 0 || reconcile == nil || reconcile.DesiredLinks != 0 || len(reconcile.Actions) != 0 {
				t.Fatalf("startup reconcile = %+v links=%+v, want no adopted or automatic orphan cleanup", reconcile, links)
			}
			if len(driver.Terminated) != 0 || len(driver.Unloaded) != 0 {
				t.Fatalf("startup removed unowned observation: terminated=%+v unloaded=%+v", driver.Terminated, driver.Unloaded)
			}

			cleaned, orphans, err := service.handleIPsecCleanupEvent(context.Background(), true)
			if err != nil {
				t.Fatalf("handleIPsecCleanupEvent: %v", err)
			}
			if cleaned != 0 || orphans != 1 {
				t.Fatalf("cleanup result = links:%d orphans:%d, want 0/1", cleaned, orphans)
			}
			if len(driver.Terminated) != 1 || driver.Terminated[0] != spec.TransportID || len(driver.Unloaded) != 1 || driver.Unloaded[0] != spec.TransportID {
				t.Fatalf("orphan cleanup: terminated=%+v unloaded=%+v", driver.Terminated, driver.Unloaded)
			}
			if len(driver.DeletedIFs) != 0 {
				t.Fatalf("orphan connection cleanup deleted unproven XFRM interfaces: %+v", driver.DeletedIFs)
			}
		})
	}
}

func TestCleanupIPsecLinkInstancesTearsDownManagedLinks(t *testing.T) {
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
	links := map[string]ipsec.LinkInstance{inst.ID: inst}
	driver := &ipsec.DryRunDriver{}

	platformDriver := newTestLinuxDriver(driver, driver)
	remaining, cleaned, err := cleanupIPsecLinkInstanceSet(context.Background(), links, []string{inst.ID}, platformDriver)
	if err != nil {
		t.Fatalf("cleanupLinuxDriverIPsecLinks: %v", err)
	}
	if cleaned != 1 {
		t.Fatalf("cleaned = %d, want 1", cleaned)
	}
	if len(remaining) != 0 {
		t.Fatalf("link instances = %+v, want empty", remaining)
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
}

func TestRecoveryPurgeRevokedApplyCleansIPsecLinksBeforeDeletingState(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(5101, 0)
	addRevocationTombstoneForTest(t, verified.Network, "node-b.catofes.", "catofes.")
	spec := ipsec.TransportLinkSpec{
		LocalZone:     verified.ManagedZone,
		PeerZone:      "node-b.catofes.",
		OverlayID:     "main",
		TransportID:   "ipsec-purge-revoked",
		InterfaceName: "phx-purge0",
		XFRMIfID:      5101,
	}
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
	observationLinks := map[string]ipsec.LinkInstance{inst.ID: inst}
	checkpoint.Peers = map[string]corestate.PeerCheckpoint{"node-b.catofes.": {}}
	rt := &AppContext{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	driver := &ipsec.DryRunDriver{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	setTestIPsecObservation(service, observationLinks, nil)
	installTestIPsecDrivers(service, driver, driver)

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
	common := service.State.Common.ReadView()
	latestLinks, latestReconcile := readTestIPsecObservation(service)
	if common.State.Network.Zones["node-b.catofes."] != nil {
		t.Fatalf("revoked zone still present after purge")
	}
	if _, ok := latestLinks[inst.ID]; ok {
		t.Fatalf("revoked link instance still present after purge")
	}
	if _, ok := common.Gossip.Peers["node-b.catofes."]; ok {
		t.Fatalf("revoked sync peer still present after purge")
	}
	if latestReconcile == nil || latestReconcile.LastRunUnix != now.Unix() {
		t.Fatalf("ipsec cleanup snapshot = %+v, want timestamp", latestReconcile)
	}
}

func TestRecoveryCleanupIPsecDirectNoLinksDoesNotRequireVICI(t *testing.T) {
	verified, checkpoint, runtime, _ := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	now := time.Unix(5105, 0)
	rt := &AppContext{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	seedPartitionedStateDB(t, rt.StatePath, verified, checkpoint, runtime)
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
}

func TestCleanupIPsecOrphanConnectionsOnlyRemovesUnreferencedPhotonConnections(t *testing.T) {
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
	links := map[string]ipsec.LinkInstance{inst.ID: inst}
	driver := &ipsec.DryRunDriver{
		LoadedConnections: []ipsec.ConnectionState{
			{Name: "ipsec-managed"},
			{Name: "ipsec-orphan-r3"},
			{Name: "manual-vpn"},
		},
	}

	platformDriver := newTestLinuxDriver(driver, driver)
	cleaned, err := platformDriver.CleanupIPsecOrphans(context.Background(), managedIPsecConnectionNamesFromLinks(links))
	if err != nil {
		t.Fatalf("CleanupIPsecOrphans: %v", err)
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
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(5110, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	appConfig := defaultAppConfig()
	group := testIPsecLinkGroup()
	setTestIPsecOverlayIntent(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", group, now)
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{group}
	plan, err := ipsec.PlanTransportLinks(context.Background(), verified.Network, verified.ManagedZone, appConfig.IPsec.LinkGroups, ipsec.LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired links = %d, want 1", len(plan.Desired))
	}
	spec := plan.Desired[0]
	inst := ipsec.NewLinkInstance(spec, ipsec.LinkStateUp, now)
	observationLinks := map[string]ipsec.LinkInstance{inst.ID: inst}
	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	driver := &observedIPsecDriver{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	setTestIPsecObservation(service, observationLinks, nil)
	installTestIPsecDrivers(service, driver, driver)

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
	latestLinks, _ := readTestIPsecObservation(service)
	if len(latestLinks) != 1 {
		t.Fatalf("observed link instances = %+v, want recreated link", latestLinks)
	}
	recreated := latestLinks[ipsec.LinkInstanceID(spec)]
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

func TestDaemonIPsecCleanupEventCanCleanOrphanConnections(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(5112, 0)
	rt := &AppContext{
		Config:    defaultAppConfig(),
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	driver := &ipsec.DryRunDriver{
		LoadedConnections: []ipsec.ConnectionState{{Name: "ipsec-orphan-r3"}},
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestIPsecDrivers(service, driver, driver)

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
