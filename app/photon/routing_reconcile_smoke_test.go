package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestRoutingDryRunSmoke(t *testing.T) {
	verified, checkpoint, runtime, config, _ := buildDryRunSmokeOwners(t)
	now := time.Unix(4000, 0)

	// Verify the route set authorizes the expected announcements without errors.
	ars, err := routing.BuildAuthorizedRouteSet(verified.Network, now)
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) > 0 {
		t.Fatalf("unexpected authorization errors: %+v", ars.Errors)
	}

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "ipsec-main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "ipsec-main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return now },
	}

	pm := &fakeBirdProcessManager{running: false}
	client := &fakeBirdClient{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, pm, func(socketPath string, timeout time.Duration) birdClient {
		return client
	})

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	_, latest := service.StateStore.readCommonAndRuntime()
	if len(latest.BirdInstances) != 1 {
		t.Fatalf("BirdInstances len = %d, want 1", len(latest.BirdInstances))
	}
	inst := latest.BirdInstances["photontesth2"]
	if inst == nil {
		t.Fatalf("missing bird instance state for netns photontesth2")
	}
	if inst.State == birdInstanceStateError {
		t.Fatalf("bird instance state is error: %s", inst.LastError)
	}
	if inst.ConfigPath == "" {
		t.Fatalf("ConfigPath is empty")
	}

	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	importIdx := strings.Index(cfg, "filter photon_import_photontesth2")
	exportIdx := strings.Index(cfg, "filter photon_export_photontesth2")
	if importIdx == -1 || exportIdx == -1 {
		t.Fatalf("missing import/export filters")
	}
	importFilter := cfg[importIdx:exportIdx]
	exportFilter := cfg[exportIdx:]

	// Import filter should contain authorized route announcement prefixes exactly.
	if !strings.Contains(importFilter, "10.0.1.0/24") {
		t.Errorf("import filter missing authorized route prefix 10.0.1.0/24")
	}
	if !strings.Contains(importFilter, "10.1.1.0/24") {
		t.Errorf("import filter missing authorized route prefix 10.1.1.0/24")
	}

	// Export filter should contain only the local announcement.
	if !strings.Contains(exportFilter, "10.0.1.0/24") {
		t.Errorf("export filter missing local prefix 10.0.1.0/24")
	}
	if strings.Contains(exportFilter, "10.1.1.0/24") {
		t.Errorf("export filter should not contain remote prefix 10.1.1.0/24")
	}

	// The reconcile run itself should not have recorded any error.
	if latest.RoutingReconcile != nil && latest.RoutingReconcile.LastError != "" {
		t.Errorf("unexpected routing reconcile error: %s", latest.RoutingReconcile.LastError)
	}
}

func TestIPAMRoutingSmoke(t *testing.T) {
	verified, checkpoint, runtime, config, signers, rt := buildIPAMRoutingSmokeOwners(t)
	rt.DisableControl = true
	now := rt.Now()

	// Construct records signed by both authorities without pretending that one
	// persisted node can switch its managed identity between CLI calls.
	if err := applyAuthoritativeTestIntentAs(verified, "catofes.", signers["catofes."], commonIPAMIntentForTest(t, ipamMutationRequest{
		Operation: ipamOperationPoolCreate,
		Zone:      "catofes.", Prefix: "10.0.0.0/16", Target: "catofes.",
	}), now); err != nil {
		t.Fatalf("catofes pool write: %v", err)
	}
	if err := applyAuthoritativeTestIntentAs(verified, "catofes.", signers["catofes."], commonIPAMIntentForTest(t, ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      "catofes.", Prefix: "10.0.0.0/16", Target: "node-a.catofes.",
	}), now); err != nil {
		t.Fatalf("catofes IPAM writes: %v", err)
	}

	if err := applyAuthoritativeTestIntentAs(verified, "node-a.catofes.", signers["node-a.catofes."], commonRouteIntent(routeMutationRequest{
		Zone: "node-a.catofes.", Prefix: "10.0.1.0/24", Active: true,
	}), now); err != nil {
		t.Fatalf("node-a route announce: %v", err)
	}
	// Verify the authorized route set before reconcile.
	ars, err := routing.BuildAuthorizedRouteSet(verified.Network, now)
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) > 0 {
		t.Fatalf("unexpected authorization errors: %+v", ars.Errors)
	}
	if _, ok := ars.Announced["node-a.catofes."][netip.MustParsePrefix("10.0.1.0/24")]; !ok {
		t.Fatalf("expected 10.0.1.0/24 to be authorized for node-a.catofes.")
	}

	// Reconcile routing and verify BIRD config import/export filters.
	pm := &fakeBirdProcessManager{running: false}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, pm, func(socketPath string, timeout time.Duration) birdClient {
		return &fakeBirdClient{}
	})

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	_, latest := service.StateStore.readCommonAndRuntime()
	inst := latest.BirdInstances["photontesth2"]
	if inst == nil || inst.ConfigPath == "" {
		t.Fatalf("missing bird instance state or config path")
	}

	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	importIdx := strings.Index(cfg, "filter photon_import_photontesth2")
	exportIdx := strings.Index(cfg, "filter photon_export_photontesth2")
	if importIdx == -1 || exportIdx == -1 {
		t.Fatalf("missing import/export filters")
	}
	importFilter := cfg[importIdx:exportIdx]
	exportFilter := cfg[exportIdx:]

	if !strings.Contains(importFilter, "10.0.1.0/24") {
		t.Errorf("import filter missing authorized route prefix 10.0.1.0/24")
	}
	if !strings.Contains(exportFilter, "10.0.1.0/24") {
		t.Errorf("export filter missing local announcement prefix 10.0.1.0/24")
	}

	_ = signers
}

func TestAutoAnnounceAssignedIPsRoutingSmoke(t *testing.T) {
	verified, checkpoint, runtime, config, signers, rt := buildIPAMRoutingSmokeOwners(t)
	rt.DisableControl = true
	rt.Config.IPAM.AutoAnnounceAssignedIPs = true
	now := rt.Now()

	if err := applyAuthoritativeTestIntentAs(verified, "catofes.", signers["catofes."], commonIPAMIntentForTest(t, ipamMutationRequest{
		Operation: ipamOperationPoolCreate,
		Zone:      "catofes.", Prefix: "10.0.0.0/16", Target: "catofes.",
	}), now); err != nil {
		t.Fatalf("catofes pool write: %v", err)
	}
	if err := applyAuthoritativeTestIntentAs(verified, "catofes.", signers["catofes."], commonIPAMIntentForTest(t, ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      "catofes.", Prefix: "10.0.0.0/24", Target: "node-a.catofes.",
	}), now); err != nil {
		t.Fatalf("catofes assignment write: %v", err)
	}
	// Reconcile routing and let auto-announce publish the route.
	pm := &fakeBirdProcessManager{running: false}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, pm, func(socketPath string, timeout time.Duration) birdClient {
		return &fakeBirdClient{}
	})

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	// Verify the route announcement record was auto-published.
	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	common := service.StateStore.common.ReadView()
	rec := common.State.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected auto-published announcement for 10.0.0.0/24")
	}
	ann, err := routing.ParseRouteAnnouncementRecord(rec)
	if err != nil {
		t.Fatalf("ParseRouteAnnouncementRecord: %v", err)
	}
	if !ann.Active {
		t.Fatalf("expected active auto-published announcement")
	}
	if ann.Prefix != "10.0.0.0/24" {
		t.Fatalf("expected prefix 10.0.0.0/24, got %s", ann.Prefix)
	}

	// Verify the BIRD export filter includes the auto-announced prefix.
	_, latest := service.StateStore.readCommonAndRuntime()
	inst := latest.BirdInstances["photontesth2"]
	if inst == nil || inst.ConfigPath == "" {
		t.Fatalf("missing bird instance state or config path")
	}
	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}
	exportIdx := strings.Index(cfg, "filter photon_export_photontesth2")
	if exportIdx == -1 {
		t.Fatalf("missing export filter")
	}
	exportFilter := cfg[exportIdx:]
	if !strings.Contains(exportFilter, "10.0.0.0/24") {
		t.Errorf("export filter missing auto-announced prefix 10.0.0.0/24")
	}

	_ = now
}

func TestRoutingDryRunSmokeRevokeAssignment(t *testing.T) {
	verified, checkpoint, runtime, config, signers := buildDryRunSmokeOwners(t)
	now := time.Unix(4000, 0)

	// Initial authorized route set should authorize node-a's announcement.
	ars, err := routing.BuildAuthorizedRouteSet(verified.Network, now)
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) > 0 {
		t.Fatalf("unexpected authorization errors: %+v", ars.Errors)
	}
	if _, ok := ars.Announced["node-a.catofes."][netip.MustParsePrefix("10.0.1.0/24")]; !ok {
		t.Fatalf("expected 10.0.1.0/24 to be authorized for node-a.catofes.")
	}
	if _, ok := ars.Assignments[netip.MustParsePrefix("10.0.0.0/16")]; !ok {
		t.Fatalf("expected 10.0.0.0/16 assignment to be present")
	}

	// Revoke the assignment covering node-a's announcement.
	addRouteAssignment(t, verified.Network, "catofes.", "10.0.0.0/16", "node-a.catofes.", false, now.Add(time.Second), signers["catofes."])

	// After revocation the assignment and its authorized announcement should disappear.
	ars, err = routing.BuildAuthorizedRouteSet(verified.Network, now.Add(time.Second))
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet after revoke: %v", err)
	}
	if _, ok := ars.Announced["node-a.catofes."][netip.MustParsePrefix("10.0.1.0/24")]; ok {
		t.Fatalf("expected 10.0.1.0/24 to be removed from authorized announcements after assignment revoke")
	}
	if _, ok := ars.Assignments[netip.MustParsePrefix("10.0.0.0/16")]; ok {
		t.Fatalf("expected 10.0.0.0/16 assignment to be removed after revoke")
	}
	foundErr := false
	for _, e := range ars.Errors {
		if e.Code == "route_unauthorized_no_assignment" && e.Prefix == netip.MustParsePrefix("10.0.1.0/24") {
			foundErr = true
			break
		}
	}
	if !foundErr {
		t.Fatalf("expected route_unauthorized_no_assignment error for 10.0.1.0/24, got %+v", ars.Errors)
	}

	// Reconcile routing again and verify the export filter no longer contains the revoked prefix.
	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "ipsec-main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "ipsec-main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return now.Add(time.Second) },
	}

	pm := &fakeBirdProcessManager{running: false}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, pm, func(socketPath string, timeout time.Duration) birdClient {
		return &fakeBirdClient{}
	})

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	_, latest := service.StateStore.readCommonAndRuntime()
	inst := latest.BirdInstances["photontesth2"]
	if inst == nil || inst.ConfigPath == "" {
		t.Fatalf("missing bird instance state or config path")
	}

	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	importIdx := strings.Index(cfg, "filter photon_import_photontesth2")
	exportIdx := strings.Index(cfg, "filter photon_export_photontesth2")
	if importIdx == -1 || exportIdx == -1 {
		t.Fatalf("missing import/export filters")
	}
	importFilter := cfg[importIdx:exportIdx]
	exportFilter := cfg[exportIdx:]

	if !strings.Contains(importFilter, "10.1.1.0/24") {
		t.Errorf("import filter missing remaining authorized route prefix 10.1.1.0/24")
	}
	if strings.Contains(importFilter, "10.0.1.0/24") {
		t.Errorf("import filter should not contain revoked route prefix 10.0.1.0/24")
	}
	if strings.Contains(exportFilter, "10.0.1.0/24") {
		t.Errorf("export filter should not contain revoked local prefix 10.0.1.0/24")
	}
}
