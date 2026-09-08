package main

import (
	"context"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// TestUpstreamRoutingDryRunSmoke verifies that the upstream veth + static route
// pipeline produces a valid BIRD config with multi-interface blocks and the
// filter correctly includes the assigned prefixes.
func TestUpstreamRoutingDryRunSmoke(t *testing.T) {
	verified, checkpoint, runtime, syncConfig := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}

	upstreamYAML := []routingInstanceYAML{{
		ID:           "main",
		NetNS:        "photontesth2",
		Enabled:      boolPtr(true),
		Mode:         ipsec.RoutingModeManaged,
		InterfacePat: "phx*",
		Upstream: &upstreamConfigYAML{
			Enabled:    boolPtr(true),
			CreateVeth: boolPtr(true),
			Mesh: upstreamEndpointYAML{
				Interface: "phv2host",
				IPv4LL:    "169.254.0.1/30",
				IPv6LL:    "fe80::1/64",
			},
			External: upstreamEndpointYAML{
				Interface: "phv2mesh",
				IPv4LL:    "169.254.0.2/30",
				IPv6LL:    "fe80::2/64",
			},
		},
	}}
	appConfig.Routing, _ = parseRoutingConfigInstances(upstreamYAML, appConfig.Netns, appConfig.DataDir)

	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}

	// Verify upstream config was parsed correctly.
	inst := appConfig.Routing.Instances[0]
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream config not parsed correctly")
	}

	// Build a fake veth manager.
	fakeVM := &fakeVethManager{}
	fakeRM := &fakeUpstreamRouteManager{}
	pm := &fakeBirdProcessManager{running: false}
	client := &fakeBirdClient{}

	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, syncConfig, time.Second)
	installTestLinuxDrivers(service, testLinuxDrivers{
		veth: fakeVM, upstreamRoutes: fakeRM, birdProcess: pm,
		birdClientFactory: func(socketPath string, timeout time.Duration) birdClient { return client },
	})

	ctx := context.Background()
	if err := service.reconcileRouting(ctx); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	// Verify veth manager was called.
	if !fakeVM.ensureCalled {
		t.Error("vethManager.EnsureVethPair was not called during reconcile")
	}
	if fakeVM.ensureSpec.MeshInterface != "phv2host" || fakeVM.ensureSpec.PeerInterface != "phv2mesh" {
		t.Fatalf("veth interfaces = %q/%q", fakeVM.ensureSpec.MeshInterface, fakeVM.ensureSpec.PeerInterface)
	}
	if fakeVM.ensureSpec.MeshIPv4LL != "169.254.0.1/30" || fakeVM.ensureSpec.PeerIPv4LL != "169.254.0.2/30" {
		t.Fatalf("veth IPv4 LL = %q/%q", fakeVM.ensureSpec.MeshIPv4LL, fakeVM.ensureSpec.PeerIPv4LL)
	}
	if fakeVM.ensureSpec.MeshIPv6LL != "fe80::1/64" || fakeVM.ensureSpec.PeerIPv6LL != "fe80::2/64" {
		t.Fatalf("veth IPv6 LL = %q/%q", fakeVM.ensureSpec.MeshIPv6LL, fakeVM.ensureSpec.PeerIPv6LL)
	}
	if !fakeRM.ensureCalled {
		t.Error("upstreamRouteManager.EnsureRoutes was not called during reconcile")
	}
	if fakeRM.ensureSpec.NetNS != "" || fakeRM.ensureSpec.Interface != "phv2mesh" {
		t.Fatalf("upstream route target = netns %q iface %q, want host phv2mesh", fakeRM.ensureSpec.NetNS, fakeRM.ensureSpec.Interface)
	}
	if !prefixesContain(fakeRM.ensureSpec.Prefixes, "10.1.0.0/24") {
		t.Fatalf("upstream routes missing remote prefix 10.1.0.0/24: %+v", fakeRM.ensureSpec.Prefixes)
	}
	if prefixesContain(fakeRM.ensureSpec.Prefixes, "10.0.0.0/24") {
		t.Fatalf("upstream routes should not send local assigned prefix back to mesh: %+v", fakeRM.ensureSpec.Prefixes)
	}
	if !prefixesContain(fakeRM.ensureSpec.SourcePrefixes, "10.0.0.1/16") {
		t.Fatalf("upstream route source prefixes missing local source 10.0.0.1/16: %+v", fakeRM.ensureSpec.SourcePrefixes)
	}
	if fakeRM.ensureSpec.MeshIPv4LL != "169.254.0.1/30" {
		t.Fatalf("upstream route mesh ipv4_ll = %q, want 169.254.0.1/30", fakeRM.ensureSpec.MeshIPv4LL)
	}
	if fakeRM.ensureSpec.MeshIPv6LL != "fe80::1/64" {
		t.Fatalf("upstream route mesh ipv6_ll = %q, want fe80::1/64", fakeRM.ensureSpec.MeshIPv6LL)
	}

	// Read the generated config and verify upstream interface + static route support.
	_, latest := service.StateStore.readCommonAndRuntime()
	birdState := latest.BirdInstances["photontesth2"]
	if birdState == nil {
		t.Fatal("BirdInstances[photontesth2] is nil")
	}
	if birdState.State != birdInstanceStateRunning {
		t.Errorf("bird state = %q, want running", birdState.State)
	}

	// Read the generated config file.
	cfgBytes, err := os.ReadFile(birdState.ConfigPath)
	if err != nil {
		t.Fatalf("read config: %v", err)
	}
	cfgStr := string(cfgBytes)

	// Assert upstream interface block exists.
	if !strings.Contains(cfgStr, `interface "phv2host" {`) {
		t.Errorf("BIRD config missing upstream interface block\n%s", cfgStr)
	}

	// Assert the primary mesh interface uses gradual ETX costing.
	if !strings.Contains(cfgStr, "type wireless;") {
		t.Errorf("BIRD config missing type wireless in primary block\n%s", cfgStr)
	}

	// Exactly one wireless block: primary mesh only, not upstream.
	if cnt := strings.Count(cfgStr, "type wireless;"); cnt != 1 {
		t.Errorf("expected exactly 1 type wireless, got %d\n%s", cnt, cfgStr)
	}

	// Assert default route rejection in filters.
	if !strings.Contains(cfgStr, "if net ~ [ 0.0.0.0/0 ] then reject;") {
		t.Errorf("BIRD config missing IPv4 default route rejection\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, "if net ~ [ ::/0 ] then reject;") {
		t.Errorf("BIRD config missing IPv6 default route rejection\n%s", cfgStr)
	}
}

// TestUpstreamRoutingWithIPAMAssignment verifies that IPAM assignments for the
// local zone produce static routes via the upstream interface.
func TestUpstreamRoutingWithIPAMAssignment(t *testing.T) {
	verified, _, _, _ := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	// Add an IPAM assignment for node-a.catofes.
	assignmentPrefix := netip.MustParsePrefix("10.42.0.0/24")
	assignmentRec := routing.IPAMAssignmentRecord{
		Version:    1,
		Prefix:     assignmentPrefix.String(),
		AssignedTo: "node-a.catofes.",
		Active:     true,
	}
	assignmentValue, _ := json.Marshal(assignmentRec)
	assignmentKey := routing.RecordKeyPrefixIPAMAssignments + strings.ReplaceAll(assignmentPrefix.String(), "/", "_")
	if zs := verified.Network.Zones["node-a.catofes."]; zs != nil {
		zs.Records[assignmentKey] = &zone.Record{
			Zone:      "node-a.catofes.",
			Key:       assignmentKey,
			Value:     assignmentValue,
			Type:      routing.RecordTypeIPAMAssignment,
			Version:   1,
			Timestamp: now.Unix(),
		}
	}
	// Also add a pool covering the assignment in the root zone.
	poolRec := routing.IPAMPoolRecord{
		Version:     1,
		Prefix:      "10.42.0.0/16",
		DelegatedTo: "catofes.",
		Active:      true,
	}
	poolValue, _ := json.Marshal(poolRec)
	poolKey := routing.RecordKeyPrefixIPAMPools + strings.ReplaceAll("10.42.0.0/16", "/", "_")
	if zs := verified.Network.Zones[zone.RootZone]; zs != nil {
		zs.Records[poolKey] = &zone.Record{
			Zone:      zone.RootZone,
			Key:       poolKey,
			Value:     poolValue,
			Type:      routing.RecordTypeIPAMPool,
			Version:   1,
			Timestamp: now.Unix(),
		}
	}
	// Add sub-assignment in catofes for node-a.
	catAssignmentRec := routing.IPAMAssignmentRecord{
		Version:    1,
		Prefix:     "10.42.0.0/24",
		AssignedTo: "node-a.catofes.",
		Active:     true,
	}
	catAssignmentValue, _ := json.Marshal(catAssignmentRec)
	catAssignmentKey := routing.RecordKeyPrefixIPAMAssignments + strings.ReplaceAll("10.42.0.0/24", "/", "_")
	if zs := verified.Network.Zones["catofes."]; zs != nil {
		zs.Records[catAssignmentKey] = &zone.Record{
			Zone:      "catofes.",
			Key:       catAssignmentKey,
			Value:     catAssignmentValue,
			Type:      routing.RecordTypeIPAMAssignment,
			Version:   1,
			Timestamp: now.Unix(),
		}
	}

	// Build AuthorizedRouteSet and verify the assignment is present.
	ars, err := routing.BuildAuthorizedRouteSet(verified.Network, now)
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}

	dataDir := t.TempDir()
	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}

	// Build the BirdInstanceSpec via parseRoutingConfigInstances for proper path derivation.
	yamlInstances := []routingInstanceYAML{{
		ID:           "main",
		NetNS:        "photontesth2",
		Enabled:      boolPtr(true),
		Mode:         "managed",
		InterfacePat: "phx*",
		Upstream: &upstreamConfigYAML{
			Enabled: boolPtr(true),
			Mesh: upstreamEndpointYAML{
				Interface: "phv2host",
				IPv6LL:    "fe80::1/64",
			},
		},
	}}
	parsedCfg, err := parseRoutingConfigInstances(yamlInstances, netnsCfg, dataDir)
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}
	inst := parsedCfg.Instances[0]
	if inst.Upstream == nil || !inst.Upstream.Enabled {
		t.Fatal("upstream config not parsed correctly")
	}
	ng := &netnsOverlayGroup{
		NetNSName: "photontesth2",
		Overlays:  []string{"main"},
		Spec:      ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
	}
	routerID := bird.StableRouterID("node-a.catofes.", rootTrustHash(verified.Network), "photontesth2")
	spec := buildBirdInstanceSpecForNetns(inst, routerID, "/tmp", ng, netnsCfg, ars, "node-a.catofes.")

	// Verify the assignment prefix appears in static routes.
	foundAssignment := false
	for _, sr := range spec.StaticRoutes {
		if sr.Prefix == assignmentPrefix {
			foundAssignment = true
			if sr.Via != "phv2host" {
				t.Errorf("static route via = %q, want phv2host", sr.Via)
			}
			if sr.NextHop.String() != "169.254.254.2" {
				t.Errorf("static route next hop = %s, want 169.254.254.2", sr.NextHop)
			}
		}
	}
	if !foundAssignment {
		t.Errorf("assignment prefix %s not found in static routes (%d routes)", assignmentPrefix, len(spec.StaticRoutes))
	}

	// Generate BIRD config and verify the static route is rendered.
	importSet := authorizedPrefixes(ars, nil)
	exportSet := authorizedPrefixes(ars, []zone.ZonePath{"node-a.catofes."})
	cfgBytes, err := bird.DefaultConfigGenerator{}.Generate(spec, importSet, exportSet)
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	cfgStr := string(cfgBytes)

	if !strings.Contains(cfgStr, "protocol static") {
		t.Errorf("BIRD config missing protocol static block\n%s", cfgStr)
	}
	if !strings.Contains(cfgStr, `route 10.42.0.0/24 via 169.254.254.2%'phv2host';`) {
		t.Errorf("BIRD config missing static route for 10.42.0.0/24\n%s", cfgStr)
	}

	// Verify import filter includes the assigned prefix exactly.
	if !strings.Contains(cfgStr, "10.42.0.0/24") {
		t.Errorf("BIRD config missing import filter for 10.42.0.0/24\n%s", cfgStr)
	}
}

func TestExternalUpstreamCanInstallSourceAddressesWithoutStaticRoutes(t *testing.T) {
	verified, checkpoint, runtime, syncConfig := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
	}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{
		ID:           "main",
		NetNS:        "photontesth2",
		Enabled:      boolPtr(true),
		Mode:         ipsec.RoutingModeManaged,
		InterfacePat: "phx*",
		Upstream: &upstreamConfigYAML{
			Enabled:                boolPtr(true),
			Mode:                   upstreamModeExternal,
			CreateVeth:             boolPtr(true),
			InstallSourceAddresses: boolPtr(true),
		},
	}}, appConfig.Netns, appConfig.DataDir)

	rt := &AppContext{
		Config:    appConfig,
		StatePath: filepath.Join(t.TempDir(), "photon.db"),
		Clock:     func() time.Time { return now },
	}
	fakeRM := &fakeUpstreamRouteManager{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, syncConfig, time.Second)
	installTestLinuxDrivers(service, testLinuxDrivers{
		veth: &fakeVethManager{}, upstreamRoutes: fakeRM, birdProcess: &fakeBirdProcessManager{running: false},
		birdClientFactory: func(socketPath string, timeout time.Duration) birdClient { return &fakeBirdClient{} },
	})

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}
	if !fakeRM.ensureCalled {
		t.Fatal("external upstream did not reconcile source addresses")
	}
	if len(fakeRM.ensureSpec.Prefixes) != 0 {
		t.Fatalf("external upstream installed static routes: %+v", fakeRM.ensureSpec.Prefixes)
	}
	if !prefixesContain(fakeRM.ensureSpec.SourcePrefixes, "10.0.0.1/16") {
		t.Fatalf("external source addresses = %+v, want 10.0.0.1/16", fakeRM.ensureSpec.SourcePrefixes)
	}
}

func TestBuildBirdInstanceSpecExternalUpstreamHasNoStaticRoutes(t *testing.T) {
	now := time.Unix(1000, 0)
	verified, _, _, _, signers, _ := buildIPAMRoutingSmokeOwners(t)
	addRouteAssignment(t, verified.Network, "catofes.", "10.42.0.0/24", "node-a.catofes.", true, now, signers["catofes."])
	ars, err := routing.BuildAuthorizedRouteSet(verified.Network, now)
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}

	dataDir := t.TempDir()
	netnsCfg := netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	yamlInstances := []routingInstanceYAML{{
		ID:           "main",
		NetNS:        "photontesth2",
		Enabled:      boolPtr(true),
		Mode:         "managed",
		InterfacePat: "phx*",
		Upstream: &upstreamConfigYAML{
			Enabled: boolPtr(true),
			Mode:    upstreamModeExternal,
			Mesh: upstreamEndpointYAML{
				Interface: "phv2host",
			},
		},
	}}
	parsedCfg, err := parseRoutingConfigInstances(yamlInstances, netnsCfg, dataDir)
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}
	inst := parsedCfg.Instances[0]
	ng := &netnsOverlayGroup{
		NetNSName: "photontesth2",
		Overlays:  []string{"main"},
		Spec:      ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
	}
	routerID := bird.StableRouterID("node-a.catofes.", rootTrustHash(verified.Network), "photontesth2")
	spec := buildBirdInstanceSpecForNetns(inst, routerID, dataDir, ng, netnsCfg, ars, "node-a.catofes.")
	if spec.Upstream == nil {
		t.Fatal("expected upstream interface block")
	}
	if len(spec.StaticRoutes) != 0 {
		t.Fatalf("external upstream static routes = %+v, want none", spec.StaticRoutes)
	}
}

// fakeVethManager is a no-op VethManager for testing.
type fakeVethManager struct {
	ensureCalled bool
	deleteCalled bool
	ensureSpec   bird.VethSpec
}

func (m *fakeVethManager) EnsureVethPair(ctx context.Context, spec bird.VethSpec) error {
	m.ensureCalled = true
	m.ensureSpec = spec
	return nil
}

func (m *fakeVethManager) DeleteVethPair(ctx context.Context, spec bird.VethSpec) error {
	m.deleteCalled = true
	return nil
}

type fakeUpstreamRouteManager struct {
	ensureCalled bool
	ensureSpec   photonlinux.UpstreamRouteSpec
}

func (m *fakeUpstreamRouteManager) EnsureRoutes(ctx context.Context, spec photonlinux.UpstreamRouteSpec) error {
	m.ensureCalled = true
	m.ensureSpec = spec
	return nil
}

func prefixesContain(prefixes []netip.Prefix, want string) bool {
	prefix, err := netip.ParsePrefix(want)
	if err != nil {
		return false
	}
	return slices.Contains(prefixes, prefix)
}
