package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestReconcileRoutingAppliesAuthorizedRoutesToBird(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = photonlinux.NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = photonlinux.ParseRoutingConfig([]photonlinux.RoutingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &testApp{Config: appConfig, Clock: func() time.Time { return now }}

	pm := &fakeBirdProcessManager{running: false}
	client := &fakeBirdClient{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, pm, func(socketPath string, timeout time.Duration) birdClient {
		return client
	})

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	latest := service.linuxObservation.routingSnapshot()
	if len(latest.Instances) != 1 {
		t.Fatalf("BirdInstances len = %d, want 1", len(latest.Instances))
	}
	inst := latest.Instances["photontesth2"]
	if inst == nil {
		t.Fatalf("missing bird instance state for netns photontesth2")
	}
	if inst.ConfigPath == "" {
		t.Fatalf("ConfigPath is empty")
	}
	if inst.LastConfigHash == "" {
		t.Fatalf("LastConfigHash is empty")
	}
	if inst.State != birdInstanceStateRunning {
		t.Fatalf("State = %q, want running", inst.State)
	}
	if !pm.started {
		t.Fatalf("BIRD process manager Start was not called")
	}

	cfg, err := readFileString(inst.ConfigPath)
	if err != nil {
		t.Fatalf("read generated config: %v", err)
	}

	// Import filter should contain the IPAM assignment prefixes (authorized route
	// space) for both local and remote zones.
	if !strings.Contains(cfg, "10.0.0.0/16") {
		t.Errorf("import filter missing local assignment prefix 10.0.0.0/16")
	}
	if !strings.Contains(cfg, "10.1.0.0/24") {
		t.Errorf("import filter missing remote route prefix 10.1.0.0/24")
	}

	// Export filter should contain only the local prefix.
	found := strings.Contains(cfg, "filter photon_import_photontesth2")
	exportIdx := strings.Index(cfg, "filter photon_export_photontesth2")
	if !found || exportIdx == -1 {
		t.Fatalf("missing import/export filters")
	}
	exportFilter := cfg[exportIdx:]
	if !strings.Contains(exportFilter, "10.0.0.0/24") {
		t.Errorf("export filter missing local prefix 10.0.0.0/24")
	}
	if strings.Contains(exportFilter, "10.1.0.0/24") {
		t.Errorf("export filter should not contain remote prefix 10.1.0.0/24")
	}

	// BIRD process should have been started with the generated config path.
	if pm.startSpec.ConfigPath != inst.ConfigPath {
		t.Errorf("Start config path = %q, want %q", pm.startSpec.ConfigPath, inst.ConfigPath)
	}
}

func TestReconcileRoutingConfigChangeUsesFullBirdConfigure(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = photonlinux.NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = photonlinux.ParseRoutingConfig([]photonlinux.RoutingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &testApp{Config: appConfig, Clock: func() time.Time { return now }}

	pm := &fakeBirdProcessManager{running: true}
	client := &fakeBirdClient{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, pm, func(socketPath string, timeout time.Duration) birdClient {
		return client
	})

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}
	if pm.started {
		t.Fatalf("running managed BIRD should be reconfigured, not restarted")
	}
	if client.configureCalls != 1 {
		t.Fatalf("Configure calls = %d, want 1", client.configureCalls)
	}
	if client.configurePath == "" {
		t.Fatalf("Configure path is empty")
	}
}

func TestReconcileRoutingForceReloadUsesFullBirdConfigureWhenHashUnchanged(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = photonlinux.NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = photonlinux.ParseRoutingConfig([]photonlinux.RoutingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &testApp{Config: appConfig, Clock: func() time.Time { return now }}

	pm := &fakeBirdProcessManager{running: false}
	client := &fakeBirdClient{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, pm, func(socketPath string, timeout time.Duration) birdClient {
		return client
	})
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("initial reconcileRouting: %v", err)
	}

	pm.running = true
	pm.started = false
	client.configureCalls = 0
	service.routingForceReload = true
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("force reconcileRouting: %v", err)
	}
	if pm.started {
		t.Fatalf("force reload should reconfigure running BIRD, not restart it")
	}
	if client.configureCalls != 1 {
		t.Fatalf("Configure calls = %d, want 1", client.configureCalls)
	}

	// A failed forced reload must remain pending even though its configuration
	// hash matched the last successful apply. Periodic reconciles must retry it.
	failure := errors.New("dial unix /tmp/bird.sock: connect: connection refused")
	client.configureErr = failure
	service.routingForceReload = true
	for attempt := 0; attempt < 2; attempt++ {
		if err := service.reconcileRouting(context.Background()); !errors.Is(err, failure) {
			t.Fatalf("failed reload %d: %v", attempt, err)
		}
		inst := service.linuxObservation.routingSnapshot().Instances["photontesth2"]
		if inst.State != birdInstanceStateDegraded || !errors.Is(inst.LastFailure, failure) || inst.LastConfigHash != "" {
			t.Fatalf("failed reload observation: %+v", inst)
		}
	}
	client.configureErr = nil
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("recovered reload: %v", err)
	}
	inst := service.linuxObservation.routingSnapshot().Instances["photontesth2"]
	if client.configureCalls != 4 || inst.State != birdInstanceStateRunning || inst.LastFailure != nil || inst.LastConfigHash == "" {
		t.Fatalf("reload recovery: calls=%d observation=%+v", client.configureCalls, inst)
	}
	// Start may adopt an existing process and fail its reload. Its failed
	// forced apply must also be retried after the process becomes observable.
	pm.running, pm.startErr = false, failure
	service.routingForceReload = true
	if err := service.reconcileRouting(context.Background()); !errors.Is(err, failure) {
		t.Fatalf("failed adoption reload: %v", err)
	}
	pm.running, pm.startErr = true, nil
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("retry adopted process: %v", err)
	}
	if client.configureCalls != 5 {
		t.Fatalf("adoption failure was not retried: configure calls=%d", client.configureCalls)
	}
}

func TestReconcileRoutingReportsBackendFailures(t *testing.T) {
	for _, mode := range []string{ipsec.RoutingModeManaged, ipsec.RoutingModeExternal} {
		t.Run(mode, func(t *testing.T) {
			fixture := newRoutingDisabledFixture(t, true, mode, false)
			failure := errors.New("bird binary not found")
			var client birdClient = &fakeBirdClient{}
			if mode == ipsec.RoutingModeManaged {
				fixture.disabledBird.startErr = failure
			} else {
				failure = os.ErrNotExist
				client = bird.NewClient(filepath.Join(t.TempDir(), "missing.sock"), time.Second)
			}
			installTestLinuxDrivers(fixture.service, testLinuxDrivers{
				veth: fixture.veth, upstreamRoutes: fixture.routes,
				birdProcesses:     map[string]bird.ProcessManager{"photontest-disabled": fixture.disabledBird},
				birdClientFactory: func(string, time.Duration) birdClient { return client },
			})
			if err := fixture.service.reconcileRouting(context.Background()); !errors.Is(err, failure) {
				t.Fatalf("backend failure: %v", err)
			}
			inst := fixture.service.linuxObservation.routingSnapshot().Instances["photontest-disabled"]
			if inst.State != birdInstanceStateError || !errors.Is(inst.LastFailure, failure) || inst.LastConfigHash != "" {
				t.Fatalf("failure observation: %+v", inst)
			}
		})
	}
}

func TestReconcileRoutingExternalModeOnlyStatus(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = photonlinux.NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = photonlinux.ParseRoutingConfig([]photonlinux.RoutingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeExternal}}, appConfig.Netns, appConfig.DataDir)

	rt := &testApp{Config: appConfig, Clock: func() time.Time { return now }}

	client := &fakeBirdClient{}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, nil, func(socketPath string, timeout time.Duration) birdClient {
		return client
	})

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	if !client.statusCalled {
		t.Fatalf("external mode should call client.Status")
	}

	latest := service.linuxObservation.routingSnapshot()
	inst := latest.Instances["photontesth2"]
	if inst == nil || inst.State != birdInstanceStateRunning {
		t.Fatalf("external instance state = %+v, want running", inst)
	}
}

func TestReconcileRoutingSkipsWhenDisabled(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}

	rt := &testApp{Config: appConfig, Clock: func() time.Time { return now }}

	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	if latest := service.linuxObservation.routingSnapshot(); latest != nil {
		t.Fatalf("routing observation = %+v, want nil when routing is disabled", latest)
	}
}

func TestRoutingReconcileInterval(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.Routing = photonlinux.RoutingConfig{Instances: []photonlinux.RoutingInstance{
		{ID: "a", Enabled: true,
			Bird: bird.BirdInstanceSpec{
				NetNSName: "photontesth2",
				Mode:      bird.BirdMode(ipsec.RoutingModeManaged),
			}},
	}}
	service := newTestDaemonFromOwners(
		&testApp{Config: appConfig}, nil, nil, &photonlinux.LinuxState{}, appConfig, time.Second,
	)
	if got := service.routingReconcileInterval(); got != 30*time.Second {
		t.Fatalf("routingReconcileInterval = %s, want 30s", got)
	}
}

func TestRoutingReconcileIntervalZeroWhenDisabled(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.Routing = photonlinux.RoutingConfig{Instances: []photonlinux.RoutingInstance{
		{ID: "a", Enabled: false,
			Bird: bird.BirdInstanceSpec{
				NetNSName: "photontesth2",
				Mode:      bird.BirdMode(ipsec.RoutingModeManaged),
			}},
	}}
	service := newTestDaemonFromOwners(
		&testApp{Config: appConfig}, nil, nil, &photonlinux.LinuxState{}, appConfig, time.Second,
	)
	if got := service.routingReconcileInterval(); got != 0 {
		t.Fatalf("routingReconcileInterval = %s, want 0", got)
	}
}
