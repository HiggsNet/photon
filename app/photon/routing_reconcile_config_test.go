package main

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestReconcileRoutingGeneratesConfig(t *testing.T) {
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
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

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
	if !strings.Contains(cfg, `interface "phx*" {`) {
		t.Errorf("babel interface should use configured XFRM interface pattern:\n%s", cfg)
	}
	for _, want := range []string{
		"rtt cost 1024;", "rtt min 10 ms;", "rtt max 500 ms;", "rtt decay 12;",
		"hello interval 4 s;", "update interval 16 s;",
	} {
		if !strings.Contains(cfg, want) {
			t.Errorf("generated Babel config missing %q:\n%s", want, cfg)
		}
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
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return now },
	}

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
	if client.configureSoftCalls != 0 {
		t.Fatalf("ConfigureSoft calls = %d, want 0", client.configureSoftCalls)
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
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

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
		t.Fatalf("initial reconcileRouting: %v", err)
	}

	pm.running = true
	pm.started = false
	client.configureCalls = 0
	client.configureSoftCalls = 0
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
	if client.configureSoftCalls != 0 {
		t.Fatalf("ConfigureSoft calls = %d, want 0", client.configureSoftCalls)
	}
}

func TestReconcileRoutingStaleRevisionDoesNotCommitBirdInstance(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
	now := time.Unix(4010, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return now },
	}

	pm := &blockingBirdProcessManager{
		startedCh: make(chan struct{}),
		unblock:   make(chan struct{}),
	}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, pm, func(socketPath string, timeout time.Duration) birdClient {
		return &fakeBirdClient{}
	})
	var logs strings.Builder
	service.Log = &appLogger{level: logLevelDebug, out: &logs, now: func() time.Time { return now }}

	initialRev := service.StateStore.Meta().Revision
	done := make(chan error, 1)
	go func() {
		done <- service.reconcileRouting(context.Background())
	}()
	select {
	case <-pm.startedCh:
	case <-time.After(time.Second):
		close(pm.unblock)
		t.Fatal("routing reconcile did not enter blocking BIRD start")
	}

	newerRev, err := advanceTestVerifiedRevision(service.StateStore, now.Add(time.Nanosecond))
	if err != nil {
		close(pm.unblock)
		t.Fatalf("advance state revision during routing apply: %v", err)
	}
	if newerRev != initialRev+1 {
		close(pm.unblock)
		t.Fatalf("newer revision = %d, want %d", newerRev, initialRev+1)
	}
	close(pm.unblock)
	if err := <-done; err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}
	if !service.routingDirty {
		t.Fatal("routingDirty = false, want stale reconcile to be retried")
	}
	meta := service.StateStore.Meta()
	if meta.Revision != newerRev {
		t.Fatalf("stale reconcile advanced revision: got %d want %d", meta.Revision, newerRev)
	}
	if !meta.Dirty.Routing {
		t.Fatal("state store routing dirty flag = false, want retry visible to readers")
	}
	_, currentRuntime := service.StateStore.readCommonAndRuntime()
	if len(currentRuntime.BirdInstances) != 0 {
		t.Fatalf("bird instances = %+v, want stale result discarded", currentRuntime.BirdInstances)
	}
	if currentRuntime.RoutingReconcile != nil {
		t.Fatalf("routing reconcile = %+v, want stale summary discarded", currentRuntime.RoutingReconcile)
	}
	logOutput := logs.String()
	if !strings.Contains(logOutput, "event=stale_reconcile_result") ||
		!strings.Contains(logOutput, "source_revision="+fmt.Sprint(initialRev)) ||
		!strings.Contains(logOutput, "current_revision="+fmt.Sprint(newerRev)) {
		t.Fatalf("stale reconcile log lacks revision diagnostics: %s", logOutput)
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
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeExternal}}, appConfig.Netns, appConfig.DataDir)

	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return now },
	}

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

	_, latest := service.StateStore.readCommonAndRuntime()
	inst := latest.BirdInstances["photontesth2"]
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

	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return now },
	}

	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}

	_, latest := service.StateStore.readCommonAndRuntime()
	if len(latest.BirdInstances) != 0 {
		t.Fatalf("BirdInstances len = %d, want 0", len(latest.BirdInstances))
	}
}

func TestRoutingReconcileInterval(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{
		{ID: "a", NetNS: "photontesth2", Enabled: true, Mode: ipsec.RoutingModeManaged},
	}}
	service := newTestDaemonFromOwners(
		&AppContext{Config: appConfig}, nil, nil, &linuxRuntimeState{}, &gossipStartupConfig{}, time.Second,
	)
	if got := service.routingReconcileInterval(); got != 30*time.Second {
		t.Fatalf("routingReconcileInterval = %s, want 30s", got)
	}
}

func TestRoutingReconcileIntervalZeroWhenDisabled(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{
		{ID: "a", NetNS: "photontesth2", Enabled: false, Mode: ipsec.RoutingModeManaged},
	}}
	service := newTestDaemonFromOwners(
		&AppContext{Config: appConfig}, nil, nil, &linuxRuntimeState{}, &gossipStartupConfig{}, time.Second,
	)
	if got := service.routingReconcileInterval(); got != 0 {
		t.Fatalf("routingReconcileInterval = %s, want 0", got)
	}
}
