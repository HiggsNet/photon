package main

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type blockingBirdProcessManager struct {
	started   bool
	startSpec bird.BirdInstanceSpec
	startedCh chan struct{}
	unblock   chan struct{}
	startErr  error
}

func (f *blockingBirdProcessManager) Start(ctx context.Context, spec bird.BirdInstanceSpec) error {
	f.started = true
	f.startSpec = spec
	close(f.startedCh)
	select {
	case <-f.unblock:
	case <-ctx.Done():
		return ctx.Err()
	}
	return f.startErr
}

func (f *blockingBirdProcessManager) Stop(ctx context.Context, spec bird.BirdInstanceSpec) error {
	return nil
}

func (f *blockingBirdProcessManager) IsRunning(ctx context.Context) bool {
	return false
}

func (f *blockingBirdProcessManager) LastExit() *bird.ProcessExit {
	return nil
}

func TestReconcileRoutingBacksOffAfterManagedBirdCrash(t *testing.T) {
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

	pm := &fakeBirdProcessManager{running: false, lastExit: &bird.ProcessExit{PID: 1234, Failure: errors.New("signal: killed")}}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, pm, func(socketPath string, timeout time.Duration) birdClient {
		return &fakeBirdClient{}
	})

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}
	if pm.started {
		t.Fatalf("managed BIRD should not restart while crash backoff is active")
	}
	latest := service.linuxObservation.routingSnapshot()
	inst := latest.Instances["photontesth2"]
	if inst == nil {
		t.Fatalf("missing bird instance state")
	}
	if inst.State != birdInstanceStateDegraded {
		t.Fatalf("State = %q, want degraded", inst.State)
	}
	if inst.FailureCount != 1 {
		t.Fatalf("FailureCount = %d, want 1", inst.FailureCount)
	}
	if inst.BackoffUntilUnix != now.Add(time.Second).Unix() {
		t.Fatalf("BackoffUntilUnix = %d, want %d", inst.BackoffUntilUnix, now.Add(time.Second).Unix())
	}
	if !strings.Contains(inst.LastExit, "pid 1234") {
		t.Fatalf("LastExit = %q, want pid detail", inst.LastExit)
	}
	if inst.Owner.ControlSocketToken == "" || inst.Owner.PIDFileToken == "" || inst.Owner.RouteTableToken == "" || inst.Owner.RuleToken == "" {
		t.Fatalf("owner tokens are incomplete: %+v", inst.Owner)
	}
}

func TestReconcileRoutingRestartsManagedBirdAfterCrashBackoff(t *testing.T) {
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
	initialBird := map[string]*bird.InstanceObservation{
		"photontesth2": {
			NetNSName:        "photontesth2",
			State:            birdInstanceStateDegraded,
			FailureCount:     1,
			BackoffUntilUnix: now.Add(-time.Second).Unix(),
			LastFailure:      errors.New("bird restart backoff active"),
			LastExit:         "pid 1234: signal: killed",
		},
	}

	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return now },
	}

	pm := &fakeBirdProcessManager{running: false}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	service.linuxObservation.replaceRouting(&routingObservation{Instances: initialBird})
	installTestBirdDrivers(service, pm, func(socketPath string, timeout time.Duration) birdClient {
		return &fakeBirdClient{}
	})

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}
	if !pm.started {
		t.Fatalf("managed BIRD should restart after crash backoff expires")
	}
	if pm.startSpec.Owner.RouteTableToken == "" || pm.startSpec.Owner.RuleToken == "" {
		t.Fatalf("start spec owner tokens are incomplete: %+v", pm.startSpec.Owner)
	}
	latest := service.linuxObservation.routingSnapshot()
	inst := latest.Instances["photontesth2"]
	if inst == nil || inst.State != birdInstanceStateRunning {
		t.Fatalf("bird instance = %+v, want running", inst)
	}
	if inst.FailureCount != 0 || inst.BackoffUntilUnix != 0 || inst.LastExit != "" {
		t.Fatalf("restart did not clear crash state: %+v", inst)
	}
}

func TestReconcileRoutingClearsStaleBackoffForRunningBird(t *testing.T) {
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
	installTestBirdDrivers(service, pm, func(socketPath string, timeout time.Duration) birdClient { return client })
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("initial reconcileRouting: %v", err)
	}

	observed := service.linuxObservation.routingSnapshot()
	inst := observed.Instances["photontesth2"]
	inst.State = birdInstanceStateDegraded
	inst.LastFailure = errors.New("bird restart backoff active until 1970-01-01T01:06:41Z")
	inst.FailureCount = 1
	inst.BackoffUntilUnix = now.Add(-time.Second).Unix()
	inst.LastExit = "pid 1234: signal: killed"
	service.linuxObservation.replaceRouting(observed)
	pm.running = true
	pm.started = false
	client.configureCalls = 0

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}
	latest := service.linuxObservation.routingSnapshot()
	inst = latest.Instances["photontesth2"]
	if inst == nil || inst.State != birdInstanceStateRunning || inst.LastFailure != nil {
		t.Fatalf("bird instance = %+v, want running with no error", inst)
	}
	if inst.FailureCount != 0 || inst.BackoffUntilUnix != 0 || inst.LastExit != "" {
		t.Fatalf("stale crash state was not cleared: %+v", inst)
	}
	if pm.started || client.configureCalls != 0 {
		t.Fatalf("healthy unchanged BIRD should not restart/reconfigure: started=%v configure=%d", pm.started, client.configureCalls)
	}
}

func TestLongBirdReconcileDoesNotBlockCommittedReaders(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
	now := time.Unix(4050, 0)

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

	committedRev := uint64(service.State.Common.VerifiedRevision())
	statusDone := make(chan controlViewResponse[inspect.DaemonStatusView], 1)
	go func() {
		statusDone <- controlViewRequestViaPipe[inspect.DaemonStatusView](t, service, controlRequest{Method: "daemon_status_view"})
	}()
	select {
	case status := <-statusDone:
		if !status.OK || status.View.StateRevision != committedRev {
			close(pm.unblock)
			t.Fatalf("status response = %#v, want committed revision %d", status, committedRev)
		}
	case <-time.After(time.Second):
		close(pm.unblock)
		t.Fatal("control status blocked behind BIRD start")
	}

	linksDone := make(chan controlViewResponse[inspect.LinksDebugView], 1)
	go func() {
		linksDone <- controlViewRequestViaPipe[inspect.LinksDebugView](t, service, controlRequest{Method: "links_view"})
	}()
	select {
	case links := <-linksDone:
		if !links.OK {
			close(pm.unblock)
			t.Fatalf("links_view response = %#v", links)
		}
	case <-time.After(time.Second):
		close(pm.unblock)
		t.Fatal("links_view blocked behind BIRD start")
	}

	close(pm.unblock)
	if err := <-done; err != nil {
		t.Fatalf("reconcileRouting: %v", err)
	}
}

func TestStopManagedBirdInstancesHonorsShutdownPolicy(t *testing.T) {
	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{
		"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		"photontesth3": {Kind: ipsec.NetNSName, Name: "photontesth3", Create: true},
		"photontesth4": {Kind: ipsec.NetNSName, Name: "photontesth4", Create: true},
	}}
	var err error
	appConfig.Routing, err = parseRoutingConfigInstances([]routingInstanceYAML{
		{ID: "managed-persist", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged},
		{ID: "external", NetNS: "photontesth3", Enabled: boolPtr(true), Mode: ipsec.RoutingModeExternal},
		{ID: "managed-stop", NetNS: "photontesth4", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged, ShutdownPolicy: routingShutdownPolicyStop},
	}, appConfig.Netns, appConfig.DataDir)
	if err != nil {
		t.Fatalf("parseRoutingConfigInstances: %v", err)
	}

	persistPM := &fakeBirdProcessManager{running: true}
	externalPM := &fakeBirdProcessManager{running: true}
	stopPM := &fakeBirdProcessManager{running: true}
	service := newTestDaemonFromOwners(
		&AppContext{Config: appConfig}, nil, nil, &photonlinux.LinuxState{}, appConfig, time.Second,
	)
	installTestLinuxDrivers(service, testLinuxDrivers{birdProcesses: map[string]bird.ProcessManager{
		"photontesth2": persistPM,
		"photontesth3": externalPM,
		"photontesth4": stopPM,
	}})

	if err := service.stopManagedBirdInstances(context.Background(), false); err != nil {
		t.Fatalf("stopManagedBirdInstances: %v", err)
	}
	if persistPM.stopped {
		t.Fatalf("default managed BIRD should persist across daemon shutdown")
	}
	if externalPM.stopped {
		t.Fatalf("external BIRD process manager should not be stopped")
	}
	if !stopPM.stopped {
		t.Fatalf("managed BIRD with shutdown_policy=stop was not stopped")
	}
	if stopPM.stopSpec.NetNSName != "photontesth4" {
		t.Fatalf("Stop netns = %q, want photontesth4", stopPM.stopSpec.NetNSName)
	}
	if stopPM.stopSpec.ControlSocketPath == "" || stopPM.stopSpec.PIDFilePath == "" || stopPM.stopSpec.ConfigPath == "" {
		t.Fatalf("Stop spec paths must be populated: %+v", stopPM.stopSpec)
	}

	persistPM.stopped = false
	stopPM.stopped = false
	if err := service.stopManagedBirdInstances(context.Background(), true); err != nil {
		t.Fatalf("force stopManagedBirdInstances: %v", err)
	}
	if !persistPM.stopped || !stopPM.stopped {
		t.Fatalf("force stop should stop all managed instances: persist=%v stop=%v", persistPM.stopped, stopPM.stopped)
	}
}

func TestFlushRoutingReconcileCoalesces(t *testing.T) {
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
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	installTestBirdDrivers(service, pm, nil)

	if service.flushRoutingReconcile(context.Background()) {
		t.Fatalf("flushRoutingReconcile should return false when not dirty")
	}

	service.routingDirty = true
	if !service.flushRoutingReconcile(context.Background()) {
		t.Fatalf("flushRoutingReconcile should return true when dirty")
	}

	if service.routingDirty {
		t.Fatalf("routingDirty should be cleared after flush")
	}

	latest := service.linuxObservation.routingSnapshot()
	if len(latest.Instances) != 1 {
		t.Fatalf("BirdInstances len = %d, want 1", len(latest.Instances))
	}

	beforeNoopRev := uint64(service.State.Common.VerifiedRevision())
	now = now.Add(defaultRoutingReconcileInterval)
	service.routingDirty = true
	if !service.flushRoutingReconcile(context.Background()) {
		t.Fatal("second routing reconcile was not flushed")
	}
	if afterNoopRev := uint64(service.State.Common.VerifiedRevision()); afterNoopRev != beforeNoopRev {
		t.Fatalf("no-op routing reconcile advanced revision: before=%d after=%d", beforeNoopRev, afterNoopRev)
	}
	if observation := service.linuxObservation.routingSnapshot(); observation == nil || observation.LastRunUnix != now.Unix() {
		t.Fatalf("runtime routing observation = %+v, want last run %d", observation, now.Unix())
	}
}

func TestRoutingObservationDoesNotAdvancePersistentRevision(t *testing.T) {
	verified := &corestate.VerifiedState{}
	runtime := &photonlinux.LinuxState{}
	service := &Daemon{State: newState(nil, corestate.NewStore(verified, nil), runtime)}
	common := service.State.Common.ReadView()
	rev := uint64(common.Revision)
	observation := &routingObservation{
		Instances: map[string]*bird.InstanceObservation{
			"mesh": {NetNSName: "mesh", Overlays: []string{"main"}, State: birdInstanceStateRunning},
		},
		LastRunUnix: 20,
	}
	service.publishRoutingObservation(rev, observation)
	observation.Instances["mesh"].State = birdInstanceStateError
	observation.Instances["mesh"].Overlays[0] = "changed"
	if got := uint64(service.State.Common.VerifiedRevision()); got != rev {
		t.Fatalf("routing observation advanced revision: got %d want %d", got, rev)
	}
	got := service.linuxObservation.routingSnapshot()
	if got == nil || got.LastRunUnix != 20 || got.Instances["mesh"] == nil || got.Instances["mesh"].State != birdInstanceStateRunning || got.Instances["mesh"].Overlays[0] != "main" {
		t.Fatalf("routing observation = %+v", got)
	}
	got.Instances["mesh"].State = birdInstanceStateError
	if latest := service.linuxObservation.routingSnapshot(); latest.Instances["mesh"].State != birdInstanceStateRunning {
		t.Fatalf("routing snapshot shares mutable instance: %+v", latest)
	}
}
