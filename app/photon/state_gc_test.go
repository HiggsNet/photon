package main

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestStateGCOnlyPlansUnconfiguredBirdInstances(t *testing.T) {
	config := defaultAppConfig()
	config.Routing = routingConfig{Instances: []RoutingInstance{
		{ID: "main", NetNS: "photon", Enabled: true, Mode: ipsec.RoutingModeManaged},
		// Disabled entries remain configured and must not be treated as orphans.
		{ID: "standby", NetNS: "edge", Enabled: false, Mode: ipsec.RoutingModeDisabled},
	}}
	runtime := &linuxRuntimeState{BirdInstances: map[string]*BirdInstanceState{
		"default": {NetNSName: "default"},
		"edge":    {NetNSName: "edge"},
		"photon":  {NetNSName: "photon"},
	}}

	plan := buildStateGCPlan(config, runtime.BirdInstances)
	if len(plan.OrphanBirdInstances) != 1 || plan.OrphanBirdInstances[0] != "default" {
		t.Fatalf("orphan BIRD instances = %#v, want [default]", plan.OrphanBirdInstances)
	}
	if !applyStateGCPlan(runtime, plan) {
		t.Fatal("applyStateGCPlan = false, want true")
	}
	if _, ok := runtime.BirdInstances["default"]; ok {
		t.Fatal("default BIRD state was not removed")
	}
	if len(runtime.BirdInstances) != 2 || runtime.BirdInstances["photon"] == nil || runtime.BirdInstances["edge"] == nil {
		t.Fatalf("remaining BIRD state = %#v", runtime.BirdInstances)
	}
}

func TestStateGCEmptyPlanDoesNotMutateState(t *testing.T) {
	config := defaultAppConfig()
	config.Routing = routingConfig{Instances: []RoutingInstance{{ID: "main", NetNS: "photon", Enabled: true}}}
	runtime := &linuxRuntimeState{BirdInstances: map[string]*BirdInstanceState{"photon": {NetNSName: "photon"}}}

	plan := buildStateGCPlan(config, runtime.BirdInstances)
	if len(plan.OrphanBirdInstances) != 0 {
		t.Fatalf("orphan BIRD instances = %#v, want none", plan.OrphanBirdInstances)
	}
	if applyStateGCPlan(runtime, plan) {
		t.Fatal("applyStateGCPlan = true for empty plan")
	}
}

func TestDirectStateGCOnlyCommitsLinuxRuntime(t *testing.T) {
	verified, checkpoint, runtime, _ := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	trustedRoot, err := rootPublicKey(verified.Network)
	if err != nil {
		t.Fatalf("rootPublicKey: %v", err)
	}
	runtime.BirdInstances = map[string]*BirdInstanceState{
		"default": {NetNSName: "default"},
		"photon":  {NetNSName: "photon"},
	}
	appConfig := defaultAppConfig()
	appConfig.TrustedRootPublicKey = trustedRoot
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{{ID: "main", NetNS: "photon", Enabled: true}}}
	rt := &AppContext{Config: appConfig, StatePath: filepath.Join(t.TempDir(), "photon.db")}
	seedPartitionedStateDB(t, rt.StatePath, verified, checkpoint, runtime)

	plan, err := garbageCollectStateDirect(rt, true)
	if err != nil {
		t.Fatalf("garbageCollectStateDirect: %v", err)
	}
	if len(plan.OrphanBirdInstances) != 1 || plan.OrphanBirdInstances[0] != "default" {
		t.Fatalf("plan = %#v, want default orphan", plan)
	}
	store, startup, err := openLinuxDaemonState(rt)
	if err != nil {
		t.Fatalf("openLinuxDaemonState: %v", err)
	}
	defer store.Close()
	defer startup.Common.Close()
	if startup.Common.VerifiedRevision() != 0 {
		t.Fatalf("Linux GC advanced verified revision to %d", startup.Common.VerifiedRevision())
	}
	if startup.Runtime.BirdInstances["default"] != nil || startup.Runtime.BirdInstances["photon"] == nil {
		t.Fatalf("persisted BIRD runtime = %#v", startup.Runtime.BirdInstances)
	}
}

func TestDaemonStateGCApplyPersistsPlan(t *testing.T) {
	verified, checkpoint, runtime, syncConfig := buildTestDaemonOwners(t)
	runtime.BirdInstances = map[string]*BirdInstanceState{
		"default": {NetNSName: "default"},
		"photon":  {NetNSName: "photon"},
	}
	appConfig := defaultAppConfig()
	appConfig.Routing = routingConfig{Instances: []RoutingInstance{{ID: "main", NetNS: "photon", Enabled: true}}}
	rt := &AppContext{Config: appConfig}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, syncConfig, time.Second)

	preview, err := service.handleStateGCEvent(false)
	if err != nil {
		t.Fatalf("state GC preview: %v", err)
	}
	if len(preview.OrphanBirdInstances) != 1 || preview.OrphanBirdInstances[0] != "default" {
		t.Fatalf("preview = %#v, want default orphan", preview)
	}
	if _, ok := runtime.BirdInstances["default"]; !ok {
		t.Fatal("preview mutated state")
	}

	applied, err := service.handleStateGCEvent(true)
	if err != nil {
		t.Fatalf("state GC apply: %v", err)
	}
	if len(applied.OrphanBirdInstances) != 1 || applied.OrphanBirdInstances[0] != "default" {
		t.Fatalf("applied plan = %#v, want default orphan", applied)
	}
	_, reloaded := service.StateStore.readCommonAndRuntime()
	if _, ok := reloaded.BirdInstances["default"]; ok {
		t.Fatalf("stale default BIRD state remained: %#v", reloaded.BirdInstances)
	}
	if reloaded.BirdInstances["photon"] == nil {
		t.Fatalf("configured photon BIRD state was removed: %#v", reloaded.BirdInstances)
	}
}
