package main

import (
	"path/filepath"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestRecoveryChainZonesRootToLeaf(t *testing.T) {
	got := recoveryChainZones("node-b.pek.catofes.")
	want := []zone.ZonePath{zone.RootZone, "catofes.", "pek.catofes.", "node-b.pek.catofes."}
	if len(got) != len(want) {
		t.Fatalf("chain len = %d, want %d: %#v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("chain[%d] = %s, want %s; chain=%#v", i, got[i], want[i], got)
		}
	}
}

func TestRecoveryImportNoopDoesNotCommitOrNotify(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	now := time.Unix(1000, 0)
	snapshot, err := corestate.Snapshot(verified.Network, "node-b.catofes.")
	if err != nil {
		t.Fatalf("Snapshot(node-b): %v", err)
	}

	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig(), Clock: func() time.Time { return now }},
		verified, checkpoint, runtime, config, defaultDaemonInterval,
	)
	if _, _, err := service.handleRecoveryImportZoneEvent(snapshot); err != nil {
		t.Fatalf("handleRecoveryImportZoneEvent(first): %v", err)
	}
	notifications := 0
	service.Hooks.OnStateChanged = func() { notifications++ }
	beforeRevision := uint64(service.State.Common.VerifiedRevision())
	result, _, err := service.handleRecoveryImportZoneEvent(snapshot)
	if err != nil {
		t.Fatalf("handleRecoveryImportZoneEvent(no-op): %v", err)
	}
	if result.NetworkChanged {
		t.Fatalf("identical recovery snapshot result = %+v, want no network change", result)
	}
	if revision := uint64(service.State.Common.VerifiedRevision()); revision != beforeRevision {
		t.Fatalf("no-op recovery revision = %d, want unchanged %d", revision, beforeRevision)
	}
	if notifications != 0 {
		t.Fatalf("no-op recovery emitted %d state-change notifications", notifications)
	}
}

func TestRecoveryExportImportOfflineRootIPAMRecords(t *testing.T) {
	dir := t.TempDir()
	adminConfig := filepath.Join(dir, "admin.yaml")
	catofesConfig := filepath.Join(dir, "catofes.yaml")
	catofesKeyPath := filepath.Join(dir, "catofes.key.json")
	catofesRequestPath := filepath.Join(dir, "catofes.request.b64")
	catofesBundlePath := filepath.Join(dir, "catofes.bundle.b64")
	rootSnapshotPath := filepath.Join(dir, "root.snapshot.b64")

	writeConfig(t, adminConfig, filepath.Join(dir, "admin"))
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := runRootInit(); err != nil {
		t.Fatalf("runRootInit(admin): %v", err)
	}

	writeConfig(t, catofesConfig, filepath.Join(dir, "catofes"))
	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := keygen(catofesKeyPath); err != nil {
		t.Fatalf("keygen(catofes): %v", err)
	}
	if err := createJoinRequest("catofes.", catofesKeyPath, catofesRequestPath); err != nil {
		t.Fatalf("createJoinRequest(catofes): %v", err)
	}
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := issueDelegation(catofesRequestPath, catofesBundlePath, nil, true); err != nil {
		t.Fatalf("issueDelegation(catofes): %v", err)
	}
	if err := createIPAMPool(".", "2a0d:2905::/32", ".", true); err != nil {
		t.Fatalf("createIPAMPool(root): %v", err)
	}
	if err := recoveryExportZone(zone.RootZone, rootSnapshotPath); err != nil {
		t.Fatalf("recoveryExportZone(root): %v", err)
	}

	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := acceptJoinBundle(catofesBundlePath, catofesKeyPath, true); err != nil {
		t.Fatalf("acceptJoinBundle(catofes): %v", err)
	}
	if err := recoveryImportZone(rootSnapshotPath, true); err != nil {
		t.Fatalf("recoveryImportZone(root): %v", err)
	}
	rt, err := NewAppContext()
	if err != nil {
		t.Fatalf("NewAppContext(catofes): %v", err)
	}
	state, err := openState(rt)
	if err != nil {
		t.Fatalf("openState(catofes): %v", err)
	}
	defer state.Close()
	view := state.Common.ReadView()
	key, err := routing.NormalizeIPAMPoolKey("2a0d:2905::/32")
	if err != nil {
		t.Fatalf("NormalizeIPAMPoolKey: %v", err)
	}
	if view.State == nil || view.State.Network.Zones[zone.RootZone].Records[key] == nil {
		t.Fatalf("imported root snapshot missing IPAM pool record %s", key)
	}
}

func TestRecoveryImportZoneEventAppliesToDaemonState(t *testing.T) {
	dir := t.TempDir()
	adminConfig := filepath.Join(dir, "admin.yaml")
	catofesConfig := filepath.Join(dir, "catofes.yaml")
	catofesKeyPath := filepath.Join(dir, "catofes.key.json")
	catofesRequestPath := filepath.Join(dir, "catofes.request.b64")
	catofesBundlePath := filepath.Join(dir, "catofes.bundle.b64")

	writeConfig(t, adminConfig, filepath.Join(dir, "admin"))
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := runRootInit(); err != nil {
		t.Fatalf("runRootInit(admin): %v", err)
	}

	writeConfig(t, catofesConfig, filepath.Join(dir, "catofes"))
	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := keygen(catofesKeyPath); err != nil {
		t.Fatalf("keygen(catofes): %v", err)
	}
	if err := createJoinRequest("catofes.", catofesKeyPath, catofesRequestPath); err != nil {
		t.Fatalf("createJoinRequest(catofes): %v", err)
	}
	t.Setenv("PHOTON_CONFIG", adminConfig)
	if err := issueDelegation(catofesRequestPath, catofesBundlePath, nil, true); err != nil {
		t.Fatalf("issueDelegation(catofes): %v", err)
	}
	if err := createIPAMPool(".", "2a0d:2905::/32", ".", true); err != nil {
		t.Fatalf("createIPAMPool(root): %v", err)
	}
	adminState, err := loadConfiguredVerifiedState()
	if err != nil {
		t.Fatalf("loadState(admin): %v", err)
	}
	snapshot, err := corestate.Snapshot(adminState.Network, zone.RootZone)
	if err != nil {
		t.Fatalf("Snapshot(root): %v", err)
	}

	t.Setenv("PHOTON_CONFIG", catofesConfig)
	if err := acceptJoinBundle(catofesBundlePath, catofesKeyPath, true); err != nil {
		t.Fatalf("acceptJoinBundle(catofes): %v", err)
	}
	rt, err := NewAppContext()
	if err != nil {
		t.Fatalf("NewAppContext(catofes): %v", err)
	}
	state, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(catofes): %v", err)
	}
	service := newTestDaemonFromOwners(rt, state.State, state.Gossip, runtime, rt.Config, time.Second)

	result, _, _ := service.handleEvent(daemonEvent{
		Type:     daemonEventRecoveryImportZone,
		Snapshot: snapshot,
	})
	if result.Error != nil {
		t.Fatalf("handle recovery import event: %v", result.Error)
	}

	reloaded := service.State.Common.ReadView()
	key, err := routing.NormalizeIPAMPoolKey("2a0d:2905::/32")
	if err != nil {
		t.Fatalf("NormalizeIPAMPoolKey: %v", err)
	}
	if reloaded.State.Network.Zones[zone.RootZone].Records[key] == nil {
		t.Fatalf("daemon import missing IPAM pool record %s", key)
	}
}
