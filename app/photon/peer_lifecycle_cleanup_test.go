package main

import (
	"context"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestApplyPeerLifecycleCleanupDeletesOfflineCacheAndKeepsSuppression(t *testing.T) {
	state, _, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(200_000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig()
	state.checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{
		LastSyncUnix: now.Add(-cfg.CleanupAfter - time.Minute).Unix(),
	}

	removed, changed := applyPeerLifecycleCleanup(state.verified.Network, state.checkpoint.Peers, state.runtime.PeerCleanups, now, cfg)
	if !changed || len(removed) != 1 || removed[0] != "node-b.catofes." {
		t.Fatalf("cleanup = changed:%t removed:%v", changed, removed)
	}
	if _, ok := state.checkpoint.Peers["node-b.catofes."]; ok {
		t.Fatal("offline SyncPeers cache entry was retained")
	}
	cleanup, ok := state.runtime.PeerCleanups["node-b.catofes."]
	if !ok || cleanup.Reason != peerCleanupReasonOffline {
		t.Fatalf("cleanup marker = %+v present=%t", cleanup, ok)
	}
	if got := peerLifecycleExcludedPeers(state.runtime.PeerCleanups, state.checkpoint, now, cfg)["node-b.catofes."]; got != peerCleanupReasonOffline {
		t.Fatalf("excluded reason = %q", got)
	}
}

func TestApplyPeerLifecycleCleanupRetainsThenDeletesRevokedCache(t *testing.T) {
	state, parentKey, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(300_000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig()
	state.checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{LastSyncUnix: now.Unix()}
	addRevocationToParent(t, state.verified.Network, "catofes.", "node-b.catofes.", parentKey, now)

	removed, changed := applyPeerLifecycleCleanup(state.verified.Network, state.checkpoint.Peers, state.runtime.PeerCleanups, now, cfg)
	if !changed || len(removed) != 0 {
		t.Fatalf("initial cleanup = changed:%t removed:%v", changed, removed)
	}
	if _, ok := state.checkpoint.Peers["node-b.catofes."]; !ok {
		t.Fatal("revoked diagnostic entry was removed before retention elapsed")
	}
	marker := state.runtime.PeerCleanups["node-b.catofes."]
	if marker.Reason != peerCleanupReasonRevoked || marker.CleanupUnix != now.Unix() {
		t.Fatalf("revoked cleanup marker = %+v", marker)
	}

	removed, changed = applyPeerLifecycleCleanup(state.verified.Network, state.checkpoint.Peers, state.runtime.PeerCleanups, now.Add(cfg.CleanupAfter-time.Second), cfg)
	if changed || len(removed) != 0 {
		t.Fatalf("early cleanup = changed:%t removed:%v", changed, removed)
	}
	removed, changed = applyPeerLifecycleCleanup(state.verified.Network, state.checkpoint.Peers, state.runtime.PeerCleanups, now.Add(cfg.CleanupAfter), cfg)
	if !changed || len(removed) != 1 || removed[0] != "node-b.catofes." {
		t.Fatalf("expired cleanup = changed:%t removed:%v", changed, removed)
	}
	if _, ok := state.checkpoint.Peers["node-b.catofes."]; ok {
		t.Fatal("revoked SyncPeers entry survived cleanup_after")
	}
	if _, ok := state.runtime.PeerCleanups["node-b.catofes."]; ok {
		t.Fatal("revoked cleanup marker survived completed retention")
	}
}

func TestPeerLifecycleCleanupTearsDownAndSuccessfulSyncRestoresLink(t *testing.T) {
	verified, checkpoint, runtime, syncConfig := buildTestDaemonOwners(t)
	now := time.Unix(500_000, 0)
	addTestIPsecRecords(t, verified.Network.Zones["node-b.catofes."], "node-b.catofes.", now, ipsec.RoleIn)
	config := defaultAppConfig()
	config.PeerLifecycle = inspect.PeerLifecycleConfig{
		StaleAfter:       time.Second,
		OfflineAfter:     2 * time.Second,
		CleanupAfter:     3 * time.Second,
		KeepSAWhileStale: true,
	}
	config.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:                 "main",
		Provider:           ipsec.ProviderStrongSwan,
		NetNS:              ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photon-lifecycle", Create: true},
		DefaultPathMode:    ipsec.PathModeFamilyRedundant,
		AddressSourceOrder: []string{ipsec.SourceManualAddress},
		ConnectRules:       []string{"strongswan://*.catofes.?role=in"},
	}}
	rt := &AppContext{Config: config, Clock: func() time.Time { return now }}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, syncConfig, time.Second)
	if _, err := service.StateStore.common.UpdatePeerCheckpoint(context.Background(), "node-b.catofes.", corestate.PeerCheckpointPatch{
		LastSyncUnix: corestate.PatchField[int64]{Set: true, Value: now.Unix()},
	}); err != nil {
		t.Fatalf("seed peer checkpoint: %v", err)
	}
	service.notifyStateChanged()
	_, initial := readTestDaemonOwners(service)
	if len(initial.LinkInstances) != 1 {
		t.Fatalf("initial links = %+v, want one", initial.LinkInstances)
	}

	now = now.Add(config.PeerLifecycle.CleanupAfter + time.Second)
	service.notifyStateChanged()
	common, cleaned := readTestDaemonOwners(service)
	if len(cleaned.LinkInstances) != 0 || cleaned.IPsecReconcile.DesiredLinks != 0 {
		t.Fatalf("cleaned links = %+v desired=%d", cleaned.LinkInstances, cleaned.IPsecReconcile.DesiredLinks)
	}
	if _, ok := common.Gossip.Peers["node-b.catofes."]; ok {
		t.Fatal("offline peer cache was not removed")
	}
	if _, ok := cleaned.PeerCleanups["node-b.catofes."]; !ok {
		t.Fatal("offline peer suppression marker is missing")
	}
	if _, err := service.StateStore.common.UpdatePeerCheckpoint(context.Background(), "node-b.catofes.", corestate.PeerCheckpointPatch{
		LastSyncUnix: corestate.PatchField[int64]{Set: true, Value: now.Unix()},
	}); err != nil {
		t.Fatalf("record successful sync: %v", err)
	}
	service.notifyStateChanged()
	_, recovered := readTestDaemonOwners(service)
	if _, ok := recovered.PeerCleanups["node-b.catofes."]; ok {
		t.Fatal("successful sync did not clear lifecycle suppression")
	}
	if len(recovered.LinkInstances) != 1 || recovered.IPsecReconcile.DesiredLinks != 1 {
		t.Fatalf("recovered links = %+v desired=%d", recovered.LinkInstances, recovered.IPsecReconcile.DesiredLinks)
	}
}
