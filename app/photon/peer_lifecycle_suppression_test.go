package main

import (
	"context"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestPeerLifecycleSuppressionDerivesFromRetainedCheckpoint(t *testing.T) {
	state, _, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(200_000, 0)
	cfg := inspect.DefaultPeerLifecycleConfig()
	peerID := zone.ZonePath("node-b.catofes.")
	state.checkpoint.Peers[peerID.String()] = corestate.PeerCheckpoint{
		LastSyncUnix: now.Add(-cfg.CleanupAfter - time.Minute).Unix(),
	}

	if got := peerLifecycleExcludedPeers(state.checkpoint, now, cfg)[peerID]; got != peerCleanupReasonOffline {
		t.Fatalf("excluded reason = %q", got)
	}
	if !peerLifecycleSuppressions(state.verified.Network, state.checkpoint, now, cfg)[peerID.String()] {
		t.Fatal("offline peer is not suppressed from derived discovery updates")
	}
	if _, ok := state.checkpoint.Peers[peerID.String()]; !ok {
		t.Fatal("suppression calculation removed the checkpoint used as its source")
	}

	state.checkpoint.Peers[peerID.String()] = corestate.PeerCheckpoint{LastSyncUnix: now.Unix()}
	if _, ok := peerLifecycleExcludedPeers(state.checkpoint, now, cfg)[peerID]; ok {
		t.Fatal("successful sync did not clear the derived data-plane suppression")
	}
	if peerLifecycleSuppressions(state.verified.Network, state.checkpoint, now, cfg)[peerID.String()] {
		t.Fatal("successful sync did not clear the derived discovery suppression")
	}
}

func TestPeerLifecycleSuppressionDerivesRevocationFromVerifiedState(t *testing.T) {
	state, parentKey, _, _ := buildPeerStateTestOwners(t)
	now := time.Unix(300_000, 0)
	peerID := zone.ZonePath("node-b.catofes.")
	addRevocationToParent(t, state.verified.Network, "catofes.", peerID, parentKey, now)
	delete(state.verified.Network.Zones, peerID)

	if !peerLifecycleSuppressions(state.verified.Network, state.checkpoint, now, inspect.DefaultPeerLifecycleConfig())[peerID.String()] {
		t.Fatal("revoked peer without ZoneState or checkpoint is not suppressed from discovery")
	}
}

func TestPeerLifecycleSuppressionTearsDownAndSuccessfulSyncRestoresLink(t *testing.T) {
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
	if _, err := service.State.Common.UpdatePeerCheckpoint(context.Background(), "node-b.catofes.", corestate.PeerCheckpointPatch{
		LastSyncUnix: corestate.PatchField[int64]{Set: true, Value: now.Unix()},
	}); err != nil {
		t.Fatalf("seed peer checkpoint: %v", err)
	}
	service.notifyStateChanged()
	initialLinks, _ := readTestIPsecObservation(service)
	if len(initialLinks) != 1 {
		t.Fatalf("initial links = %+v, want one", initialLinks)
	}

	now = now.Add(config.PeerLifecycle.CleanupAfter + time.Second)
	service.notifyStateChanged()
	common := service.State.Common.ReadView()
	cleanedLinks, cleanedReconcile := readTestIPsecObservation(service)
	if len(cleanedLinks) != 0 || cleanedReconcile.DesiredLinks != 0 {
		t.Fatalf("cleaned links = %+v desired=%d", cleanedLinks, cleanedReconcile.DesiredLinks)
	}
	if _, ok := common.Gossip.Peers["node-b.catofes."]; !ok {
		t.Fatal("offline checkpoint was removed instead of retained as the suppression source")
	}
	if _, err := service.State.Common.UpdatePeerCheckpoint(context.Background(), "node-b.catofes.", corestate.PeerCheckpointPatch{
		LastSyncUnix: corestate.PatchField[int64]{Set: true, Value: now.Unix()},
	}); err != nil {
		t.Fatalf("record successful sync: %v", err)
	}
	service.notifyStateChanged()
	recoveredLinks, recoveredReconcile := readTestIPsecObservation(service)
	if len(recoveredLinks) != 1 || recoveredReconcile.DesiredLinks != 1 {
		t.Fatalf("recovered links = %+v desired=%d", recoveredLinks, recoveredReconcile.DesiredLinks)
	}
}
