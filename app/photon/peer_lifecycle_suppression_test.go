package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestTunnelSuspensionSurvivesRestartWithoutActivityTimestamps(t *testing.T) {
	now := time.Unix(500_000, 0)
	peerID := zone.ZonePath("node-b.catofes.")
	owners, _, _, _ := buildPeerStateTestOwners(t)
	verified := owners.verified
	addTestIPsecRecords(t, verified.Network.Zones[peerID], peerID, now, ipsec.RoleIn)
	path := filepath.Join(t.TempDir(), "photon.db")
	seedPartitionedStateDB(t, path, verified, nil, &photonlinux.LinuxState{})

	config := defaultAppConfig()
	config.PeerLifecycle = inspect.PeerLifecycleConfig{
		StaleAfter: 15 * time.Second, OfflineAfter: 30 * time.Second,
		CleanupAfter: time.Minute, KeepSAWhileStale: true,
	}
	open := func() *Daemon {
		t.Helper()
		disk, err := corestate.OpenBoltStore(path, 0o600, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		state, found, err := restoreState(disk, verified.TrustedRootPublicKey)
		if err != nil || !found {
			_ = disk.Close()
			t.Fatalf("restore state: found=%v err=%v", found, err)
		}
		t.Cleanup(func() { _ = state.Close() })
		return &Daemon{Config: config, State: state}
	}
	reconcile := func(d *Daemon, at time.Time, suspended bool) {
		t.Helper()
		if err := d.reconcileTunnelPeerSuspensions(d.State.Common.ReadView(), d.State.ReadLinux(), at); err != nil {
			t.Fatal(err)
		}
		if got := d.State.ReadLinux().SuspendedTunnelPeers[peerID]; got != suspended {
			t.Fatalf("at %s: suspension=%v, want %v", at, got, suspended)
		}
	}

	d := open()
	reconcile(d, now, false)
	reconcile(d, now.Add(time.Minute-time.Second), false)
	reconcile(d, now.Add(time.Minute), true)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	d = open()
	now = now.Add(time.Hour)
	reconcile(d, now, true)
	if _, err := d.State.Common.UpdatePeerCheckpoint(t.Context(), peerID.String(), corestate.PeerCheckpointPatch{
		ObservedLastUnix: corestate.PatchField[int64]{Set: true, Value: now.Unix()},
	}); err != nil {
		t.Fatal(err)
	}
	reconcile(d, now, false)
	if err := d.Close(); err != nil {
		t.Fatal(err)
	}

	d = open()
	peer := d.State.Common.PeerCheckpoints([]string{peerID.String()})[peerID.String()]
	if peerLifecycleLastActiveUnix(peer) != 0 {
		t.Fatalf("activity timestamps survived restart: %+v", peer)
	}
	reconcile(d, now.Add(time.Second), false)
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
	clock := newFakeClock(now)
	rt := &testApp{Config: config, Clock: clock.Now}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, syncConfig, time.Second)
	defer service.gossipDriver.Stop()
	if _, err := service.State.Common.UpdatePeerCheckpoint(context.Background(), "node-b.catofes.", corestate.PeerCheckpointPatch{
		LastSyncUnix: corestate.PatchField[int64]{Set: true, Value: now.Unix()},
	}); err != nil {
		t.Fatalf("seed peer checkpoint: %v", err)
	}
	service.notifyStateChanged()
	service.processEvents(context.Background(), nil)
	initialLinks, _ := readTestIPsecObservation(service)
	if len(initialLinks) != 1 {
		t.Fatalf("initial links = %+v, want one", initialLinks)
	}

	clock.Advance(config.PeerLifecycle.CleanupAfter + time.Second)
	now = clock.Now()
	service.notifyStateChanged()
	service.processEvents(context.Background(), nil)
	cleanedLinks, cleanedReconcile := readTestIPsecObservation(service)
	if len(cleanedLinks) != 0 || len(cleanedReconcile.Desired) != 0 {
		t.Fatalf("cleaned links = %+v desired=%d", cleanedLinks, len(cleanedReconcile.Desired))
	}
	if !service.State.ReadLinux().SuspendedTunnelPeers["node-b.catofes."] {
		t.Fatal("tunnel was cleaned without publishing the suspension marker")
	}
	if _, err := service.State.Common.UpdatePeerCheckpoint(context.Background(), "node-b.catofes.", corestate.PeerCheckpointPatch{
		LastSyncUnix: corestate.PatchField[int64]{Set: true, Value: now.Unix()},
	}); err != nil {
		t.Fatalf("record successful sync: %v", err)
	}
	// An unchanged catalog only updates activity. The periodic IPsec
	// reconcile must release the suspension even without a Zone change.
	service.ipsecDirty = true
	service.flushIPsecReconcile(context.Background())
	if service.State.ReadLinux().SuspendedTunnelPeers["node-b.catofes."] {
		t.Fatal("fresh activity did not clear the suspension marker")
	}
	recoveredLinks, recoveredReconcile := readTestIPsecObservation(service)
	if len(recoveredLinks) != 1 || len(recoveredReconcile.Desired) != 1 {
		t.Fatalf("recovered links = %+v desired=%d", recoveredLinks, len(recoveredReconcile.Desired))
	}
}
