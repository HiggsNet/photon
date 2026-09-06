package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// This app-level test only covers the Linux composition reaction to a common
// GossipDriver result. Chunk assembly, snapshot validation, checkpoint updates
// and session completion are unit-tested in pkg/core/host.
func TestDaemonObjectChunkCompletionNotifiesPlatformOnce(t *testing.T) {
	sourceVerified, _, _, _ := buildTestDaemonOwners(t)
	snapshot, err := corestate.Snapshot(sourceVerified.Network, "catofes.")
	if err != nil {
		t.Fatalf("Snapshot(catofes): %v", err)
	}
	data, err := gossip.EncodeZoneSnapshotObject(snapshot)
	if err != nil {
		t.Fatalf("EncodeZoneSnapshotObject: %v", err)
	}
	objectHash := sha256.Sum256(data)
	rootHash := corestate.ZoneRoot(sourceVerified.Network.Zones["catofes."])

	targetVerified := *sourceVerified
	targetVerified.Network = zone.CloneNetworkState(sourceVerified.Network)
	delete(targetVerified.Network.Zones, zone.ZonePath("catofes."))
	delete(targetVerified.Network.Zones, zone.ZonePath("node-b.catofes."))
	now := time.Unix(2230, 0)
	rt := &AppContext{Clock: func() time.Time { return now }}
	config := &gossipStartupConfig{PeerID: "node-a.catofes.", ListenAddr: "127.0.0.1:0"}
	service := newTestDaemonFromOwners(
		rt, &targetVerified, &corestate.GossipCheckpoint{}, &linuxRuntimeState{}, config, defaultDaemonInterval,
	)
	peerID := "node-b.catofes."
	session := gossip.NewSyncSession(peerID)
	_, _ = session.OnEvent(&gossip.SyncTimerEvent{PeerID: peerID}, now)
	_, _ = session.OnEvent(&gossip.PongReceivedEvent{PeerID: peerID, Pong: &gossip.Pong{}, MissingZones: []zone.ZonePath{"catofes."}}, now)
	_, _ = session.OnEvent(&gossip.ObjectPullResultEvent{PeerID: peerID, Zone: "catofes.", Err: errors.New("tcp unavailable")}, now)
	service.gossipDriver.Gossip.SetSession(peerID, session)
	notifications := 0
	service.Hooks.OnStateChanged = func() { notifications++ }
	beforeRevision := service.StateStore.common.VerifiedRevision()

	chunkSize := len(data) / 2
	if chunkSize == 0 {
		t.Fatal("encoded snapshot unexpectedly empty")
	}
	chunks := []*gossip.ObjectChunk{
		{
			TransferID: []byte("daemon-chunks-01"), Object: gossip.ObjectPullZone,
			Zone: "catofes.", RootHash: rootHash, ObjectHash: objectHash[:],
			Index: 0, Total: 2, Data: data[:chunkSize],
		},
		{
			TransferID: []byte("daemon-chunks-01"), Object: gossip.ObjectPullZone,
			Zone: "catofes.", RootHash: rootHash, ObjectHash: objectHash[:],
			Index: 1, Total: 2, Data: data[chunkSize:],
		},
	}
	for _, chunk := range []*gossip.ObjectChunk{chunks[1], chunks[0]} {
		if err := service.processPacketEvent(&gossip.Packet{Message: &gossip.Message{
			Type: gossip.MessageObjectChunk, PeerID: peerID, ObjectChunk: chunk,
		}}, context.Background()); err != nil {
			t.Fatalf("handleObjectChunk: %v", err)
		}
	}
drainEvents:
	for range 4 {
		if service.gossipDriver.Gossip.Session(peerID) == nil && service.gossipDriver.PendingEventCount() == 0 {
			break
		}
		select {
		case hostEvent := <-service.gossipDriver.Events():
			_, _ = service.handleGossipDriverEvent(context.Background(), hostEvent)
		default:
			break drainEvents
		}
	}

	if targetVerified.Network.Zones["catofes."] != nil {
		t.Fatal("common Store mutated the detached verified input")
	}
	committed := service.StateStore.common.ReadView()
	if committed.Revision <= beforeRevision || committed.State.Network.Zones["catofes."] == nil {
		t.Fatalf("common owner did not publish chunk snapshot: revision %d -> %d", beforeRevision, committed.Revision)
	}
	if active := service.gossipDriver.Gossip.Session(peerID); active != nil {
		t.Fatalf("chunk sync session remained active: state=%s pending=%d inflight=%d", active.State, active.PendingCount(), active.InflightCount())
	}
	if notifications != 1 {
		t.Fatalf("platform notifications = %d, want one", notifications)
	}
}
