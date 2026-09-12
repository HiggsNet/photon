package main

import (
	"github.com/HiggsNet/photon/internal/photonlinux"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestDaemonObjectPullWorkerPullsZone(t *testing.T) {
	verified, checkpoint, _, _ := buildTestDaemonOwners(t)
	verified.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	now := time.Unix(1000, 0)
	record := &zone.Record{
		Zone:      "node-b.catofes.",
		Key:       "identity",
		Type:      "node.identity",
		Value:     []byte("node-b"),
		Version:   1,
		Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(record, verified.IdentityPrivateKey); err != nil {
		t.Fatalf("SignRecord: %v", err)
	}
	if err := verified.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt: %v", err)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen: %v", err)
	}
	runtime := corehost.NewGossipDriver(corehost.NewClock(nil), corehost.DefaultEventBuffer, nil, corehost.GossipDriverConfig{})
	server := newTestDaemonFromOwners(
		&AppContext{}, verified, checkpoint, &photonlinux.LinuxState{}, &appConfig{PeerID: "node-b.catofes."}, time.Second,
	)
	if err := runtime.StartGossipObjectPullServer(t.Context(), listener, server.objectPullResponse, 0, 0); err != nil {
		_ = listener.Close()
		t.Fatalf("StartGossipObjectPullServer: %v", err)
	}
	defer runtime.Stop()

	config := &appConfig{Bootstrap: []syncConfigPeer{{ID: "node-b.catofes.", Addr: listener.Addr().String()}}}
	service := newTestDaemonFromOwners(&AppContext{}, verified, nil, &photonlinux.LinuxState{}, config, time.Second)
	completion := service.objectPullExecutor.PullGossipObject(t.Context(), gossip.StartObjectPullAction{PeerID: "node-b.catofes.", Zone: "node-b.catofes."})
	if completion.Err != nil {
		t.Fatalf("object pull failed: %v", completion.Err)
	}
	if completion.Snapshot == nil || completion.Snapshot.Zone != "node-b.catofes." {
		t.Fatalf("unexpected snapshot: %+v", completion.Snapshot)
	}
	if len(completion.Snapshot.Records) != 1 {
		t.Fatalf("expected 1 record, got %d", len(completion.Snapshot.Records))
	}
}

func TestDaemonObjectPullWorkerReturnsErrorForUnreachable(t *testing.T) {
	verified, checkpoint, runtime, _ := buildTestDaemonOwners(t)
	config := &appConfig{Bootstrap: []syncConfigPeer{{ID: "node-b.catofes.", Addr: "127.0.0.1:1"}}}
	service := newTestDaemonFromOwners(
		&AppContext{}, verified, checkpoint, runtime, config, time.Second,
	)
	completion := service.objectPullExecutor.PullGossipObject(t.Context(), gossip.StartObjectPullAction{PeerID: "node-b.catofes.", Zone: "node-b.catofes."})
	if completion.Err == nil {
		t.Fatal("expected error for unreachable peer")
	}
	if completion.Snapshot != nil {
		t.Fatal("expected nil snapshot on error")
	}
}
