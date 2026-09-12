package main

import (
	"context"
	"github.com/HiggsNet/photon/internal/photonlinux"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// This remains an app-level test because it validates the complete Linux
// composition: UDP datagrams, TCP object-pull, daemon event pumping and the
// two common stores converge through the production wiring.
func TestDaemonEventLoopSyncSession(t *testing.T) {
	verifiedA, configA, verifiedB, configB := buildTestABVerifiedStates(t)
	now := time.Now()

	recordA, err := buildSignedRecordAt(verifiedA.Network, verifiedA.IdentityPrivateKey, "node-a.catofes.", "event-loop-test", []byte("from-a"), "policy.string", now)
	if err != nil {
		t.Fatalf("build record for A: %v", err)
	}
	if err := verifiedA.Network.Put(recordA); err != nil {
		t.Fatalf("put record on A: %v", err)
	}
	recordB, err := buildSignedRecordAt(verifiedB.Network, verifiedB.IdentityPrivateKey, "node-b.catofes.", "event-loop-test", []byte("from-b"), "policy.string", now)
	if err != nil {
		t.Fatalf("build record for B: %v", err)
	}
	if err := verifiedB.Network.Put(recordB); err != nil {
		t.Fatalf("put record on B: %v", err)
	}

	transportA, err := listenTestGossipTransport(configA.ListenAddr, gossip.Config{PeerID: configA.PeerID})
	if err != nil {
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()
	transportB, err := listenTestGossipTransport(configB.ListenAddr, gossip.Config{PeerID: configB.PeerID})
	if err != nil {
		t.Fatalf("Listen(B): %v", err)
	}
	defer transportB.Close()
	transportA.AddPeer(configB.PeerID, transportB.LocalAddr())
	transportB.AddPeer(configA.PeerID, transportA.LocalAddr())
	configA.ListenAddr = transportA.LocalAddr().String()
	configB.ListenAddr = transportB.LocalAddr().String()
	configA.Bootstrap = []syncConfigPeer{{ID: configB.PeerID, Addr: transportB.LocalAddr().String()}}
	configB.Bootstrap = []syncConfigPeer{{ID: configA.PeerID, Addr: transportA.LocalAddr().String()}}

	rtA := &AppContext{Config: defaultAppConfig(), Clock: func() time.Time { return now }}
	rtB := &AppContext{Config: defaultAppConfig(), Clock: func() time.Time { return now }}

	serviceA := newTestDaemonFromOwners(rtA, verifiedA, nil, &photonlinux.LinuxState{}, configA, time.Second)
	setTestGossipTransport(t, serviceA, transportA)
	serviceB := newTestDaemonFromOwners(rtB, verifiedB, nil, &photonlinux.LinuxState{}, configB, time.Second)
	setTestGossipTransport(t, serviceB, transportB)
	clock := newFakeClock(now)
	serviceA.EnableEventLoopSync(clock)
	serviceB.EnableEventLoopSync(clock)

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := startObjectPullServer(ctx, serviceA); err != nil {
		t.Fatalf("startObjectPullServer(A): %v", err)
	}
	if err := startObjectPullServer(ctx, serviceB); err != nil {
		t.Fatalf("startObjectPullServer(B): %v", err)
	}
	if err := serviceA.gossipDriver.StartGossipObjectPullWorkers(ctx, serviceA.objectPullExecutor, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer serviceA.gossipDriver.Stop()
	if err := serviceB.gossipDriver.StartGossipObjectPullWorkers(ctx, serviceB.objectPullExecutor, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer serviceB.gossipDriver.Stop()
	if err := serviceA.handleSyncTimerEvent(ctx, true); err != nil {
		t.Fatalf("handleSyncTimerEvent(A): %v", err)
	}
	if err := serviceB.handleSyncTimerEvent(ctx, true); err != nil {
		t.Fatalf("handleSyncTimerEvent(B): %v", err)
	}

	for {
		pumpEventLoopSync(ctx, []*Daemon{serviceA, serviceB}, []*gossip.Transport{transportA, transportB})
		a := serviceA.gossipDriver.Gossip.Session(configB.PeerID)
		b := serviceB.gossipDriver.Gossip.Session(configA.PeerID)
		if (a == nil || a.Done()) && (b == nil || b.Done()) {
			break
		}
		clock.Advance(5 * time.Second)
	}
	if serviceA.gossipDriver.Gossip.Session(configB.PeerID) != nil || serviceB.gossipDriver.Gossip.Session(configA.PeerID) != nil {
		t.Fatal("completed two-node sync retained an active session")
	}
	latestA := serviceA.State.Common.ReadView()
	latestB := serviceB.State.Common.ReadView()
	if latestA.State.Network.Zones["node-b.catofes."] == nil || latestA.State.Network.Zones["node-b.catofes."].Records["event-loop-test"] == nil {
		t.Fatal("record from B did not appear on A")
	}
	if latestB.State.Network.Zones["node-a.catofes."] == nil || latestB.State.Network.Zones["node-a.catofes."].Records["event-loop-test"] == nil {
		t.Fatal("record from A did not appear on B")
	}
}

func TestObjectPullTCPAddrUsesGossipPort(t *testing.T) {
	if got := objectPullTCPAddr("192.0.2.1:33434"); got != "192.0.2.1:33434" {
		t.Fatalf("objectPullTCPAddr = %q, want 192.0.2.1:33434", got)
	}
	if got := objectPullTCPAddr("[2001:db8::1]:33434"); got != "[2001:db8::1]:33434" {
		t.Fatalf("objectPullTCPAddr v6 = %q, want [2001:db8::1]:33434", got)
	}
}

// The timer fallback remains app-specific while daemon scheduling still owns
// the periodic bootstrap trigger around GossipDriver's bounded event queue.
func TestDaemonSyncTimerStartsWhenInternalEventQueueIsFull(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(1000, 0)
	peerID := "bootstrap.catofes."
	config.Bootstrap = []syncConfigPeer{{ID: peerID, Addr: "127.0.0.1:33434"}}
	checkpoint.Peers = map[string]corestate.PeerCheckpoint{peerID: {BackoffUntilUnix: now.Add(-time.Minute).Unix()}}
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig(), Clock: func() time.Time { return now }},
		verified, checkpoint, runtime, config, time.Minute,
	)
	for {
		if err := service.gossipDriver.PostGossip(&gossip.SyncTimerEvent{PeerID: "queued.catofes."}); err != nil {
			break
		}
	}
	if err := service.handleSyncTimerEvent(context.Background(), false); err != nil {
		t.Fatalf("handleSyncTimerEvent: %v", err)
	}
	session := service.gossipDriver.Gossip.Session(peerID)
	if session == nil || session.State != gossip.SyncSessionSummarySent {
		t.Fatalf("bootstrap session = %#v, want directly started summary_sent session", session)
	}
}
