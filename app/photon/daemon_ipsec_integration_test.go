package main

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDaemonABPublishesGossipsAndReconcilesIPsecRecords(t *testing.T) {
	verifiedA, configA, verifiedB, configB := buildTestABVerifiedStates(t)
	runtimeA, runtimeB := &photonlinux.LinuxState{}, &photonlinux.LinuxState{}
	group := testIPsecLinkGroup()

	transportA, err := listenTestGossipTransport(configA.ListenAddr, gossip.Config{
		PeerID: configA.PeerID,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(A): %v", err)
	}
	defer transportA.Close()
	transportB, err := listenTestGossipTransport(configB.ListenAddr, gossip.Config{
		PeerID: configB.PeerID,
	})
	if err != nil {
		skipRestrictedSocket(t, err)
		t.Fatalf("Listen(B): %v", err)
	}
	defer transportB.Close()
	transportA.AddPeer(configB.PeerID, transportB.LocalAddr())
	transportB.AddPeer(configA.PeerID, transportA.LocalAddr())
	configA.ListenAddr = transportA.LocalAddr().String()
	configB.ListenAddr = transportB.LocalAddr().String()
	configA.Bootstrap = []syncConfigPeer{{ID: configB.PeerID, Addr: transportB.LocalAddr().String()}}
	configB.Bootstrap = []syncConfigPeer{{ID: configA.PeerID, Addr: transportA.LocalAddr().String()}}

	rtA := &testApp{Config: testDaemonIPsecAppConfig(filepath.Join(t.TempDir(), "a"), "198.51.100.10:4500", group), Clock: time.Now}
	rtA.Config.IPsec.Role = ipsec.RoleIn
	rtB := &testApp{Config: testDaemonIPsecAppConfig(filepath.Join(t.TempDir(), "b"), "198.51.100.20:4500", group), Clock: time.Now}
	rtB.Config.IPsec.Role = ipsec.RoleIn
	driverA := &observedIPsecDriver{}
	driverB := &observedIPsecDriver{}
	serviceA := newTestDaemonFromOwners(rtA, verifiedA, nil, runtimeA, configA, time.Second)
	serviceB := newTestDaemonFromOwners(rtB, verifiedB, nil, runtimeB, configB, time.Second)
	setTestGossipTransport(t, serviceA, transportA)
	setTestGossipTransport(t, serviceB, transportB)
	installTestIPsecDrivers(serviceA, driverA, driverA)
	installTestIPsecDrivers(serviceB, driverB, driverB)

	if err := startObjectPullServer(t.Context(), serviceA); err != nil {
		t.Fatalf("startObjectPullServer(A): %v", err)
	}
	if err := startObjectPullServer(t.Context(), serviceB); err != nil {
		t.Fatalf("startObjectPullServer(B): %v", err)
	}

	if _, err := serviceA.handleEndpointTimerEvent(); err != nil {
		t.Fatalf("publish node-a ipsec records: %v", err)
	}
	if _, err := serviceB.handleEndpointTimerEvent(); err != nil {
		t.Fatalf("publish node-b ipsec records: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := serviceA.gossipDriver.StartGossipObjectPullWorkers(ctx, serviceA.objectPullExecutor, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer serviceA.gossipDriver.Stop()
	if err := serviceB.gossipDriver.StartGossipObjectPullWorkers(ctx, serviceB.objectPullExecutor, 0, 0); err != nil {
		t.Fatal(err)
	}
	defer serviceB.gossipDriver.Stop()

	if err := serviceB.handleSyncTimerEvent(ctx, true); err != nil {
		t.Fatalf("start sync node-b from node-a: %v", err)
	}
	if err := serviceA.handleSyncTimerEvent(ctx, true); err != nil {
		t.Fatalf("start sync node-a from node-b: %v", err)
	}
	for {
		if err := pumpEventLoopSync(ctx, []*Daemon{serviceA, serviceB}, []*gossip.Transport{transportA, transportB}); err != nil {
			t.Fatalf("pump event loop: %v", err)
		}
		aActive := false
		if s := serviceA.gossipDriver.Gossip.Session(configB.PeerID); s != nil && !s.Done() {
			aActive = true
		}
		bActive := false
		if s := serviceB.gossipDriver.Gossip.Session(configA.PeerID); s != nil && !s.Done() {
			bActive = true
		}
		if !aActive && !bActive {
			break
		}
		if ctx.Err() != nil {
			t.Fatalf("event-loop sync timed out: %v", ctx.Err())
		}
	}

	if err := serviceA.reconcileIPsecLinks(ctx); err != nil {
		t.Fatalf("reconcile node-a ipsec links: %v", err)
	}
	if err := serviceB.reconcileIPsecLinks(ctx); err != nil {
		t.Fatalf("reconcile node-b ipsec links: %v", err)
	}

	commonA := serviceA.State.Common.ReadView()
	_, latestAReconcile := readTestIPsecObservation(serviceA)
	commonB := serviceB.State.Common.ReadView()
	_, latestBReconcile := readTestIPsecObservation(serviceB)
	assertGossipedIPsecRecords(t, commonA.State.Network, "node-b.catofes.")
	assertGossipedIPsecRecords(t, commonB.State.Network, "node-a.catofes.")
	specA := singleDesiredSpec(t, commonA.State.ManagedZone, latestAReconcile)
	specB := singleDesiredSpec(t, commonB.State.ManagedZone, latestBReconcile)
	if specA.PeerZone != "node-b.catofes." || specB.PeerZone != "node-a.catofes." {
		t.Fatalf("planned peer zones = %s/%s, want node-b/node-a", specA.PeerZone, specB.PeerZone)
	}
	assertDryRunApply(t, driverA, specA, group.NetNS)
	assertDryRunApply(t, driverB, specB, group.NetNS)
	if latestAReconcile == nil || latestAReconcile.DesiredLinks != 1 || len(latestAReconcile.Actions) == 0 {
		t.Fatalf("node-a reconcile = %+v, want desired link and action", latestAReconcile)
	}
	if latestBReconcile == nil || latestBReconcile.DesiredLinks != 1 || len(latestBReconcile.Actions) == 0 {
		t.Fatalf("node-b reconcile = %+v, want desired link and action", latestBReconcile)
	}
}
