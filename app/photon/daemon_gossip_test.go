package main

import (
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestPlanDaemonDiscoveryDoesNotRefreshLifecycleSuppressedCheckpoint(t *testing.T) {
	verified, checkpoint, _, config := buildTestDaemonOwners(t)
	now := time.Now().Truncate(time.Second)
	putVerifiedEndpointRecord(t, verified, "203.0.113.10", 33434, now)
	if checkpoint.Peers == nil {
		checkpoint.Peers = make(map[string]corestate.PeerCheckpoint)
	}
	checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{
		LastSyncUnix: now.Add(-inspect.DefaultPeerLifecycleConfig().CleanupAfter - time.Minute).Unix(),
	}
	input := corehost.GossipDiscoveryInput{
		LocalPeerID: config.PeerID, ManagedZone: verified.ManagedZone, Network: verified.Network,
		Bootstrap: configuredKnownPeers(config), EndpointGrace: gossip.DefaultEndpointGrace,
		SourceOrder: append([]string(nil), defaultAppConfig().EndpointSourceOrder...),
		Suppressed:  peerLifecycleSuppressions(verified.Network, checkpoint, now, inspect.DefaultPeerLifecycleConfig()),
	}
	if checkpoint != nil {
		input.Peers = checkpoint.Peers
	}

	plan := corehost.PlanGossipDiscovery(input, now)
	if _, ok := plan.Patches["node-b.catofes."]; ok {
		t.Fatalf("lifecycle-suppressed peer checkpoint was refreshed: %#v", plan.Patches)
	}
	transport := &gossip.Transport{}
	corehost.ApplyGossipDiscoveryPlan(transport, plan)
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("lifecycle-suppressed peer is not dialable for recovery: %v", addr)
	}
}

func TestDaemonUpdateDiscoveredPeersCommitsThenRepairsTransportWithoutNoopRevision(t *testing.T) {
	verified, checkpoint, runtimeState, config := buildTestDaemonOwners(t)
	now := time.Now().Truncate(time.Second)
	putVerifiedEndpointRecord(t, verified, "203.0.113.10", 33434, now)
	runtime := &AppContext{Config: defaultAppConfig(), Clock: func() time.Time { return now }}
	service := newTestDaemonFromOwners(runtime, verified, checkpoint, runtimeState, config, time.Second)
	transport := &gossip.Transport{}
	setTestGossipTransport(t, service, transport)

	before := uint64(service.State.Common.VerifiedRevision())
	service.refreshGossipDiscovery()
	after := uint64(service.State.Common.VerifiedRevision())
	if after != before {
		t.Fatalf("discovery changed verified revision: before=%d after=%d", before, after)
	}
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("transport address = %v", addr)
	}
	if got := service.State.Common.ReadView().Gossip.Peers["node-b.catofes."].DiscoveredEndpoint; got != "203.0.113.10:33434" {
		t.Fatalf("committed DiscoveredEndpoint = %q", got)
	}
	transport.RemovePeerAddrs("node-b.catofes.")
	service.refreshGossipDiscovery()
	if got := uint64(service.State.Common.VerifiedRevision()); got != after {
		t.Fatalf("no-op discovery changed revision: before=%d after=%d", after, got)
	}
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("no-op discovery did not repair transport: %v", addr)
	}
}

func putVerifiedEndpointRecord(t *testing.T, verified *corestate.VerifiedState, ip string, port uint16, now time.Time) {
	t.Helper()
	record := &zone.Record{
		Zone: "node-b.catofes.", Key: gossip.EndpointRecordKeyUDP, Type: "sync.endpoint",
		Value:   endpointRecordBytes([]gossip.LocalEndpoint{{IP: net.ParseIP(ip), Port: port, Scope: "global", Priority: 100, Source: gossip.SourceAdvertise}}, now),
		Version: 1, Timestamp: now.Unix(),
	}
	if err := photoncrypto.SignRecord(record, verified.IdentityPrivateKey); err != nil {
		t.Fatalf("SignRecord(endpoint): %v", err)
	}
	if err := verified.Network.PutAt(record, now); err != nil {
		t.Fatalf("PutAt(endpoint): %v", err)
	}
}
