package main

import (
	"bytes"
	"context"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestAppLoggerAcceptsCommonGossipRecords(t *testing.T) {
	for _, level := range []slog.Level{slog.LevelDebug, slog.LevelInfo, slog.LevelWarn, slog.LevelError} {
		t.Run(level.String(), func(t *testing.T) {
			var output bytes.Buffer
			logger := (&appLogger{}).setLevel(logLevelInfo).withOutput(&output)
			enabled := logger.Enabled(t.Context(), level)
			if enabled != (level >= slog.LevelInfo) {
				t.Fatalf("enabled = %v", enabled)
			}
			if !enabled {
				return
			}
			record := slog.NewRecord(time.Now(), level, "zone_applied", 0)
			record.AddAttrs(slog.String("component", "gossip"), slog.String("peer_id", "node-b.catofes."))
			if err := logger.Handle(t.Context(), record); err != nil {
				t.Fatal(err)
			}
			for _, want := range []string{"level=" + strings.ToLower(level.String()), "component=gossip", "event=zone_applied", "peer_id=node-b.catofes."} {
				if !strings.Contains(output.String(), want) {
					t.Fatalf("log %q missing %q", output.String(), want)
				}
			}
		})
	}
}

func TestDaemonDiscoveryRefreshesAddressEvenWhenTunnelIsSuspended(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Now().Truncate(time.Second)
	putVerifiedEndpointRecord(t, verified, "203.0.113.10", 33434, now)
	if checkpoint.Peers == nil {
		checkpoint.Peers = make(map[string]corestate.PeerCheckpoint)
	}
	checkpoint.Peers["node-b.catofes."] = corestate.PeerCheckpoint{
		LastSyncUnix: now.Add(-inspect.DefaultPeerLifecycleConfig().CleanupAfter - time.Minute).Unix(),
	}
	runtime.SuspendedTunnelPeers = map[zone.ZonePath]bool{"node-b.catofes.": true}
	service := newTestDaemonFromOwners(
		&testApp{Config: defaultAppConfig(), Clock: func() time.Time { return now }},
		verified, checkpoint, runtime, config, time.Second,
	)
	transport := &gossip.Transport{}
	setTestGossipTransport(t, service, transport)
	service.refreshGossipDiscovery()
	if addr := transport.PeerAddr("node-b.catofes."); addr == nil || addr.String() != "203.0.113.10:33434" {
		t.Fatalf("lifecycle-suppressed peer is not dialable for recovery: %v", addr)
	}
}

func TestDaemonDiscoveryRefreshRepairsTransportWithoutAdvancingRevision(t *testing.T) {
	verified, checkpoint, runtimeState, config := buildTestDaemonOwners(t)
	now := time.Now().Truncate(time.Second)
	putVerifiedEndpointRecord(t, verified, "203.0.113.10", 33434, now)
	runtime := &testApp{Config: defaultAppConfig(), Clock: func() time.Time { return now }}
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
	transport.ReplaceDiscoveryAddrs(nil, nil)
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

func TestDaemonPacketEventUpdatesCheckpointOwner(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&testApp{Config: defaultAppConfig()}, verified, checkpoint, runtime, config, time.Second,
	)
	packet := &gossip.Packet{
		Addr: &net.UDPAddr{IP: net.ParseIP("198.51.100.9"), Port: 33434},
		Message: &gossip.Message{
			Type:   gossip.MessagePong,
			PeerID: "node-b.catofes.",
			Pong:   &gossip.Pong{},
		},
	}

	if _, err := service.handleGossipDriverEvent(context.Background(), corehost.GossipPacketReceived{Packet: packet}); err != nil {
		t.Fatalf("packet event error: %v", err)
	}

	peer := service.State.Common.ReadView().Gossip.Peers["node-b.catofes."]
	if peer.ObservedEndpoint != "198.51.100.9:33434" {
		t.Fatalf("observed endpoint = %q, want packet source", peer.ObservedEndpoint)
	}
}
