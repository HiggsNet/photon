package main

import (
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestDaemonGossipTransportConfigUsesInjectedDeps(t *testing.T) {
	verified, _, _, appConfig := buildTestDaemonOwners(t)
	config := gossipDriverConfig(appConfig, verified, nil)
	knownAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 10001}
	replay := gossip.NewReplayWindow(time.Minute)
	quotas := gossip.NewPeerQuotas(gossip.QuotaConfig{ByteRate: 1, ByteBurst: 1, ObjectRate: 1, ObjectBurst: 1})
	var logged bool
	logger := func(gossip.Event) { logged = true }
	now := time.Unix(1234, 0)
	rt := &AppContext{Clock: func() time.Time { return now }}

	deps := &SyncTransportDeps{
		KnownPeers: map[string]*net.UDPAddr{"node-b.catofes.": knownAddr},
		Replay:     replay,
		Quotas:     quotas,
		Log:        logger,
	}

	transportConfig := gossipTransportConfig(config, deps, rt.Now)
	if transportConfig.KnownPeers["node-b.catofes."] != knownAddr {
		t.Fatalf("KnownPeers did not use injected map")
	}
	if transportConfig.Replay != replay {
		t.Fatalf("Replay did not use injected replay window")
	}
	if transportConfig.Quotas != quotas {
		t.Fatalf("Quotas did not use injected quotas")
	}
	transportConfig.Log(gossip.Event{})
	if !logged {
		t.Fatalf("Log did not use injected logger")
	}
	if got := transportConfig.Clock(); !got.Equal(now) {
		t.Fatalf("Clock = %s, want %s", got, now)
	}
}

func TestDefaultSyncTransportDeps(t *testing.T) {
	appConfig := &appConfig{
		PeerID:          "node-a.catofes.",
		ListenAddr:      "127.0.0.1:0",
		MaxMessageBytes: 4096,
		Bootstrap: []syncConfigPeer{{
			ID:   "node-b.catofes.",
			Addr: "127.0.0.1:10001",
		}},
	}

	config := gossipDriverConfig(appConfig, nil, nil)
	deps := defaultSyncTransportDeps(config, nil)
	if deps.Replay == nil {
		t.Fatalf("Replay is nil")
	}
	if deps.Quotas == nil {
		t.Fatalf("Quotas is nil")
	}
	if addr := deps.KnownPeers["node-b.catofes."]; addr == nil || addr.String() != "127.0.0.1:10001" {
		t.Fatalf("KnownPeers[node-b] = %v, want 127.0.0.1:10001", addr)
	}
}
