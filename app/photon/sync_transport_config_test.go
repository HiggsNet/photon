package main

import (
	"testing"
	"time"
)

func TestDaemonGossipTransportConfigUsesDriverConfig(t *testing.T) {
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
	now := time.Unix(1234, 0)
	transportConfig := gossipTransportConfig(config, nil, func() time.Time { return now })
	if transportConfig.PeerID != config.PeerID || transportConfig.MaxMessageBytes != 4096 {
		t.Fatalf("transport identity/limits = %q/%d", transportConfig.PeerID, transportConfig.MaxMessageBytes)
	}
	if addr := transportConfig.KnownPeers["node-b.catofes."]; addr == nil || addr.String() != "127.0.0.1:10001" {
		t.Fatalf("KnownPeers[node-b] = %v, want 127.0.0.1:10001", addr)
	}
	if transportConfig.Replay == nil || transportConfig.Quotas == nil {
		t.Fatal("transport must enforce replay protection and quotas")
	}
	if got := transportConfig.Clock(); !got.Equal(now) {
		t.Fatalf("Clock = %s, want %s", got, now)
	}
}
