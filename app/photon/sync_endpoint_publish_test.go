package main

import (
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestEndpointProtocolIntentCollectsPlatformCandidates(t *testing.T) {
	verified, _, _, config := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	config.PeerID = string(verified.ManagedZone)
	config.ListenAddr = "127.0.0.1:33434"
	now := time.Unix(1000, 0)
	oldCollect := collectSyncLocalEndpoints
	collectSyncLocalEndpoints = func(port uint16, _ []string, _ []string, _ time.Duration, _ bool) ([]gossip.LocalEndpoint, error) {
		return []gossip.LocalEndpoint{{IP: net.ParseIP("198.51.100.10"), Port: port, Scope: "global", Source: gossip.SourceReflector}}, nil
	}
	t.Cleanup(func() { collectSyncLocalEndpoints = oldCollect })

	daemon := &Daemon{
		App: &AppContext{Config: config, Clock: func() time.Time { return now }},
	}
	daemon.App.Config.EndpointTTL = time.Hour
	intent, err := daemon.endpointProtocolIntent(verified)
	if err != nil || intent == nil {
		t.Fatalf("endpoint intent/error = %#v/%v", intent, err)
	}
	var record gossip.EndpointRecord
	if err := json.Unmarshal(intent.Value, &record); err != nil {
		t.Fatal(err)
	}
	if len(record.Endpoints) != 1 || record.Endpoints[0].Address != "198.51.100.10" || record.Endpoints[0].Port != 33434 {
		t.Fatalf("collected endpoints = %#v", record.Endpoints)
	}
}
