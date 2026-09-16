package main

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestEndpointProtocolIntentCollectsPlatformCandidates(t *testing.T) {
	verified, _, _, config := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	config.PeerID = string(verified.ManagedZone)
	config.ListenAddr = "127.0.0.1:33434"
	config.AdvertiseAddrs = []string{"198.51.100.10:33434"}
	config.EndpointDiscovery = "advertise_only"
	config.Reflectors = nil
	now := time.Unix(1000, 0)

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
	for _, endpoint := range record.Endpoints {
		if endpoint.Address == "198.51.100.10" && endpoint.Port == 33434 {
			return
		}
	}
	t.Fatalf("advertised endpoint missing from collected endpoints: %#v", record.Endpoints)
}
