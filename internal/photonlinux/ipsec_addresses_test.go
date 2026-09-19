package photonlinux

import (
	"encoding/json"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestIPsecAddressPublicationPriorityAndLeaseBoundary(t *testing.T) {
	now := time.Unix(5000, 0)
	endpoints := &gossip.EndpointRecord{TTL: 60, GraceSeconds: 10, Endpoints: []gossip.EndpointEntry{
		{Address: "192.0.2.1", Source: "reflector", Priority: 50},
		{Address: "192.0.2.3", Source: "reflector+interface", Priority: 42, LastObserved: 4930},
		{Address: "192.0.2.4", Source: "reflector", LastObserved: 4929},
		{Address: "10.0.0.1", Source: "interface", Scope: "private", Priority: 12},
		{Address: "invalid"},
	}}
	before, err := json.Marshal(endpoints)
	if err != nil {
		t.Fatal(err)
	}
	got := BuildIPsecAddressRecord([]string{"192.0.2.1"}, []string{"192.0.2.1:123", "[2001:db8::1]:456"}, []string{" vpn.example ", "vpn.example"}, "127.0.0.1:99", endpoints, now)
	if len(got.Addresses) != 5 {
		t.Fatalf("addresses = %+v", got.Addresses)
	}
	wantPriorities := []int{100, 99, 98, 42, 12}
	for i, address := range got.Addresses {
		if int(address.Priority) != wantPriorities[i] {
			t.Fatalf("priority at %d = %d", i, address.Priority)
		}
	}
	if got.Addresses[0].Source != ipsec.SourceManualAddress || got.Addresses[2].Host != "vpn.example" || got.Addresses[3].Address != "192.0.2.3" || got.Addresses[3].Source != ipsec.SourceReflector || got.Addresses[4].Reachability != ipsec.ReachabilityPrivate || got.Addresses[4].Source != ipsec.SourceLocal {
		t.Fatalf("source order/classification = %+v", got.Addresses)
	}
	// At exact expiry the entry remains; one nanosecond later it is removed.
	later := BuildIPsecAddressRecord(nil, nil, nil, "", endpoints, now.Add(time.Nanosecond))
	for _, address := range later.Addresses {
		if address.Address == "192.0.2.3" {
			t.Fatal("expired endpoint retained")
		}
	}
	after, _ := json.Marshal(endpoints)
	if string(before) != string(after) {
		t.Fatal("mutated gossip record")
	}
	// Lease renewal must not refresh declaration timestamps.
	endpoints.Endpoints[1].LastObserved++
	refreshed := BuildIPsecAddressRecord([]string{"192.0.2.1"}, []string{"192.0.2.1:123", "[2001:db8::1]:456"}, []string{"vpn.example"}, "", endpoints, now)
	if !reflect.DeepEqual(got, refreshed) {
		t.Fatal("lease renewal changed IPsec declaration")
	}
}

func TestIPsecAddressPublicationFallbackAndDefaultTTL(t *testing.T) {
	now := time.Unix(5000, 0)
	for _, tc := range []struct{ listen, address string }{
		{"0.0.0.0:123", ""}, {"[::]:123", ""}, {"", ""},
		{"[2001:db8::1]:123", "2001:db8::1"}, {"[2001:db8::1]", "2001:db8::1"},
		{"192.0.2.1:123", "192.0.2.1"}, {"host.example:123", ""},
	} {
		t.Run(tc.listen, func(t *testing.T) {
			got := BuildIPsecAddressRecord(nil, nil, nil, tc.listen, nil, now)
			if tc.address == "" {
				if len(got.Addresses) != 0 {
					t.Fatalf("unexpected fallback: %+v", got)
				}
			} else if len(got.Addresses) != 1 || got.Addresses[0].Address != tc.address || got.Addresses[0].ID != "listen" {
				t.Fatalf("fallback: %+v", got)
			}
		})
	}
	endpoints := &gossip.EndpointRecord{Endpoints: []gossip.EndpointEntry{
		{Address: "192.0.2.1", LastObserved: now.Add(-gossip.DefaultEndpointTTL).Unix(), Source: "advertise"},
		{Address: "192.0.2.2", LastObserved: now.Add(-gossip.DefaultEndpointTTL - time.Second).Unix()},
		{Address: "2001:db8::1", Source: "interface", Scope: "global"},
	}}
	got := BuildIPsecAddressRecord(nil, nil, nil, "", endpoints, now)
	if len(got.Addresses) != 2 || got.Addresses[0].Source != ipsec.SourceManualAddress || got.Addresses[1].Source != ipsec.SourceDiscovery {
		t.Fatalf("default TTL or source mapping: %+v", got)
	}
}
