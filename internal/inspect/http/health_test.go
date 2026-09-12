package http

import (
	"encoding/json"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestHealthResponsePreservesObserverSchema(t *testing.T) {
	got := HealthResponse{
		Datasource: map[string]any{"kind": "local_spool"},
		Links: []HealthContextItem{{
			Health:          inspect.HealthSample{InstanceID: "link-1", State: "unknown"},
			PeerZone:        "node-b.catofes.",
			GroupID:         "blue",
			InterfaceName:   "phx0",
			Endpoint:        "198.51.100.10:4500",
			ActualState:     "up",
			LocalTunnelAddr: "fd00::1%phx0",
			PeerTunnelAddr:  "fd00::2%phx0",
		}},
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	links := decoded["links"].([]any)
	item := links[0].(map[string]any)
	if item["peer_zone"] != "node-b.catofes." || item["health"] == nil {
		t.Fatalf("health context fields missing: %#v", item)
	}
}

func TestHealthSeriesResponsePreservesObserverSchema(t *testing.T) {
	got := HealthSeriesResponse{
		Datasource: map[string]any{"kind": "local_spool"},
		LinkID:     "link-1",
		Series:     map[string]any{"metric": "rtt"},
	}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded["link_id"] != "link-1" || decoded["series"] == nil {
		t.Fatalf("series response fields missing: %#v", decoded)
	}
}

func TestBuildHealthContextMergesRuntimeContextAndMissingLinks(t *testing.T) {
	got := BuildHealthContext(HealthContextInput{
		View: inspect.HealthView{Samples: []inspect.HealthSample{{
			InstanceID: "link-b", ProbeRole: "staged", InterfaceName: "health-if", State: "healthy",
		}}},
		Instances: map[string]HealthInstanceContextInput{
			"link-a": {
				ID:            "link-a",
				PeerZone:      "node-a.catofes.",
				GroupID:       "blue",
				InterfaceName: "phx-a",
				Endpoint:      "198.51.100.10:4500",
				ActualState:   "up",
				Instance:      map[string]any{"id": "link-a"},
			},
			"link-b": {
				ID:            "link-b",
				PeerZone:      "node-b.catofes.",
				GroupID:       "blue",
				InterfaceName: "phx-b",
				Endpoint:      "198.51.100.11:4500",
				ActualState:   "up",
				Instance:      map[string]any{"id": "link-b"},
			},
		},
		Desired: map[string]HealthDesiredContextInput{
			"link-a": {
				InstanceID:      "link-a",
				PeerZone:        "node-a.catofes.",
				GroupID:         "blue",
				InterfaceName:   "desired-a",
				LocalTunnelAddr: "fd00::1",
				PeerTunnelAddr:  "fd00::2",
				Desired:         map[string]any{"instance_id": "link-a"},
			},
			"link-b": {
				InstanceID:      "link-b",
				LocalTunnelAddr: "fd00::3",
				PeerTunnelAddr:  "fd00::4",
				Desired:         map[string]any{"instance_id": "link-b"},
			},
		},
	})

	if len(got) != 2 {
		t.Fatalf("context len = %d, want 2: %#v", len(got), got)
	}
	if got[0].Health.InstanceID != "link-a" || got[0].PeerZone != "node-a.catofes." || got[0].InterfaceName != "phx-a" {
		t.Fatalf("missing-link context = %#v", got[0])
	}
	if got[0].Health.State != "unknown" {
		t.Fatalf("missing-link health = %#v, want unknown map", got[0].Health)
	}
	if got[1].Health.InstanceID != "link-b" || got[1].Health.ProbeRole != "staged" {
		t.Fatalf("existing health sort keys = %#v", got[1])
	}
	if got[1].InterfaceName != "health-if" {
		t.Fatalf("interface = %q, want health interface override", got[1].InterfaceName)
	}
	if got[1].LocalTunnelAddr != "fd00::3" || got[1].PeerTunnelAddr != "fd00::4" {
		t.Fatalf("desired tunnel context missing: %#v", got[1])
	}
}

func TestBuildHealthContextUsesCanonicalUnknownSample(t *testing.T) {
	got := BuildHealthContext(HealthContextInput{
		Instances: map[string]HealthInstanceContextInput{
			"link-a": {ID: "link-a"},
		},
	})
	if len(got) != 1 {
		t.Fatalf("context len = %d, want 1", len(got))
	}
	if got[0].Health.InstanceID != "link-a" || got[0].Health.State != "unknown" {
		t.Fatalf("health = %#v, want canonical unknown sample", got[0].Health)
	}
}
