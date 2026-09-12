package http

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestPeersResponsePreservesObserverSchema(t *testing.T) {
	peerView := inspect.BuildPeerViewFromCheckpoint(
		"node-b.catofes.",
		"192.0.2.10:33434",
		[]inspect.PeerEndpointView{{Addr: "192.0.2.10:33434", Source: "bootstrap", Selected: true}},
		corestate.PeerCheckpoint{
			LastSyncUnix:     900,
			LastAttemptUnix:  850,
			BackoffUntilUnix: 950,
			LastRelayUnix:    920,
			FailureCount:     2,
			ObservedEndpoint: "198.51.100.9:33434",
			LastFailure:      &corestate.PeerFailure{Code: corestate.PeerFailureTimeout, Message: "sync timed out", AtUnix: 940},
		},
		observability.PeerDiagnostics{
			LastUpdateSource:      "announce",
			LastRelaySuppression:  "relay_fanout_limited",
			LastRelaySuppressedAt: 910,
			ObservedSource:        "verified_packet",
			DatagramStats:         &observability.PeerDatagramStats{ChunkFallbacks: 2},
			ObjectPullStats:       &observability.PeerObjectPullStats{Failures: 1, LastFailure: errors.New("TCP unavailable")},
		},
	)
	got := PeersResponse{Peers: []PeerJSON{peerView}}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	peers := decoded["peers"].([]any)
	peer := peers[0].(map[string]any)
	if peer["peer_id"] != "node-b.catofes." || peer["configured_addr"] != "192.0.2.10:33434" {
		t.Fatalf("peer fields missing: %#v", peer)
	}
	if peer["endpoints"] == nil || peer["datagram_stats"] == nil {
		t.Fatalf("endpoint/diagnostic fields missing: %#v", peer)
	}
	if _, ok := peer["last_error"]; ok {
		t.Fatalf("legacy last_error leaked into peer schema: %#v", peer)
	}
	failure := peer["last_failure"].(map[string]any)
	if failure["code"] != "timeout" || failure["message"] != "sync timed out" {
		t.Fatalf("peer failure missing stable code/message: %#v", failure)
	}
	objectPull := peer["object_pull_stats"].(map[string]any)
	objectPullFailure := objectPull["last_failure"].(map[string]any)
	if objectPullFailure["code"] != inspect.FailureCodeGossipObjectPull || objectPullFailure["message"] != "TCP unavailable" {
		t.Fatalf("object-pull failure missing stable code/message: %#v", objectPullFailure)
	}
}

func TestPeersResponseKeepsZeroValueSchemaFields(t *testing.T) {
	peerView := inspect.BuildPeerViewFromCheckpoint("node-b.catofes.", "", nil, corestate.PeerCheckpoint{}, observability.PeerDiagnostics{})
	got := PeersResponse{Peers: []PeerJSON{peerView}}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	peers := decoded["peers"].([]any)
	peer := peers[0].(map[string]any)
	for _, field := range []string{"last_sync_unix", "last_attempt_unix", "backoff_until_unix", "failure_count"} {
		if _, ok := peer[field]; !ok {
			t.Fatalf("zero-value schema field %q missing: %#v", field, peer)
		}
	}
}
