package text

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestWritePeerDebug(t *testing.T) {
	view := inspect.PeerDebugView{
		PeerID:           "node-b.catofes.",
		Source:           "bootstrap",
		ConfiguredAddr:   "127.0.0.1:9999",
		ResolvedAddr:     "127.0.0.1:2000",
		Status:           "online",
		LastSuccess:      "2023-11-14T22:13:20Z",
		Backoff:          "-",
		NextRetry:        "-",
		KnownEndpoint:    "127.0.0.1:2000",
		DiscoveredAddr:   "127.0.0.1:2000",
		ObservedAddr:     "127.0.0.1:3000",
		ObservedStatus:   "active until=2023-11-14T22:14:20Z",
		LastUpdateSource: "node-c.catofes.",
		LastRelay:        "2023-11-14T22:13:20Z",
		RelaySuppression: "relay_fanout_limited",
		SyncFlow: inspect.PeerSyncFlowView{
			ActivePullState:     "object_pulling",
			ActivePullLastEvent: "catalog_page",
			ActivePullUpdated:   "2023-11-14T22:13:20Z",
			LastHint:            "2023-11-14T22:13:20Z",
			LastHintReason:      "announce_hint",
			LastHintSuppression: "session_active",
			LastResponder:       "2023-11-14T22:13:20Z",
			LastResponderKind:   "chunk_fallback",
			LastResponderZone:   "node-b.catofes.",
		},
		DatagramStats: inspect.PeerDatagramStatsView{
			TooLargeDropped:       2,
			LastTooLarge:          "2023-11-14T22:13:20Z",
			LastTooLargeDirection: "send",
			LastTooLargeObject:    "record",
			LastTooLargeZone:      "node-b.catofes.",
			LastTooLargeKey:       "bigdata",
			LastTooLargeBytes:     1800,
			LastTooLargeLimit:     1200,
		},
		ObjectPullStats: inspect.PeerObjectPullStatsView{
			Attempts:        3,
			Last:            "2023-11-14T22:13:20Z",
			LastObject:      "record",
			LastZone:        "node-b.catofes.",
			LastKey:         "bigdata",
			LastBytes:       4096,
			LastSourcePeer:  "node-b.catofes.",
			LastUnreachable: true,
			LastFailure:     &inspect.FailureView{Code: inspect.FailureCodeGossipObjectPull, Message: "no TCP address"},
		},
	}
	var buf strings.Builder
	if err := WritePeerDebug(&buf, view); err != nil {
		t.Fatalf("WritePeerDebug: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"peer_id: node-b.catofes.",
		"source: bootstrap",
		"configured_addr: 127.0.0.1:9999",
		"observed_status: active",
		"active_pull_state: object_pulling",
		"datagram_too_large_dropped: 2",
		"datagram_last_too_large: 2023-11-14T22:13:20Z direction=send object=record zone=node-b.catofes. key=bigdata bytes=1800 limit=1200",
		"object_pull_attempts: 3",
		"object_pull_last: 2023-11-14T22:13:20Z object=record zone=node-b.catofes. key=bigdata bytes=4096 source_peer=node-b.catofes. unreachable=true failure=code=gossip_object_pull_failed message=no TCP address",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
