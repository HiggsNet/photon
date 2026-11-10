package text

import (
	"bytes"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestWriteSyncStatusVerbose(t *testing.T) {
	view := inspect.SyncStatusView{
		PeerID:       "node-a.catofes.",
		ListenAddr:   "127.0.0.1:0",
		KnownPeers:   1,
		KnownZones:   2,
		LocalRootHex: "abcd",
		Limits: inspect.SyncLimitsView{
			MaxDatagramBytes: 4096,
			MaxSyncZones:     8,
			MaxSyncRecords:   64,
			WireVersion:      1,
			WireCodec:        "msgpack",
		},
		Verbose:         true,
		AllowlistSource: "bootstrap+discovery",
		BootstrapPeers:  1,
		DiscoveredPeers: 1,
		Bootstrap: []inspect.SyncVerbosePeerView{{
			PeerDebugView: inspect.PeerDebugView{
				PeerID:           "node-b.catofes.",
				ConfiguredAddr:   "127.0.0.1:9999",
				ResolvedAddr:     "127.0.0.1:9999",
				Status:           "ok",
				LastSuccess:      "2023-11-14T22:13:20Z",
				NextRetry:        "-",
				LastUpdateSource: "node-c.catofes.",
				LastRelay:        "2023-11-14T22:13:20Z",
				RelaySuppression: "-",
				ObservedAddr:     "127.0.0.1:3000",
				ObservedStatus:   "active",
				SyncFlow: inspect.PeerSyncFlowView{
					ActivePullState:     "object_pulling",
					ActivePullLastEvent: "catalog_page",
					ActivePullUpdated:   "2023-11-14T22:13:20Z",
					HintAccepted:        2,
					HintSuppressed:      1,
					LastHint:            "2023-11-14T22:13:20Z",
					LastHintReason:      "ping_summary",
					LastHintSuppression: "session_active",
					ReadOnlyResponder:   3,
					LastResponder:       "2023-11-14T22:13:20Z",
					LastResponderKind:   "chunk_fallback",
					LastResponderZone:   "node-b.catofes.",
				},
				DatagramStats: inspect.PeerDatagramStatsView{
					TooLargeDropped:     2,
					DigestOnlyAnnounces: 1,
					LastTooLarge:        "2023-11-14T22:13:20Z",
					LastTooLargeObject:  "record",
				},
				ObjectPullStats: inspect.PeerObjectPullStatsView{
					Attempts:   3,
					Successes:  2,
					Failures:   1,
					Last:       "2023-11-14T22:13:20Z",
					LastObject: "record",
				},
			},
		}},
		Discovered: []inspect.SyncVerbosePeerView{{
			PeerDebugView: inspect.PeerDebugView{
				PeerID:         "node-c.catofes.",
				Status:         "new",
				LastSuccess:    "never",
				LastRelay:      "never",
				ObservedStatus: "-",
			},
			Addr: "127.0.0.1:2000",
		}},
		Peers: []inspect.SyncPeerSummaryView{{
			PeerID:     "node-b.catofes.",
			Addr:       "127.0.0.1:9999",
			Status:     "ok",
			LastSync:   "2023-11-14T22:13:20Z",
			KnownZones: 2,
			NextRetry:  "-",
		}},
		Zones: []inspect.SyncZoneSummaryView{{
			Zone:        "node-b.catofes.",
			RootHex:     "beef",
			Records:     1,
			History:     2,
			Delegations: 3,
			Revocations: 4,
		}},
	}

	var buf bytes.Buffer
	if err := WriteSyncStatus(&buf, view); err != nil {
		t.Fatalf("WriteSyncStatus: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"peer_id: node-a.catofes.",
		"limits: max_datagram_bytes=4096 max_sync_zones=8 max_sync_records=64 wire_version=1 wire_codec=msgpack",
		"bootstrap peer=node-b.catofes. configured_addr=127.0.0.1:9999 resolved_addr=127.0.0.1:9999 status=ok",
		"sync_flow peer=node-b.catofes. active_pull=object_pulling active_event=catalog_page",
		"datagram peer=node-b.catofes. too_large_dropped=2 digest_only_announces=1",
		"object_pull peer=node-b.catofes. attempts=3 successes=2 failures=1",
		"discovered peer=node-c.catofes. addr=127.0.0.1:2000 status=new last_success=never",
		"peer node-b.catofes. addr=127.0.0.1:9999 status=ok last_sync=2023-11-14T22:13:20Z known_zones=2",
		"zone node-b.catofes. root=beef records=1 history=2 delegations=3 revocations=4",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
