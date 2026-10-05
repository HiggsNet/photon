package text

import (
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestWriteGossipPeersKeepsHistoryQueryable(t *testing.T) {
	peers := []inspect.PeerDebugView{{PeerID: "active.catofes.", Status: "online"}, {PeerID: "old.catofes.", Status: "offline", Historical: true}}
	for _, tc := range []struct {
		name, filter     string
		verbose, wantOld bool
		count            string
	}{
		{"default", "", false, false, "peers: 1"},
		{"explicit", "old.catofes.", false, true, "peers: 1/2"},
		{"verbose", "", true, true, "peers: 2"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var out strings.Builder
			if err := WriteGossipPeers(&out, peers, tc.filter, tc.verbose); err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.String(), "old.catofes.") != tc.wantOld || !strings.Contains(out.String(), tc.count+"\n") {
				t.Fatalf("unexpected output:\n%s", out.String())
			}
			if tc.verbose && !strings.Contains(out.String(), "historical: true") {
				t.Fatal("missing historical explanation")
			}
		})
	}
}

func TestWriteGossipPeersUsesGossipRuntimeFields(t *testing.T) {
	peers := []inspect.PeerDebugView{
		{
			PeerID: "node-a.catofes.", Source: "bootstrap", ResolvedAddr: "192.0.2.10:33434",
			Status: "online", LastSuccess: "2023-11-14T22:13:20Z", NextRetry: "-",
		},
		{
			PeerID: "node-b.catofes.", Source: "discovered", ResolvedAddr: "198.51.100.20:33434",
			Status: "backoff", LastSuccess: "never", NextRetry: "2023-11-14T22:14:20Z", LastFailure: &inspect.FailureView{Code: "timeout", Message: "ping timeout"},
			ObservedAddr: "198.51.100.21:33434", ObservedStatus: "active", LastUpdateSource: "pong",
		},
	}

	var summary strings.Builder
	if err := WriteGossipPeers(&summary, peers, "", false); err != nil {
		t.Fatalf("WriteGossipPeers summary: %v", err)
	}
	for _, want := range []string{"PEER", "SOURCE", "ENDPOINT", "STATUS", "LAST_SYNC", "NEXT_RETRY", "LAST_FAILURE", "192.0.2.10:33434", "ping timeout"} {
		if !strings.Contains(summary.String(), want) {
			t.Fatalf("summary missing %q:\n%s", want, summary.String())
		}
	}
	for _, unwanted := range []string{"LINKS", "desired_links", "up_links", "last_reconcile"} {
		if strings.Contains(summary.String(), unwanted) {
			t.Fatalf("summary contains transport field %q:\n%s", unwanted, summary.String())
		}
	}

	var verbose strings.Builder
	if err := WriteGossipPeers(&verbose, peers, "node-b", true); err != nil {
		t.Fatalf("WriteGossipPeers verbose: %v", err)
	}
	for _, want := range []string{"peers: 1/2", "peer_id: node-b.catofes.", "observed_addr: 198.51.100.21:33434", "last_update_source: pong", "datagram_too_large_dropped:"} {
		if !strings.Contains(verbose.String(), want) {
			t.Fatalf("verbose output missing %q:\n%s", want, verbose.String())
		}
	}
	if strings.Contains(verbose.String(), "node-a.catofes.") {
		t.Fatalf("filter leaked node-a:\n%s", verbose.String())
	}
}

func TestWritePeerLifecycleDebugNoPeers(t *testing.T) {
	var buf strings.Builder
	if err := WritePeerLifecycleDebug(&buf, inspect.PeerLifecycleDebugView{}); err != nil {
		t.Fatalf("WritePeerLifecycleDebug: %v", err)
	}
	if got := buf.String(); got != "no peers known\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestWritePeerLifecycleDebugSummaryAndSeverity(t *testing.T) {
	view := inspect.PeerLifecycleDebugView{
		Config: inspect.PeerLifecycleDebugConfig{
			StaleAfter:       15 * time.Minute,
			OfflineAfter:     12 * time.Hour,
			CleanupAfter:     48 * time.Hour,
			KeepSAWhileStale: true,
		},
		Peers: []inspect.PeerStatusInfo{
			{
				PeerID:            "node-b.catofes.",
				Zone:              "node-b.catofes.",
				State:             "revoked",
				Reason:            "zone_revoked",
				Detail:            "revoked by catofes.",
				LastSeenUnix:      1700000000,
				LastSyncUnix:      1700000001,
				LastReconcileUnix: 1700000002,
				DesiredLinks:      1,
				ActualLinks:       1,
				UpLinks:           0,
			},
			{
				PeerID:           "node-c.catofes.",
				Zone:             "node-c.catofes.",
				State:            "offline",
				Reason:           "cleanup_after_exceeded",
				OfflineSinceUnix: 1700000010,
				NextCleanupUnix:  1700000020,
			},
		},
	}

	var buf strings.Builder
	if err := WritePeerLifecycleDebug(&buf, view); err != nil {
		t.Fatalf("WritePeerLifecycleDebug: %v", err)
	}
	out := buf.String()
	out = strings.Join(strings.Fields(out), " ")
	for _, want := range []string{
		"summary: offline=1, revoked=1",
		"PEER ZONE STATE LINKS desired/actual/up SEVERITY REASON DETAIL",
		"node-b.catofes. node-b.catofes. revoked 1/1/0 critical (revoked) zone_revoked revoked by catofes.",
		"node-c.catofes. node-c.catofes. offline 0/0/0 warning (cleanup due) cleanup_after_exceeded",
		"node-b.catofes. 2023-11-14T22:13:20Z 2023-11-14T22:13:21Z 2023-11-14T22:13:22Z",
		"2023-11-14T22:13:30Z 2023-11-14T22:13:40Z",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}
