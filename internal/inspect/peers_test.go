package inspect

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestBuildPeerIDsMergesFiltersAndSorts(t *testing.T) {
	got := BuildPeerIDs(PeerSetInput{
		RuntimeIDs:   []string{"node-c.catofes.", "node-a.catofes.", "self.catofes."},
		BootstrapIDs: []string{"node-b.catofes.", "node-a.catofes."},
		SignedIDs:    []string{"node-d.catofes.", "self.catofes."},
		LocalIDs:     []string{"self.catofes."},
	})
	want := []string{"node-a.catofes.", "node-b.catofes.", "node-c.catofes.", "node-d.catofes."}
	if len(got) != len(want) {
		t.Fatalf("len = %d, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q; all=%+v", i, got[i], want[i], got)
		}
	}
}

func TestSortZoneStringsGroupsDotAndHyphenSuffixes(t *testing.T) {
	got := []string{
		"a-sha.catofes.",
		"b-pek.catofes.",
		"alpha.catofes.",
		"foo.pek.catofes.",
		"deep.a-pek.catofes.",
		"catofes.",
		"a-pek.catofes.",
		".",
	}
	SortZoneStrings(got)
	want := []string{
		".",
		"catofes.",
		"alpha.catofes.",
		"a-pek.catofes.",
		"deep.a-pek.catofes.",
		"b-pek.catofes.",
		"foo.pek.catofes.",
		"a-sha.catofes.",
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got[%d] = %q, want %q; all=%+v", i, got[i], want[i], got)
		}
	}
}

func TestPeerKnownExcludesLocalPeer(t *testing.T) {
	input := PeerSetInput{
		RuntimeIDs:   []string{"node-a.catofes.", "self.catofes."},
		BootstrapIDs: []string{"node-b.catofes."},
		SignedIDs:    []string{"node-c.catofes."},
		LocalIDs:     []string{"self.catofes."},
	}
	for _, peerID := range []string{"node-a.catofes.", "node-b.catofes.", "node-c.catofes."} {
		if !PeerKnown(input, peerID) {
			t.Fatalf("PeerKnown(%s) = false, want true", peerID)
		}
	}
	if PeerKnown(input, "self.catofes.") {
		t.Fatal("local peer should not be known as observable remote peer")
	}
	if PeerKnown(input, "unknown.catofes.") {
		t.Fatal("unknown peer should not be known")
	}
}

func TestBuildPeerEndpointsMergesAndSortsSources(t *testing.T) {
	got := BuildPeerEndpoints(PeerEndpointInput{
		BootstrapAddr:  "192.0.2.10:33434",
		SelectedAddr:   "203.0.113.20:33434",
		ObservedAddr:   "198.51.100.9:33434",
		ObservedSource: "verified_packet",
		Signed: []PeerSignedEndpoint{{
			Address:      "203.0.113.20",
			Port:         33434,
			Scope:        "global",
			Source:       "advertise",
			Priority:     100,
			LastObserved: 900,
		}},
		Grace: []PeerGraceEndpoint{{Addr: "198.51.100.8:33434"}},
	})
	if len(got) != 5 {
		t.Fatalf("len = %d, want 5: %+v", len(got), got)
	}
	if got[0].Addr != "203.0.113.20:33434" || !got[0].Selected {
		t.Fatalf("first endpoint = %+v, want selected signed endpoint", got[0])
	}
	var sawBootstrap, sawObserved, sawGrace bool
	for _, ep := range got {
		switch {
		case ep.Addr == "192.0.2.10:33434" && ep.Source == "bootstrap":
			sawBootstrap = true
		case ep.Addr == "198.51.100.9:33434" && ep.Source == "verified_packet":
			sawObserved = true
		case ep.Addr == "198.51.100.8:33434" && ep.Source == "observed_grace":
			sawGrace = true
		}
	}
	if !sawBootstrap || !sawObserved || !sawGrace {
		t.Fatalf("missing endpoint sources: %+v", got)
	}
}

func TestBuildPeerEndpointsDeduplicatesByAddrAndSource(t *testing.T) {
	got := BuildPeerEndpoints(PeerEndpointInput{
		SelectedAddr: "203.0.113.20:33434",
		Signed: []PeerSignedEndpoint{
			{Address: "203.0.113.20", Port: 33434, Source: "advertise"},
			{Address: "203.0.113.20", Port: 33434, Source: "advertise"},
		},
	})
	var advertise int
	for _, ep := range got {
		if ep.Source == "advertise" {
			advertise++
			if !ep.Selected {
				t.Fatalf("deduped advertise endpoint lost selected flag: %+v", ep)
			}
		}
	}
	if advertise != 1 {
		t.Fatalf("advertise endpoints = %d, want 1: %+v", advertise, got)
	}
}

func TestBuildEndpointDebugProjectsVerifiedEndpointRecords(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	endpointRecord := func(entries []gossip.EndpointEntry) []byte {
		value, err := json.Marshal(gossip.EndpointRecord{UpdatedAt: now.Unix(), TTL: 3600, Endpoints: entries})
		if err != nil {
			t.Fatal(err)
		}
		return value
	}
	network := zone.NewNetworkState()
	for peerID, entries := range map[zone.ZonePath][]gossip.EndpointEntry{
		"node-c.catofes.": {{Address: "198.51.100.30", Port: 33434}},
		"node-b.catofes.": {
			{Address: "198.51.100.10", Port: 33434, Priority: 50, LastObserved: now.Add(-3 * time.Minute).Unix()},
			{Address: "198.51.100.20", Port: 33434, Priority: 100, LastObserved: now.Add(-2 * time.Minute).Unix()},
			{Address: "198.51.100.30", Port: 33434, Priority: 100, LastObserved: now.Add(-time.Minute).Unix()},
		},
	} {
		network.Zones[peerID] = &zone.ZoneState{Path: peerID, Records: map[string]*zone.Record{
			gossip.EndpointRecordKeyUDP: {Zone: peerID, Key: gossip.EndpointRecordKeyUDP, Value: endpointRecord(entries), Timestamp: now.Unix()},
		}}
	}
	got := BuildEndpointDebug(&corestate.VerifiedState{ManagedZone: "node-b.catofes.", Network: network}, now)
	if got.ManagedPeerID != "node-b.catofes." {
		t.Fatalf("ManagedPeerID = %q", got.ManagedPeerID)
	}
	if len(got.Peers) != 2 {
		t.Fatalf("Peers len = %d, want 2: %+v", len(got.Peers), got.Peers)
	}
	if got.Peers[0].PeerID != "node-b.catofes." || got.Peers[1].PeerID != "node-c.catofes." {
		t.Fatalf("Peers not sorted: %+v", got.Peers)
	}
	endpoints := got.Peers[0].Endpoints
	if len(endpoints) != 3 {
		t.Fatalf("node-b endpoints len = %d, want 3: %+v", len(endpoints), endpoints)
	}
	if endpoints[0].Address != "198.51.100.30" || endpoints[1].Address != "198.51.100.20" || endpoints[2].Address != "198.51.100.10" {
		t.Fatalf("node-b endpoints not sorted by priority/last_observed: %+v", endpoints)
	}
}

func TestBuildEndpointDebugHandlesMissingVerifiedState(t *testing.T) {
	got := BuildEndpointDebug(nil, time.Now())
	if len(got.Peers) != 0 || got.ManagedPeerID != "" {
		t.Fatalf("view = %+v, want empty", got)
	}
}

func TestBuildPeerDebugFormatsRuntimeDiagnostics(t *testing.T) {
	now := time.Unix(1700000000, 0)
	got := BuildPeerDebug(PeerDebugInput{
		PeerID:               "node-b.catofes.",
		Source:               "bootstrap",
		ConfiguredAddr:       "127.0.0.1:9999",
		ResolvedAddr:         "127.0.0.1:2000",
		LastSyncUnix:         now.Add(-time.Minute).Unix(),
		BackoffUntilUnix:     now.Add(30 * time.Second).Unix(),
		DiscoveredAddr:       "127.0.0.1:2000",
		ObservedAddr:         "127.0.0.1:3000",
		ObservedUntilUnix:    now.Add(time.Hour).Unix(),
		ObservedLastSeenUnix: now.Unix(),
		ObservedLastSyncUnix: now.Add(-time.Minute).Unix(),
		ObservedFailureCount: 2,
		LastRelayUnix:        now.Add(-2 * time.Minute).Unix(),
		Diagnostics: observability.PeerDiagnostics{
			ObservedSource:        "PING",
			LastUpdateSource:      "node-c.catofes.",
			LastRelaySuppression:  "relay_throttled",
			LastRelaySuppressedAt: now.Add(-time.Minute).Unix(),
			ActivePullState:       "object_pulling",
			DatagramStats:         &observability.PeerDatagramStats{TooLargeDropped: 2},
			ObjectPullStats:       &observability.PeerObjectPullStats{Attempts: 3},
		},
		Now: now,
	})

	if got.PeerID != "node-b.catofes." || got.Source != "bootstrap" || got.ResolvedAddr != "127.0.0.1:2000" {
		t.Fatalf("identity fields = %+v", got)
	}
	if got.Status != "backoff" || got.Backoff != "30s" || got.NextRetry == "-" {
		t.Fatalf("retry fields = status=%q backoff=%q next=%q", got.Status, got.Backoff, got.NextRetry)
	}
	if !strings.Contains(got.ObservedStatus, "active until=") || !strings.Contains(got.ObservedStatus, "failures=2 source=PING") {
		t.Fatalf("observed status = %q", got.ObservedStatus)
	}
	if !strings.Contains(got.RelaySuppression, "relay_throttled at=") {
		t.Fatalf("relay suppression = %q", got.RelaySuppression)
	}
	if got.SyncFlow.ActivePullState != "object_pulling" || got.DatagramStats.TooLargeDropped != 2 || got.ObjectPullStats.Attempts != 3 {
		t.Fatalf("nested diagnostics = %+v", got)
	}
}

func TestBuildPeerRuntimeDiagnosticViewsFormatTimestamps(t *testing.T) {
	now := time.Unix(1700000000, 0)

	flow := BuildPeerSyncFlowFromObservability(observability.PeerDiagnostics{
		ActivePullUpdatedUnix: now.Unix(),
		LastHintUnix:          now.Add(-time.Minute).Unix(),
		LastResponderUnix:     now.Add(-2 * time.Minute).Unix(),
	})
	if flow.ActivePullUpdated != "2023-11-14T22:13:20Z" || flow.LastHint == "never" || flow.LastResponder == "never" {
		t.Fatalf("sync flow timestamps = %+v", flow)
	}

	datagram := BuildPeerDatagramStats(&observability.PeerDatagramStats{
		LastCatalogUnix:  now.Unix(),
		LastTooLargeUnix: now.Add(-time.Minute).Unix(),
	})
	if datagram.LastCatalog != "2023-11-14T22:13:20Z" || datagram.LastTooLarge == "never" {
		t.Fatalf("datagram timestamps = %+v", datagram)
	}

	objectPull := BuildPeerObjectPullStats(&observability.PeerObjectPullStats{
		LastUnix:    now.Unix(),
		LastFailure: errors.New("object unavailable"),
	})
	if objectPull.Last != "2023-11-14T22:13:20Z" || objectPull.LastFailure == nil || objectPull.LastFailure.Code != FailureCodeGossipObjectPull {
		t.Fatalf("object pull timestamp = %+v", objectPull)
	}
}
