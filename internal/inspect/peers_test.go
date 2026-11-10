package inspect

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

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
