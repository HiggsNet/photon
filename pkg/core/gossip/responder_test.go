package gossip

import (
	"testing"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestPlanPingResponse(t *testing.T) {
	local := &corestate.CatalogSummary{CatalogRoot: []byte("local"), ZoneCount: 2}
	if messages := PlanPingResponse(nil, local); len(messages) != 0 {
		t.Fatalf("nil ping messages = %#v, want none", messages)
	}
	if messages := PlanPingResponse(&Ping{}, nil); len(messages) != 0 {
		t.Fatalf("nil local summary messages = %#v, want none", messages)
	}

	for _, test := range []struct {
		name  string
		ping  *Ping
		count int
	}{
		{"no_remote_summary", &Ping{}, 1},
		{"matching_root", &Ping{Summary: &corestate.CatalogSummary{CatalogRoot: []byte("local"), ZoneCount: 99}}, 1},
		{"different_root", &Ping{Summary: &corestate.CatalogSummary{CatalogRoot: []byte("remote"), ZoneCount: 2}}, 2},
	} {
		t.Run(test.name, func(t *testing.T) {
			messages := PlanPingResponse(test.ping, local)
			if len(messages) != test.count {
				t.Fatalf("messages = %#v, want %d", messages, test.count)
			}
			if messages[0].Type != MessagePong || messages[0].Pong == nil || messages[0].Pong.Summary != local {
				t.Fatalf("first response = %#v, want PONG with local summary", messages[0])
			}
			if test.count == 2 && (messages[1].Type != MessageFetchCatalogPage || messages[1].FetchCatalogPage == nil) {
				t.Fatalf("second response = %#v, want FETCH_CATALOG_PAGE", messages[1])
			}
		})
	}
}

func TestCatalogRootsMatchRequiresNonNilSummaries(t *testing.T) {
	root := &corestate.CatalogSummary{CatalogRoot: []byte("root")}
	if CatalogRootsMatch(nil, root) || CatalogRootsMatch(root, nil) {
		t.Fatal("nil catalog summary matched")
	}
	if !CatalogRootsMatch(root, &corestate.CatalogSummary{CatalogRoot: []byte("root"), ZoneCount: 99}) {
		t.Fatal("equal catalog roots did not match")
	}
}
