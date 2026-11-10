package text

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/gossipview"
)

func TestWriteSyncStatusUsesSharedView(t *testing.T) {
	view := gossipview.View{PeerID: "node-a.catofes.", CatalogRoot: "abc", ZoneCount: 2, Peers: []gossipview.Peer{
		{PeerID: "node-b.catofes.", Source: "discovered", DiscoveredAddr: "192.0.2.1:33434", SyncStatus: "backoff", LastSyncUnix: 1700000000},
	}}
	var out strings.Builder
	if err := WriteSyncStatus(&out, view, true); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"known_zones: 2", "local_root: abc", "discovered peer=node-b.catofes.",
		"status=backoff last_sync=2023-11-14T22:13:20Z", "status: backoff"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
}
