package text

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/gossipview"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestWritePeerDebugUsesSharedDiagnostics(t *testing.T) {
	peer := gossipview.Peer{PeerID: "node-b.catofes.", SyncStatus: "synced", LastSyncUnix: 1700000000,
		PeerDiagnostics: observability.PeerDiagnostics{DatagramStats: &observability.PeerDatagramStats{ChunkFallbacks: 2}, ObjectPullStats: &observability.PeerObjectPullStats{LastFailure: &corestate.PeerFailure{Code: "gossip_object_pull_failed", Message: "older TCP error"}}},
	}
	var out strings.Builder
	if err := WritePeerDebug(&out, peer); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"status: synced", "last_success: 2023-11-14T22:13:20Z", "last_failure: -",
		`"chunk_fallbacks":2`, "older TCP error"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("missing %q in %s", want, out.String())
		}
	}
}
