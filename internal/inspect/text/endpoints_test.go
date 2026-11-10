package text

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/gossipview"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestWriteEndpointsDebug(t *testing.T) {
	view := gossipview.View{
		ManagedZone: "node-b.catofes.",
		LocalEndpoints: []gossip.EndpointEntry{{
			Address: "198.51.100.20", Port: 33434, Scope: "global",
			Priority: 100, Protocol: "udp", Source: "signed", LastObserved: 1700000000,
		}},
		Peers: []gossipview.Peer{
			{PeerID: "node-a.catofes.", Endpoints: []gossipview.Endpoint{
				{Addr: "198.51.100.21:33434", EndpointEntry: gossip.EndpointEntry{Address: "198.51.100.21", Port: 33434}},
				{Addr: "192.0.2.10:33434", EndpointEntry: gossip.EndpointEntry{Source: "bootstrap"}},
			}},
			{PeerID: "node-c.catofes.", Endpoints: []gossipview.Endpoint{{Addr: "192.0.2.11:33434"}}},
		},
	}
	var buf strings.Builder
	if err := WriteEndpointsDebug(&buf, view); err != nil {
		t.Fatalf("WriteEndpointsDebug: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"published_peers: 2",
		"peer node-b.catofes. endpoints=1 local=true",
		"peer node-a.catofes. endpoints=1 local=false",
		"endpoint addr=198.51.100.20 port=33434 scope=global priority=100 protocol=udp source=signed last_observed=2023-11-14T22:13:20Z",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "node-c.catofes.") || strings.Contains(output, "source=bootstrap") {
		t.Fatalf("non-published endpoints in output:\n%s", output)
	}
}
