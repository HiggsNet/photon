package photonwindows

import (
	"net/netip"
	"slices"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestGossipRouteTargetsIncludeLiveObservedAndGracePaths(t *testing.T) {
	now := time.Now()
	view := corestate.View{Gossip: &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		"live":    {ObservedEndpoint: "[2001:db8::2]:33434", ObservedUntilUnix: now.Add(time.Minute).Unix(), ObservedGraceEndpoints: []corestate.ObservedGraceEndpoint{{Endpoint: "192.0.2.3:33434", UntilUnix: now.Add(time.Minute).Unix()}, {Endpoint: "192.0.2.4:33434", UntilUnix: now.Add(-time.Minute).Unix()}}},
		"expired": {ObservedEndpoint: "192.0.2.5:33434", ObservedUntilUnix: now.Add(-time.Minute).Unix()},
	}}}
	got := gossipRouteTargets(view, now)
	for _, address := range []string{"2001:db8::2", "192.0.2.3"} {
		if !slices.Contains(got, netip.MustParseAddr(address)) {
			t.Fatal("missing control path", address, got)
		}
	}
	if len(got) != 2 {
		t.Fatal("expired hints retained", got)
	}
}
