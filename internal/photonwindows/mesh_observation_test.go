package photonwindows

import (
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestMeshObservationRendersDetachedPeer(t *testing.T) {
	f, leaf := observationFixture(t)
	peer := &meshPeer{config: *f.config, plan: f.plan, tunnel: f.p.tunnel, leaf: leaf}
	peer.config.Gateway.AllowedZones = []zone.ZonePath{f.plan.Selected.Zone}
	peer.plan.outerFamily = "ipv4"
	view := detachedPacketPolicyView(f.view)
	snapshot := meshObservationSnapshot{at: f.now, revision: view.Revision, plan: f.plan,
		peers: []meshPeerSnapshot{captureMeshPeer(peer, f.now)}}
	// The worker can finish this sample after the owner changes the tunnel.
	peer.tunnel.expiresAt = f.now.Add(-time.Second)
	leaf.pipeline = nil
	report := snapshot.render(f.config, view, nil, new(photoncrypto.Verifier))
	if !report.TunnelReady || !report.IKE.ChildLive || !report.Babel.Live ||
		len(report.Babel.Routes) != 1 || len(report.Connections) != 1 {
		t.Fatalf("snapshot lost live peer after capture: %+v", report)
	}
	if route := report.Babel.Routes[0]; route.Peer != string(f.plan.Selected.Zone) ||
		route.OuterFamily != "ipv4" || route.NextHop != f.p.peer {
		t.Fatalf("route lost next-hop connection metadata: %+v", route)
	}

	snapshot.peers[0] = captureMeshPeer(peer, f.now)
	report = snapshot.render(f.config, view, nil, new(photoncrypto.Verifier))
	if report.TunnelReady || report.IKE.ChildLive || report.Babel.Live || len(report.Babel.Routes) != 0 {
		t.Fatalf("new snapshot reported expired CHILD as usable: %+v", report)
	}
}
