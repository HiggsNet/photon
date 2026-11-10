package main

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/HiggsNet/photon/internal/gossipview"
	"github.com/HiggsNet/photon/internal/photonwindows"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func TestDesktopDashboardNodes(t *testing.T) {
	o := &photonwindows.Observation{Running: true, View: gossipview.View{Peers: []gossipview.Peer{
		{PeerID: "alpha.example.", SyncStatus: "synced"},
		{PeerID: "zulu.example.", SyncStatus: "retry_pending"},
		{PeerID: "middle.example.", SyncStatus: "syncing"},
	}}, Connections: []photonwindows.ConnectionObservation{
		{Peer: "alpha.example.", IKE: photonwindows.IKEObservation{Live: true, ChildLive: true}, BabelLive: true, TunnelReady: true},
		{Peer: "zulu.example.", IKE: photonwindows.IKEObservation{Live: true, ChildLive: true}, BabelLive: true, TunnelReady: true},
		{Peer: "middle.example.", IKE: photonwindows.IKEObservation{AttemptActive: true}},
	}, Babel: photonwindows.BabelObservation{Routes: []photonwindows.RouteObservation{
		{Peer: "alpha.example.", Prefix: netip.MustParsePrefix("10.0.0.0/24")},
		{Peer: "alpha.example.", Prefix: netip.MustParsePrefix("fd00::/64")},
		{Peer: "zulu.example.", Prefix: netip.MustParsePrefix("fd00::/64")},
	}}}
	live := desktopSnapshot{RuntimeState: "running", Observation: o}
	rows := desktopDashboardNodes(live)
	if len(rows) != 3 || rows[0].Peer != "zulu.example." || rows[1].Peer != "middle.example." || rows[2].Peer != "alpha.example." {
		t.Fatalf("nodes must be merged, unique and descending: %+v", rows)
	}
	if rows[2].Gossip != "synced · never" || rows[2].Tunnel != "✓ IPv4  ✓ IPv6" || rows[2].Health != "✓ Babel 在线" {
		t.Fatalf("current facts were contaminated by historical errors: %+v", rows[2])
	}
	if rows[0].Gossip != "retry_pending · never" || rows[0].Tunnel != "✓ IPv6" {
		t.Fatalf("single-stack node borrowed another peer's family: %+v", rows[0])
	}
	if rows[1].Tunnel != "… 连接中" || rows[1].Health != "— 未检测" {
		t.Fatalf("attempt claimed health: %+v", rows[1])
	}
	for _, s := range []desktopSnapshot{{RuntimeState: "stopped", Observation: o}, {RuntimeState: "running", Observation: o, Error: "unavailable"}} {
		if got := desktopDashboardNodes(s); len(got) != 0 {
			t.Fatalf("offline view retained live nodes: %+v", got)
		}
	}
	// Omitted route families in a bounded sample do not prove dual-stack health.
	o.RoutesTruncated = true
	o.Babel.Routes = nil
	rows = desktopDashboardNodes(live)
	if rows[2].Tunnel != "… 待就绪" {
		t.Fatalf("truncated sample invented a usable address family: %+v", rows[2])
	}
	o.Connections[0].TunnelReady = false
	o.Babel.Routes = []photonwindows.RouteObservation{{Peer: "alpha.example.", Prefix: netip.MustParsePrefix("fd00::/64")}}
	rows = desktopDashboardNodes(live)
	if rows[2].Tunnel != "… 待就绪" {
		t.Fatal("non-ready connection claimed usable family")
	}
}

func TestDesktopDashboardLegacyConnectionAndStatus(t *testing.T) {
	o := &photonwindows.Observation{Running: true, TunnelReady: true, IKE: photonwindows.IKEObservation{Gateway: "gateway.example.", Live: true, ChildLive: true}, Babel: photonwindows.BabelObservation{Live: true, Routes: []photonwindows.RouteObservation{{Prefix: netip.MustParsePrefix("10.0.0.0/24")}}}}
	s := desktopSnapshot{RuntimeState: "running", Observation: o}
	rows := desktopDashboardNodes(s)
	if len(rows) != 1 || rows[0].Tunnel != "✓ IPv4" {
		t.Fatalf("legacy single gateway lost its facts: %+v", rows)
	}
	title, _ := desktopDashboardStatus(s, desktopAdmissionView{Adopted: true})
	if title != "已入网" {
		t.Fatal(title)
	}
	for _, state := range []string{"stopped", "starting", "stopping", "failed"} {
		title, _ = desktopDashboardStatus(desktopSnapshot{RuntimeState: state}, desktopAdmissionView{})
		if slices.Contains([]string{"已入网", "网络已连接"}, title) {
			t.Fatal("lifecycle claimed live connection")
		}
	}
	o.Admission = gossip.AdmissionDiagnosis{Pending: true}
	title, _ = desktopDashboardStatus(s, desktopAdmissionView{Pending: true})
	if title != "等待入网授权" {
		t.Fatal(title)
	}
}

func TestDesktopDashboardCombinesOuterPaths(t *testing.T) {
	live := photonwindows.IKEObservation{Live: true, ChildLive: true}
	o := &photonwindows.Observation{Running: true, Connections: []photonwindows.ConnectionObservation{
		{Peer: "gateway.example.", OuterFamily: "ipv4", IKE: live, BabelLive: true, TunnelReady: true, IPv4RouteReady: true},
		{Peer: "gateway.example.", OuterFamily: "ipv6", IKE: photonwindows.IKEObservation{LastFailure: &photonwindows.IKEFailureObservation{Message: "unreachable"}}},
	}}
	snapshot := desktopSnapshot{RuntimeState: "running", Observation: o}
	rows := desktopDashboardNodes(snapshot)
	if len(rows) != 1 || rows[0].Tunnel != "✓ IPv4" || rows[0].Health != "✓ Babel 在线" {
		t.Fatalf("failed path hid the healthy path: %+v", rows)
	}
	o.Connections[1].IKE = live
	o.Connections[1].TunnelReady, o.Connections[1].IPv6RouteReady = true, true
	rows = desktopDashboardNodes(snapshot)
	if rows[0].Tunnel != "✓ IPv4  ✓ IPv6" || rows[0].Health != "✓ Babel 在线" {
		t.Fatalf("paths did not merge their ready families: %+v", rows)
	}
}
