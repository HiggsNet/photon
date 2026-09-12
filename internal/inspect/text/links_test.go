package text

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestWriteLinksDebugFiltersAndPrintsRuntimeFields(t *testing.T) {
	view := inspect.LinksDebugView{
		Inspection: inspect.LinkInspection{
			Summary: inspect.LinkSummary{
				LastRunUnix:   1700000000,
				DesiredLinks:  1,
				ActualSAs:     1,
				LinkInstances: 1,
			},
			Links: []inspect.LinkView{{
				ID:              "link-1",
				PeerZone:        "node-b.catofes.",
				GroupID:         "main",
				ActualState:     "up",
				Endpoint:        "198.51.100.10:4500",
				InterfaceName:   "phx123",
				XFRMIfID:        123,
				LocalTunnelAddr: "fe80::1%phx123",
				PeerTunnelAddr:  "fe80::2%phx123",
				DesiredSpecHash: "abcdef1234567890",
				Routing: inspect.LinkRouting{
					BirdState:      "running",
					BirdNeighbors:  "2",
					BirdBestRoutes: "4",
				},
				ActualSA: &inspect.LinkSA{
					ChildSA:        "child-a",
					Established:    true,
					LocalEndpoint:  "192.0.2.1:4500",
					RemoteEndpoint: "198.51.100.10:4500",
					ReqID:          55,
				},
				Health: &inspect.HealthSample{
					ProbeID:       "link-1",
					InstanceID:    "link-1",
					State:         "degraded",
					ProbeType:     "icmp",
					Sent:          6,
					Received:      2,
					Lost:          4,
					LossRatio:     66,
					LastRTTMs:     213,
					EWMARTTMs:     220,
					NextProbeUnix: 1700000010,
				},
			}},
			Actions: []inspect.LinkAction{{
				Action:     "cleanup_duplicate_sa",
				InstanceID: "link-1",
				GroupID:    "main",
				PeerZone:   "node-b.catofes.",
				SAUniqueID: 335,
				Reason:     "duplicate runtime SA stable for 2m",
			}},
		},
		ReplannedDesired:  1,
		DesiredPlanSource: "live",
		Filter:            "node-b",
	}
	var buf strings.Builder
	if err := WriteLinksDebug(&buf, view); err != nil {
		t.Fatalf("WriteLinksDebug: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"last_run: 2023-11-14T22:13:20Z",
		"desired_links: 1",
		"planned_desired_links: 1",
		"desired_source: live",
		"filter: node-b",
		"matched_links: 1",
		"link link-1",
		"peer: node-b.catofes.",
		"interface: phx123(123)",
		"sa_state: established",
		"reqid: 55",
		"lifecycle:",
		"health:",
		"state: degraded",
		"sent/received/lost: 6/2/4",
		"loss: 66%",
		"bird_state: running",
		"action=cleanup_duplicate_sa",
		"sa_unique_id=335",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestWriteLinksUsesTransportSummaryAndVerboseTables(t *testing.T) {
	inspection := inspect.LinkInspection{
		Summary: inspect.LinkSummary{DesiredLinks: 2, ActualSAs: 1},
		Links: []inspect.LinkView{
			{
				ID: "link-a", PeerZone: "node-a.catofes.", GroupID: "mesh",
				PathKey: "public-v6", TransportKind: "strongswan", ActualState: "up",
				Endpoint: "[2001:db8::1]:4500", InterfaceName: "phx1", XFRMIfID: 1,
				LocalTunnelAddr: "fd42::1", PeerTunnelAddr: "fd42::2",
				ActualSA: &inspect.LinkSA{ChildSA: "child-a", Established: true},
				Health:   &inspect.HealthSample{State: "healthy"},
				Rotation: inspect.LinkRotation{Phase: "stable"},
				Routing:  inspect.LinkRouting{BirdState: "running"},
				Owner:    inspect.LinkOwner{Manager: "ipsec"},
			},
			{ID: "link-b", PeerZone: "node-b.catofes.", Missing: true},
		},
	}
	var summary strings.Builder
	if err := WriteLinks(&summary, inspection, "", false); err != nil {
		t.Fatalf("WriteLinks summary: %v", err)
	}
	for _, want := range []string{"LINK", "PEER", "TRANSPORT", "STATE", "ENDPOINT", "INTERFACE", "link-a", "strongswan", "link-b", "missing"} {
		if !strings.Contains(summary.String(), want) {
			t.Fatalf("summary missing %q:\n%s", want, summary.String())
		}
	}
	var verbose strings.Builder
	if err := WriteLinks(&verbose, inspection, "link-a", true); err != nil {
		t.Fatalf("WriteLinks verbose: %v", err)
	}
	for _, want := range []string{"links: 1/2", "GROUP", "PATH", "TUNNEL", "SA", "HEALTH", "ROTATION", "ROUTING", "OWNER", "fd42::1->fd42::2", "child-a:established", "healthy", "running"} {
		if !strings.Contains(verbose.String(), want) {
			t.Fatalf("verbose output missing %q:\n%s", want, verbose.String())
		}
	}
	if strings.Contains(verbose.String(), "link-b") {
		t.Fatalf("filter leaked link-b:\n%s", verbose.String())
	}
}

func TestWriteLinksDebugShowsActiveRuntimeTunnel(t *testing.T) {
	var out strings.Builder
	link := inspect.LinkView{
		ID:              "link-1",
		PeerZone:        "venus-aliyun-pek.catofes.",
		GroupID:         "ipsec-main",
		LinkID:          "link-1",
		PathKey:         "family:ipv4",
		TransportID:     "ipsec-526e55bae2e1-r12",
		IKEName:         "ipsec-f46fb3d71fe8-r13",
		DesiredSpecHash: "actual-hash",
		ActualState:     "up",
		Endpoint:        "123.57.143.66:30002",
		InterfaceName:   "phx1be3f390",
		XFRMIfID:        467923856,
		LocalTunnelAddr: "fe80::old-local%phx1be3f390 netns=photontesth2",
		PeerTunnelAddr:  "fe80::old-peer%phx1be3f390 netns=photontesth2",
		Desired: &inspect.DesiredLink{
			TransportID:     "ipsec-f46fb3d71fe8-r2",
			DesiredSpecHash: "desired-hash",
			LocalTunnelAddr: "fe80::new-local%phx28e3c6e5 netns=photontesth2",
			PeerTunnelAddr:  "fe80::new-peer%phx28e3c6e5 netns=photontesth2",
		},
	}

	if err := WriteLinksDebug(&out, inspect.LinksDebugView{
		Inspection: inspect.LinkInspection{
			Summary: inspect.LinkSummary{LinkInstances: 1},
			Links:   []inspect.LinkView{link},
		},
	}); err != nil {
		t.Fatalf("WriteLinksDebug: %v", err)
	}
	output := out.String()
	for _, want := range []string{
		"    runtime_id: ipsec-f46fb3d71fe8-r13",
		"    endpoint: 123.57.143.66:30002",
		"    interface: phx1be3f390(467923856)",
		"    local_tunnel: fe80::old-local%phx1be3f390 netns=photontesth2",
		"    peer_tunnel: fe80::old-peer%phx1be3f390 netns=photontesth2",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("debug links output missing %q:\n%s", want, output)
		}
	}
	if strings.Contains(output, "fe80::new-local%phx28e3c6e5") || strings.Contains(output, "fe80::new-peer%phx28e3c6e5") {
		t.Fatalf("debug links planner mixed desired tunnel into active runtime block:\n%s", output)
	}
}
