package text

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestWriteRotateDebug(t *testing.T) {
	view := inspect.RotateDebugView{
		LastRunUnix:       1700000000,
		LinkInstances:     1,
		PlannedDesired:    1,
		DesiredPlanSource: "planned",
		Filter:            "node-b",
		StoredLabel:       "stored_sas",
		LiveLabel:         "live_sas",
		ReconcileSACount:  1,
		LiveSACount:       1,
		Links: []inspect.RotateDebugLink{{
			Link: inspect.LinkView{
				ID:       "link-1",
				PeerZone: "node-b.catofes.",
				GroupID:  "ipsec-main",
				LinkID:   "link-1",
				PathKey:  "family:ipv4",
				Rotation: inspect.LinkRotation{
					Phase:          "current",
					RotateDeadline: 1700000300,
				},
			},
			PortGenerationSummary: "2/1/2",
			PortSummary:           "4500/30002/30002/30003",
			Current: inspect.RotateRuntimeView{
				State:           "expected_current",
				Port:            "30002",
				RuntimeID:       "ipsec-current",
				ChildSAName:     "ipsec-current-child",
				InterfaceName:   "phx1",
				XFRMIfID:        100,
				Endpoint:        "203.0.113.10:30002",
				LocalTunnelAddr: "fe80::1%phx1",
				PeerTunnelAddr:  "fe80::2%phx1",
			},
			Staged: inspect.RotateRuntimeView{
				State:       "expected_new",
				Port:        "30003",
				RuntimeID:   "ipsec-staged",
				ChildSAName: "ipsec-staged-child",
			},
			HasStaged: true,
			ReconcileMatchingSAs: []inspect.LinkSA{{
				Name:           "ipsec-current",
				ChildSA:        "ipsec-current-child",
				XFRMIfID:       100,
				ReqID:          200,
				LocalEndpoint:  "10.0.0.1:4500",
				RemoteEndpoint: "203.0.113.10:30002",
				Established:    true,
			}},
		}},
	}
	var buf strings.Builder
	if err := WriteRotateDebug(&buf, view); err != nil {
		t.Fatalf("WriteRotateDebug: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"last_run: 2023-11-14T22:13:20Z",
		"filter: node-b",
		"matched_links: 1",
		"link link-1",
		"port_generation select/runtime/staged: 2/1/2",
		"port local/remote/runtime/staged: 4500/30002/30002/30003",
		"interface: phx1(100)",
		"reconcile_matching_sas: 1",
		"name=ipsec-current child=ipsec-current-child state=established if_id=100 reqid=200",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
