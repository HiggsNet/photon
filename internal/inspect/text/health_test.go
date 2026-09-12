package text

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestWriteHealthNoTargets(t *testing.T) {
	var buf strings.Builder
	if err := WriteHealth(&buf, inspect.HealthView{}, inspect.HealthSortPeer, true); err != nil {
		t.Fatalf("WriteHealth: %v", err)
	}
	if got := buf.String(); got != "No link instances to probe.\n" {
		t.Fatalf("output = %q", got)
	}
}

func TestWriteHealthVerboseSortsTargetsAndShowsSampleState(t *testing.T) {
	view := inspect.HealthView{
		Targets: []inspect.HealthTarget{
			{
				ProbeID:         "link-b#staged",
				InstanceID:      "link-b",
				PeerZone:        "node-b.catofes.",
				Overlay:         "blue",
				InterfaceName:   "phx-b",
				LocalTunnelAddr: "fd00::1",
				PeerTunnelAddr:  "fd00::2",
				ProbeRole:       "staged",
				State:           "up",
				Staged:          true,
			},
			{
				ProbeID:         "link-a",
				InstanceID:      "link-a",
				PeerZone:        "node-a.catofes.",
				Overlay:         "blue",
				InterfaceName:   "phx-a",
				LocalTunnelAddr: "fd00::3",
				PeerTunnelAddr:  "fd00::4",
				State:           "up",
			},
		},
		Samples: []inspect.HealthSample{{
			ProbeID:         "link-b#staged",
			InstanceID:      "link-b",
			ProbeRole:       "staged",
			State:           "healthy",
			ProbeType:       "icmp",
			Sent:            4,
			Received:        3,
			Lost:            1,
			LossRatio:       25,
			LastRTTMs:       30,
			EWMARTTMs:       25,
			P50RTTMs:        20,
			P95RTTMs:        40,
			P99RTTMs:        45,
			JitterMs:        5,
			LastError:       "timeout",
			ConsecutiveFail: 2,
			CutoverBlocking: true,
		}},
	}

	var buf strings.Builder
	if err := WriteHealth(&buf, view, inspect.HealthSortPeer, true); err != nil {
		t.Fatalf("WriteHealth: %v", err)
	}
	out := buf.String()
	if strings.Index(out, "link-b") > strings.Index(out, "link-a") {
		t.Fatalf("targets are not sorted by peer name descending:\n%s", out)
	}
	for _, want := range []string{
		"Link health (2 links):",
		"LINK    PROBE ID",
		"link-a  link-a",
		"node-a.catofes.",
		"fd00::3->fd00::4",
		"link-b  link-b#staged",
		"node-b.catofes.",
		"fd00::1->fd00::2",
		"healthy  icmp",
		"4/3/1",
		"25%",
		"30/25/20/40/45ms",
		"5ms",
		"blocked  timeout",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in output:\n%s", want, out)
		}
	}
}

func TestWriteHealthConciseHidesDiagnosticColumns(t *testing.T) {
	view := inspect.HealthView{
		Targets: []inspect.HealthTarget{{
			ProbeID: "probe-secret", InstanceID: "link-secret", PeerZone: "node-b.",
			ProbeRole: "active", UnderlayFamily: "ipv6", InterfaceName: "phx0",
		}},
		Samples: []inspect.HealthSample{{
			ProbeID: "probe-secret", State: "healthy", Sent: 10, Received: 9,
			LossRatio: 10, EWMARTTMs: 12, JitterMs: 2, LastError: "hidden error",
		}},
	}
	var buf strings.Builder
	if err := WriteHealth(&buf, view, inspect.HealthSortPeer, false); err != nil {
		t.Fatalf("WriteHealth: %v", err)
	}
	out := buf.String()
	for _, want := range []string{"PEER", "ROLE", "FAMILY", "HEALTH", "LOSS", "RTT", "node-b.", "healthy", "10%", "12ms"} {
		if !strings.Contains(out, want) {
			t.Fatalf("expected %q in concise output:\n%s", want, out)
		}
	}
	for _, hidden := range []string{"LINK", "PROBE ID", "probe-secret", "link-secret", "phx0", "hidden error", "10/9/"} {
		if strings.Contains(out, hidden) {
			t.Fatalf("unexpected %q in concise output:\n%s", hidden, out)
		}
	}
}
