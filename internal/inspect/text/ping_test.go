package text

import (
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestWritePingDebugOutput(t *testing.T) {
	view := inspect.PingDebugView{
		Zone:    "node-b.",
		Count:   4,
		Timeout: time.Second,
		Targets: []inspect.PingTargetView{
			{
				InstanceID:   "t1",
				ProbeID:      "t1",
				Role:         "active",
				Family:       "ipv4",
				TunnelFamily: "ipv6",
				Interface:    "phx0",
				NetNS:        "photontesth2",
				LocalTunnel:  "10.0.0.1",
				PeerTunnel:   "10.0.0.2",
				Success:      true,
				RTT:          2300 * time.Microsecond,
			},
			{
				InstanceID:   "t1",
				ProbeID:      "t2",
				Role:         "staged",
				Family:       "ipv6",
				TunnelFamily: "ipv6",
				Interface:    "phx-new",
				LocalTunnel:  "fd00::1",
				PeerTunnel:   "fd00::2",
				Failure:      &inspect.FailureView{Code: inspect.FailureCodeHealthProbe, Message: "100% packet loss"},
			},
		},
	}
	var buf strings.Builder
	if err := WritePingDebug(&buf, view); err != nil {
		t.Fatalf("WritePingDebug: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"zone: node-b.",
		"targets: 2",
		"count: 4 timeout: 1s",
		"instance t1",
		"role=active underlay=ipv4 tunnel=ipv6",
		"interface: phx0  netns: photontesth2",
		"result: ok rtt=2.3ms",
		"role=staged underlay=ipv6 tunnel=ipv6",
		"result: fail code=health_probe_failed message=100% packet loss",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	if actIdx, stgIdx := strings.Index(got, "role=active"), strings.Index(got, "role=staged"); actIdx >= stgIdx {
		t.Fatalf("expected active row before staged row:\n%s", got)
	}
}

func TestWritePingDebugEmpty(t *testing.T) {
	view := inspect.PingDebugView{
		Zone:           "nope.",
		AvailableZones: []string{"node-b.", "node-c."},
		Count:          4,
		Timeout:        time.Second,
	}
	var buf strings.Builder
	if err := WritePingDebug(&buf, view); err != nil {
		t.Fatalf("WritePingDebug: %v", err)
	}
	got := buf.String()
	for _, want := range []string{
		"zone: nope.",
		"targets: 0",
		"no IPsec link instances for zone nope.",
		"available peer zones: node-b., node-c.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
}

func TestWritePingDebugSeparatesInstancesNotFields(t *testing.T) {
	view := inspect.PingDebugView{
		Zone:    "node-b.",
		Count:   1,
		Timeout: time.Second,
		Targets: []inspect.PingTargetView{
			{
				InstanceID:   "t1",
				Role:         "active",
				Family:       "ipv6",
				TunnelFamily: "ipv6",
				Interface:    "phx0",
				LocalTunnel:  "fe80::1",
				PeerTunnel:   "fe80::2",
			},
			{
				InstanceID:   "t2",
				Role:         "active",
				Family:       "ipv6",
				TunnelFamily: "ipv6",
				Interface:    "phx1",
				LocalTunnel:  "fe80::3",
				PeerTunnel:   "fe80::4",
			},
		},
	}
	var buf strings.Builder
	if err := WritePingDebug(&buf, view); err != nil {
		t.Fatalf("WritePingDebug: %v", err)
	}
	got := buf.String()
	if strings.Contains(got, "interface: phx0\n\n    local:") {
		t.Fatalf("unexpected blank line within target fields:\n%s", got)
	}
	if !strings.Contains(got, "    result: fail\n\ninstance t2") {
		t.Fatalf("expected blank line between instances:\n%s", got)
	}
}
