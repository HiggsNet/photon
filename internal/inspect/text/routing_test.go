package text

import (
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/inspect"
)

func TestWriteBirdDump(t *testing.T) {
	dump := &inspect.BirdDumpResponse{Instances: map[string]inspect.BirdDumpInstance{
		"z": {
			NetNS:             "z",
			InstanceID:        "main",
			ControlSocket:     "/run/bird.ctl",
			ConfigPath:        "/run/bird.conf",
			FilterDefinitions: "filter photon_import_z {\n    reject;\n}",
			Raw: map[string]string{
				"show route": "10.0.0.0/24 unicast\n",
			},
			Interfaces:   []inspect.BirdInterfaceContext{{Name: "phx1", Zone: "node-b.catofes.", Family: "ipv6", LinkID: "link-b", RuntimeRole: "active"}},
			Neighbors:    []inspect.BirdBabelNeighbor{{Address: "fe80::2", Interface: "phx1", Zone: "node-b.catofes.", Family: "ipv6", Metric: "100", Routes: "2", Hellos: "16", Expires: "5.2", Auth: "No", RTT: "3.2", Protocol: "babel1"}},
			BabelRoutes:  []inspect.BirdBabelRoute{{Prefix: "fd00::/64", Nexthop: "fe80::2", Interface: "phx1", Zone: "node-b.catofes.", Family: "ipv6", Metric: "100", Flag: "*", Seqno: "42", Expires: "5.2", Protocol: "babel1"}},
			BabelEntries: []inspect.BirdBabelEntry{{Prefix: "fd00::/64", RouterID: "00:00:00:00:00:00:00:02", Metric: "100", Seqno: "42", Routes: "1", Sources: "1", Interface: "phx1", Zone: "node-b.catofes.", Family: "ipv6", Protocol: "babel1"}},
		},
	}}
	var buf strings.Builder
	if err := WriteBirdDump(&buf, dump); err != nil {
		t.Fatalf("WriteBirdDump: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"netns z",
		"instance_id: main",
		"control_socket: /run/bird.ctl",
		"config_path: /run/bird.conf",
		"filter_definitions:",
		"filter photon_import_z",
		"command: show route",
		"10.0.0.0/24 unicast",
		"Photon interface mapping:",
		"Babel neighbors (1):",
		"Babel routes (1):",
		"Babel entries (1):",
		"node-b.catofes.",
		"phx1",
		"fd00::/64",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}

func TestWriteBabelDebug(t *testing.T) {
	view := inspect.BabelDebugView{
		LastReconcileFailure: &inspect.FailureView{Code: inspect.FailureCodeRoutingReconcile, Message: "reload failed"},
		Instances: []inspect.BabelInstanceView{
			{
				NetNS:          "photontesth2",
				InstanceID:     "main",
				Mode:           "managed",
				ShutdownPolicy: "persist",
				Enabled:        true,
				RouterID:       12345,
				ControlSocket:  "/run/photon/bird/bird-main.ctl",
				ConfigPath:     "/run/photon/bird/bird-main.conf",
				PIDFile:        "/run/photon/bird/bird-main.pid",
				LastConfigHash: "deadbeef1234567890abcdef",
				Overlays:       []string{"main"},
				State:          "running",
				HasState:       true,
			},
			{
				NetNS:      "disabled",
				InstanceID: "off",
				Mode:       "disabled",
				Enabled:    false,
			},
		},
	}
	var buf strings.Builder
	if err := WriteBabelDebug(&buf, view); err != nil {
		t.Fatalf("WriteBabelDebug: %v", err)
	}
	output := buf.String()
	for _, want := range []string{
		"last_reconcile_failure: code=routing_reconcile_failed message=reload failed",
		"netns photontesth2",
		"shutdown_policy: persist",
		"router_id: 12345",
		"last_config_hash: deadbeef1234",
		"overlays: main",
		"state: running",
		"netns disabled",
		"state: disabled",
	} {
		if !strings.Contains(output, want) {
			t.Fatalf("output missing %q:\n%s", want, output)
		}
	}
}
