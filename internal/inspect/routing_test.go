package inspect

import (
	"errors"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/pkg/routing/bird"
)

func TestBuildBabelDebug(t *testing.T) {
	view := BuildBabelDebug(BabelDebugInput{
		LastReconcileFailure: errors.New("reload failed"),
		Instances: []BabelInstanceInput{
			{
				NetNS:      "photontesth2",
				InstanceID: "main",
				Enabled:    true,
			},
			{
				NetNS:      "external",
				InstanceID: "ext",
				Mode:       RoutingModeExternal,
				Enabled:    true,
			},
			{
				NetNS:      "disabled",
				InstanceID: "off",
				Mode:       RoutingModeManaged,
				Enabled:    false,
			},
		},
		LinuxStates: map[string]*bird.InstanceObservation{
			"photontesth2": {
				RouterID:       12345,
				ControlSocket:  "/run/photon/bird/bird-main.ctl",
				ConfigPath:     "/run/photon/bird/bird-main.conf",
				PIDFile:        "/run/photon/bird/bird-main.pid",
				LastConfigHash: "deadbeef",
				Overlays:       []string{"main"},
				State:          "running",
				LastFailure:    errors.New("bird restart failed"),
			},
		},
	})

	if view.LastReconcileFailure == nil || view.LastReconcileFailure.Code != FailureCodeRoutingReconcile || view.LastReconcileFailure.Message != "reload failed" {
		t.Fatalf("last reconcile failure = %+v", view.LastReconcileFailure)
	}
	if len(view.Instances) != 3 {
		t.Fatalf("instances = %d, want 3", len(view.Instances))
	}
	main := view.Instances[0]
	if main.Mode != RoutingModeManaged || main.ShutdownPolicy != RoutingShutdownPolicyPersist {
		t.Fatalf("main mode/shutdown = %q/%q", main.Mode, main.ShutdownPolicy)
	}
	if !main.HasState || main.RouterID != 12345 || main.State != "running" {
		t.Fatalf("main runtime state = %+v", main)
	}
	if main.LastFailure == nil || main.LastFailure.Code != FailureCodeBirdInstance || main.LastFailure.Message != "bird restart failed" {
		t.Fatalf("main failure = %+v", main.LastFailure)
	}
	if len(main.Overlays) != 1 || main.Overlays[0] != "main" {
		t.Fatalf("main overlays = %#v", main.Overlays)
	}
	external := view.Instances[1]
	if external.ShutdownPolicy != "" {
		t.Fatalf("external shutdown policy = %q, want empty", external.ShutdownPolicy)
	}
	disabled := view.Instances[2]
	if disabled.Mode != RoutingModeDisabled || disabled.HasState {
		t.Fatalf("disabled view = %+v", disabled)
	}
}

func TestBuildBabelDebugCopiesRuntimeSlices(t *testing.T) {
	overlays := []string{"main"}
	view := BuildBabelDebug(BabelDebugInput{
		Instances: []BabelInstanceInput{{NetNS: "n", InstanceID: "main", Enabled: true}},
		LinuxStates: map[string]*bird.InstanceObservation{
			"n": {Overlays: overlays},
		},
	})
	overlays[0] = "changed"

	if got := view.Instances[0].Overlays[0]; got != "main" {
		t.Fatalf("overlay copied = %q, want main", got)
	}
}

func TestParseBirdBabelDetailAddsPhotonInterfaceContext(t *testing.T) {
	contexts := map[string]BirdInterfaceContext{
		"phx31d438dd": {Name: "phx31d438dd", Zone: "node-b.catofes.", Family: "ipv6", LinkID: "link-b"},
	}
	neighbors := ParseBirdBabelNeighbors(`photon_babel_photon:
IP address                Interface  Metric Routes Hellos Expires Auth  RTT (ms)
fe80::93db:7db6:82ab:e22b phx31d438dd    100      1     16   5.640 No       3.280
`, contexts)
	if len(neighbors) != 1 || neighbors[0].Zone != "node-b.catofes." || neighbors[0].Family != "ipv6" || neighbors[0].RTT != "3.280" {
		t.Fatalf("neighbors = %#v", neighbors)
	}

	routes := ParseBirdBabelRoutes(`photon_babel_photon:
Prefix                   Nexthop                   Interface Metric F Seqno Expires
2a0d:2905:1:3::/64       fe80::93db:7db6:82ab:e22b phx31d438dd   100 *   459  12.803
`, contexts)
	if len(routes) != 1 || routes[0].Flag != "*" || routes[0].Seqno != "459" || routes[0].Zone != "node-b.catofes." {
		t.Fatalf("routes = %#v", routes)
	}

	entries := ParseBirdBabelEntries(`photon_babel_photon:
Prefix                   Router ID               Metric Seqno  Routes Sources
2a0d:2905:1:3::/64       00:00:00:00:56:35:60:b7    100   459      13       1
`, routes, contexts)
	if len(entries) != 1 || entries[0].Interface != "phx31d438dd" || entries[0].Zone != "node-b.catofes." || entries[0].Sources != "1" {
		t.Fatalf("entries = %#v", entries)
	}
}

func TestExtractBirdFilterDefinitionsExcludesOtherConfig(t *testing.T) {
	config := `router id 10.0.0.1;

filter photon_import_main {
    if net ~ [ 10.0.0.0/8+ ] then accept;
    reject;
}

filter photon_export_main {
    if net ~ [ 10.1.0.0/24 ] then accept;
    reject;
}

protocol babel photon_babel_main {
    auth "mac" key id 1 password "do-not-print";
}`
	got := ExtractBirdFilterDefinitions(config)
	for _, want := range []string{"filter photon_import_main", "10.0.0.0/8+", "filter photon_export_main", "10.1.0.0/24"} {
		if !strings.Contains(got, want) {
			t.Errorf("filter definitions missing %q:\n%s", want, got)
		}
	}
	for _, unwanted := range []string{"router id", "protocol babel", "do-not-print"} {
		if strings.Contains(got, unwanted) {
			t.Errorf("filter definitions contain %q:\n%s", unwanted, got)
		}
	}
}
