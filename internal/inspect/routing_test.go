package inspect

import (
	"errors"
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
