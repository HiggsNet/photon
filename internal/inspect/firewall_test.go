package inspect

import (
	"errors"
	"testing"

	"github.com/HiggsNet/photon/pkg/firewall"
)

func TestBuildFirewallDebugView(t *testing.T) {
	view := BuildFirewallDebug(FirewallDebugInput{
		Instances: []FirewallInstanceInput{
			{
				ID:            "photontesth2",
				Scope:         "photontesth2",
				Enabled:       true,
				Mode:          FirewallModeManaged,
				Backend:       "auto",
				DefaultPolicy: "drop",
				InlineHooks: []FirewallInlineHookView{
					{Backend: "nft", Point: "pre_input", Expression: "counter"},
					{Backend: "iptables", Family: "ipv4", Point: "pre_input", Expression: "-j ACCEPT"},
				},
			},
			{
				ID:            "host",
				Scope:         "host",
				Enabled:       true,
				Mode:          FirewallModeManaged,
				IsHost:        true,
				HostIKE:       true,
				HostNATT:      true,
				RedirectGrace: true,
			},
		},
		Reconcile: &firewall.FirewallObservation{
			Backend:     "dry-run",
			LastFailure: errors.New("nft unavailable"),
			Instances: map[string]*firewall.FirewallInstanceObservation{
				"photontesth2": {Backend: "nft", Generation: 5, OwnedObjects: 10, PolicyHash: "abc123"},
			},
		},
	})
	if view.Backend != "dry-run" {
		t.Fatalf("backend = %q, want dry-run", view.Backend)
	}
	if view.LastFailure == nil || view.LastFailure.Code != FailureCodeFirewallReconcile || view.LastFailure.Message != "nft unavailable" {
		t.Fatalf("failure = %+v", view.LastFailure)
	}
	if len(view.Instances) != 2 {
		t.Fatalf("instances = %d, want 2", len(view.Instances))
	}
	if got := view.Instances[0]; got.ID != "photontesth2" || got.Generation != 5 || got.OwnedObjects != 10 || got.PolicyHash != "abc123" {
		t.Fatalf("first instance = %+v, want reconcile fields", got)
	}
	if got := view.Instances[0]; got.ResolvedBackend != "nft" || len(got.InlineHooks) != 2 || got.InlineHooks[0].State != "active" || got.InlineHooks[1].State != "inactive" {
		t.Fatalf("inline hooks = %+v, resolved backend %q", got.InlineHooks, got.ResolvedBackend)
	}
	if got := view.Instances[1]; !got.IsHost || !got.HostIKE || !got.HostNATT || !got.RedirectGrace {
		t.Fatalf("host instance = %+v, want host flags", got)
	}
}

func TestBuildFirewallDebugDefaultsAndDisabledMode(t *testing.T) {
	view := BuildFirewallDebug(FirewallDebugInput{
		Instances: []FirewallInstanceInput{
			{ID: "enabled", Enabled: true},
			{ID: "disabled", Enabled: false, Mode: FirewallModeManaged},
		},
	})
	if got := view.Instances[0].Mode; got != FirewallModeManaged {
		t.Fatalf("enabled default mode = %q, want managed", got)
	}
	if got := view.Instances[1].Mode; got != "disabled" {
		t.Fatalf("disabled mode = %q, want disabled", got)
	}
}
