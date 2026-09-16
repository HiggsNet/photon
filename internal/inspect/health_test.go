package inspect

import (
	"encoding/json"
	"net/netip"
	"testing"

	"github.com/HiggsNet/photon/pkg/health"
)

func TestBuildHealthViewPreservesProbeAddresses(t *testing.T) {
	for _, emptyDesired := range []bool{false, true} {
		for _, sampled := range []bool{false, true} {
			desired := DesiredLink{InstanceID: "link", InterfaceName: "staged-if"}
			if !emptyDesired {
				desired.LocalTunnelAddr, desired.PeerTunnelAddr = "fd00::3", "fd00::4"
			}
			targets := []health.ProbeTarget{
				{InstanceID: "link", ProbeID: "link#old", ProbeRole: "old", InterfaceName: "old-if", LocalTunnelAddr: netip.MustParseAddr("fd00::1"), PeerTunnelAddr: netip.MustParseAddr("fd00::2")},
				{InstanceID: "link", ProbeID: "link#staged", ProbeRole: "staged", InterfaceName: "staged-if", LocalTunnelAddr: netip.MustParseAddr("fd00::3"), PeerTunnelAddr: netip.MustParseAddr("fd00::4")},
			}
			input := HealthInput{Targets: targets, Desired: map[string]DesiredLink{"link": desired}, Instances: map[string]LinkInstance{"link": {ID: "link", InterfaceName: "staged-if"}}}
			if sampled {
				for _, target := range targets {
					input.Samples = append(input.Samples, HealthSample{InstanceID: target.InstanceID, ProbeID: target.ProbeID, ProbeRole: target.ProbeRole, InterfaceName: target.InterfaceName})
				}
			}
			view := BuildHealthView(input)
			if len(view.Links) != 2 {
				t.Fatalf("links = %+v", view.Links)
			}
			for i, link := range view.Links {
				target := targets[i]
				if link.InterfaceName != target.InterfaceName || link.LocalTunnelAddr != target.LocalTunnelAddr.String() || link.PeerTunnelAddr != target.PeerTunnelAddr.String() {
					t.Fatalf("emptyDesired=%v sampled=%v: target=%+v link=%+v", emptyDesired, sampled, target, link)
				}
				if link.Desired == nil || link.Desired.LocalTunnelAddr != desired.LocalTunnelAddr || link.Desired.PeerTunnelAddr != desired.PeerTunnelAddr {
					t.Fatalf("desired not preserved: %+v", link.Desired)
				}
			}
		}
	}
}

func TestBuildHealthViewFillsOnlyMissingProbeAddresses(t *testing.T) {
	for _, localMissing := range []bool{false, true} {
		target := health.ProbeTarget{InstanceID: "link"}
		wantLocal, wantPeer := "fd00::1", "fd00::4"
		if localMissing {
			target.PeerTunnelAddr = netip.MustParseAddr("fd00::2")
			wantLocal, wantPeer = "fd00::3", "fd00::2"
		} else {
			target.LocalTunnelAddr = netip.MustParseAddr("fd00::1")
		}
		view := BuildHealthView(HealthInput{Targets: []health.ProbeTarget{target}, Desired: map[string]DesiredLink{"link": {InstanceID: "link", LocalTunnelAddr: "fd00::3", PeerTunnelAddr: "fd00::4"}}})
		if link := view.Links[0]; link.LocalTunnelAddr != wantLocal || link.PeerTunnelAddr != wantPeer {
			t.Fatalf("link = %+v", link)
		}
	}
}

func TestBuildHealthViewSortsLinks(t *testing.T) {
	view := SortHealthView(BuildHealthView(HealthInput{
		Targets: []health.ProbeTarget{
			{InstanceID: "b", ProbeRole: "staged", ProbeID: "b-staged"},
			{InstanceID: "a", ProbeRole: "active", ProbeID: "a-active"},
			{InstanceID: "b", ProbeRole: "active", ProbeID: "b-active"},
		},
	}), HealthSortPeer)

	if got := view.Links; len(got) != 3 ||
		got[0].Health.ProbeID != "a-active" ||
		got[1].Health.ProbeID != "b-active" ||
		got[2].Health.ProbeID != "b-staged" {
		t.Fatalf("links = %+v, want sorted by instance and role", got)
	}
}

func TestSortHealthViewByPeerOrRTT(t *testing.T) {
	view := BuildHealthView(HealthInput{
		Targets: []health.ProbeTarget{
			{ProbeID: "slow", InstanceID: "link-a", PeerZone: "node-a."},
			{ProbeID: "missing", InstanceID: "link-c", PeerZone: "node-c."},
			{ProbeID: "fast", InstanceID: "link-b", PeerZone: "node-b."},
		},
		Samples: []HealthSample{
			{ProbeID: "slow", InstanceID: "link-a", EWMARTTMs: 80},
			{ProbeID: "fast", InstanceID: "link-b", EWMARTTMs: 10},
		},
	})

	byPeer := SortHealthView(view, HealthSortPeer)
	if byPeer.Links[0].Health.ProbeID != "missing" || byPeer.Links[1].Health.ProbeID != "fast" || byPeer.Links[2].Health.ProbeID != "slow" {
		t.Fatalf("peer sort = %+v", byPeer.Links)
	}
	byRTT := SortHealthView(view, HealthSortRTT)
	if byRTT.Links[0].Health.ProbeID != "fast" || byRTT.Links[1].Health.ProbeID != "slow" || byRTT.Links[2].Health.ProbeID != "missing" {
		t.Fatalf("rtt sort = %+v", byRTT.Links)
	}
}

func TestSortHealthViewPeerMatchesLinksZoneOrdering(t *testing.T) {
	view := SortHealthView(BuildHealthView(HealthInput{Targets: []health.ProbeTarget{
		{ProbeID: "child", InstanceID: "c", PeerZone: "node-a.example."},
		{ProbeID: "parent", InstanceID: "p", PeerZone: "example."},
		{ProbeID: "last", InstanceID: "z", PeerZone: "node-z.example."},
	}}), HealthSortPeer)

	want := []string{"last", "child", "parent"}
	for i, probeID := range want {
		if view.Links[i].Health.ProbeID != probeID {
			t.Fatalf("links[%d] = %q, want %q; links=%+v", i, view.Links[i].Health.ProbeID, probeID, view.Links)
		}
	}
}

func TestBuildHealthViewMergesRuntimeContextAndMissingLinks(t *testing.T) {
	got := BuildHealthView(HealthInput{
		Samples: []HealthSample{{
			InstanceID: "link-b", ProbeRole: "staged", InterfaceName: "health-if", State: "healthy",
		}},
		Instances: map[string]LinkInstance{
			"link-a": {
				ID: "link-a", PeerZone: "node-a.catofes.", GroupID: "blue",
				InterfaceName: "phx-a", Endpoint: "198.51.100.10:4500", ActualState: "up",
			},
			"link-b": {
				ID: "link-b", PeerZone: "node-b.catofes.", GroupID: "blue",
				InterfaceName: "phx-b", Endpoint: "198.51.100.11:4500", ActualState: "up",
			},
		},
		Desired: map[string]DesiredLink{
			"link-a": {
				InstanceID: "link-a", PeerZone: "node-a.catofes.", GroupID: "blue",
				InterfaceName: "desired-a", LocalTunnelAddr: "fd00::1", PeerTunnelAddr: "fd00::2",
			},
			"link-b": {
				InstanceID: "link-b", LocalTunnelAddr: "fd00::3", PeerTunnelAddr: "fd00::4",
			},
		},
	})

	if len(got.Links) != 2 {
		t.Fatalf("links len = %d, want 2: %#v", len(got.Links), got.Links)
	}
	if got.Links[0].Health.InstanceID != "link-a" || got.Links[0].PeerZone != "node-a.catofes." || got.Links[0].InterfaceName != "phx-a" {
		t.Fatalf("missing-link view = %#v", got.Links[0])
	}
	if got.Links[0].Health.State != "unknown" || got.Links[0].Observed {
		t.Fatalf("missing-link health = %#v, want unobserved unknown", got.Links[0])
	}
	if got.Links[1].Health.InstanceID != "link-b" || got.Links[1].Health.ProbeRole != "staged" || !got.Links[1].Observed {
		t.Fatalf("existing health sort keys = %#v", got.Links[1])
	}
	if got.Links[1].InterfaceName != "health-if" {
		t.Fatalf("interface = %q, want health interface override", got.Links[1].InterfaceName)
	}
	if got.Links[1].LocalTunnelAddr != "fd00::3" || got.Links[1].PeerTunnelAddr != "fd00::4" {
		t.Fatalf("desired tunnel context missing: %#v", got.Links[1])
	}
}

func TestBuildHealthViewUsesCanonicalUnknownSample(t *testing.T) {
	got := BuildHealthView(HealthInput{Instances: map[string]LinkInstance{
		"link-a": {ID: "link-a"},
	}})
	if len(got.Links) != 1 {
		t.Fatalf("links len = %d, want 1", len(got.Links))
	}
	if got.Links[0].Health.InstanceID != "link-a" || got.Links[0].Health.State != "unknown" {
		t.Fatalf("health = %#v, want canonical unknown sample", got.Links[0].Health)
	}
}

func TestHealthViewPreservesObserverSchemaWithoutRuntimeInstance(t *testing.T) {
	got := HealthView{Links: []HealthLinkView{{
		Health:   HealthSample{InstanceID: "link-1", State: "unknown"},
		PeerZone: "node-b.catofes.", GroupID: "blue", InterfaceName: "phx0",
	}}}
	data, err := json.Marshal(got)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	item := decoded["links"].([]any)[0].(map[string]any)
	if item["peer_zone"] != "node-b.catofes." || item["health"] == nil {
		t.Fatalf("health fields missing: %#v", item)
	}
	if _, ok := item["instance"]; ok {
		t.Fatalf("raw runtime instance exposed: %#v", item)
	}
}
