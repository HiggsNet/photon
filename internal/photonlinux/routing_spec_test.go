package photonlinux

import (
	"net/netip"
	"reflect"
	"slices"
	"testing"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestBirdSpecUsesParsedNamespaceWithoutOverlay(t *testing.T) {
	cfg, err := ParseRoutingConfig([]RoutingInstanceYAML{{ID: "main", NetNS: "alias", Upstream: &UpstreamConfigYAML{}}}, NetNSConfig{Names: map[string]ipsec.NetNSSpec{"alias": {Kind: ipsec.NetNSName, Name: "mesh-real", Create: true}}}, "/tmp")
	if err != nil {
		t.Fatal(err)
	}
	inst := cfg.Instances[0]
	spec := BuildBirdInstanceSpec(inst, 123, nil, nil, "node-a.catofes.")
	if spec.NetNSName != "mesh-real" || spec.NetNS.Name != "mesh-real" || !spec.NetNS.Create || inst.Upstream.Veth.MeshNetns != "mesh-real" {
		t.Fatalf("parsed namespace lost: BIRD=%+v veth=%+v", spec.NetNS, inst.Upstream.Veth)
	}
	if spec.RouterID != 123 || spec.Upstream == nil || spec.Upstream.Interface != inst.Upstream.Veth.MeshInterface {
		t.Fatalf("runtime spec not completed: %+v", spec)
	}
	if cfg.Instances[0].Bird.RouterID != 0 || cfg.Instances[0].Bird.Upstream != nil {
		t.Fatal("runtime fields written back to config")
	}
}

func TestBuildBirdInstanceSpecOverlaysAndUpstreamRoutes(t *testing.T) {
	v4, v6 := netip.MustParsePrefix("10.42.0.0/24"), netip.MustParsePrefix("fd00:42::/64")
	ars := &routing.AuthorizedRouteSet{AllAssignments: []*routing.AssignmentEntry{
		{Prefix: v4, AssignedTo: "node-a.catofes."},
		{Prefix: v6, AssignedTo: "node-a.catofes.", Shared: true},
		{Prefix: netip.MustParsePrefix("10.43.0.0/24"), AssignedTo: "other.catofes."},
	}}
	groups := []ipsec.LinkGroupSpec{
		{ID: "other", NetNS: ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "other"}},
		{ID: "main", NetNS: ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "mesh", Create: true}},
		{ID: "backup", NetNS: ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "mesh"}},
	}
	for _, mode := range []string{"none", "disabled", UpstreamModeStatic, UpstreamModeExternal} {
		t.Run(mode, func(t *testing.T) {
			inst := RoutingInstance{Bird: bird.BirdInstanceSpec{NetNSName: "mesh"}}
			if mode != "none" {
				inst.Upstream = &UpstreamConfig{Enabled: mode != "disabled", Mode: mode, Veth: bird.VethSpec{MeshInterface: "to-host", PeerIPv4LL: "169.254.0.2/30", PeerIPv6LL: "fe80::2/64"}}
			}
			spec := BuildBirdInstanceSpec(inst, 123, groups, ars, "node-a.catofes.")
			if !slices.Equal(spec.Overlays, []string{"main", "backup"}) || spec.NetNS.Name != "mesh" || !spec.NetNS.Create {
				t.Fatalf("namespace/overlays = %+v/%v", spec.NetNS, spec.Overlays)
			}
			if spec.Mode != bird.BirdModeManaged || spec.RouterID != 123 {
				t.Fatalf("mode/router ID = %s/%d", spec.Mode, spec.RouterID)
			}
			enabled := mode == UpstreamModeStatic || mode == UpstreamModeExternal
			if (spec.Upstream != nil) != enabled {
				t.Fatalf("upstream = %+v", spec.Upstream)
			}
			if mode == UpstreamModeExternal {
				if len(spec.StaticRoutes) != 0 {
					t.Fatalf("external upstream routes = %v", spec.StaticRoutes)
				}
				return
			}
			if len(spec.StaticRoutes) != 2 {
				t.Fatalf("routes = %v", spec.StaticRoutes)
			}
			for _, route := range spec.StaticRoutes {
				if route.Prefix != v4 && route.Prefix != v6 {
					t.Fatalf("nonlocal route: %v", route)
				}
				if mode == UpstreamModeStatic {
					want := netip.MustParseAddr("fe80::2")
					if route.Prefix.Addr().Is4() {
						want = netip.MustParseAddr("169.254.0.2")
					}
					if route.Via != "to-host" || route.NextHop != want {
						t.Fatalf("static next hop: %+v", route)
					}
				} else if route.Via != "" || route.NextHop.IsValid() {
					t.Fatalf("unexpected next hop: %+v", route)
				}
			}
			if len(inst.Bird.Overlays) != 0 || len(inst.Bird.StaticRoutes) != 0 {
				t.Fatal("builder mutated configuration")
			}
		})
	}
}

func TestBirdRotateInterfacePoliciesPromoteStagedAndDrainOld(t *testing.T) {
	observationLinks := map[string]ipsec.LinkInstance{
		"link-1": {
			ID:                    "link-1",
			GroupID:               "main",
			ActualState:           "up",
			InterfaceName:         "phx-old",
			LocalTunnelAddr:       netip.MustParseAddr("fe80::1"),
			PeerTunnelAddr:        netip.MustParseAddr("fe80::2"),
			StagedGeneration:      2,
			RotatePhase:           ipsec.RotatePhaseDualRunning,
			StagedInterfaceName:   "phx-new",
			StagedLocalTunnelAddr: netip.MustParseAddr("fe80::3"),
			StagedPeerTunnelAddr:  netip.MustParseAddr("fe80::4"),
		},
	}
	outputs := []photonstate.LinkOutput{
		{ID: "link-1", GroupID: "main", InterfaceName: "phx-old", RuntimeRole: photonstate.LinkRuntimeActive},
		{ID: "link-1#staged", GroupID: "main", InterfaceName: "phx-new", RuntimeRole: photonstate.LinkRuntimeStaged},
	}
	routingInst := RoutingInstance{
		Bird: bird.BirdInstanceSpec{
			NetNSName: "photon", Overlays: []string{"main"},
			MetricBase:     100,
			MetricStaged:   200,
			MetricDraining: 500,
		}}

	wantPolicies := func(phase string, want map[string]uint) {
		t.Helper()
		instance := observationLinks["link-1"]
		instance.RotatePhase = phase
		observationLinks["link-1"] = instance
		got := BirdRotateInterfacePolicies(observationLinks, outputs, routingInst.Bird)
		gotMap := make(map[string]uint, len(got))
		for _, policy := range got {
			gotMap[policy.InterfaceName] = policy.Metric
		}
		if !reflect.DeepEqual(gotMap, want) {
			t.Fatalf("phase %q policies = %#v, want %#v", phase, gotMap, want)
		}
	}

	wantPolicies(ipsec.RotatePhaseDualRunning, map[string]uint{"phx-old": 100, "phx-new": 200})
	wantPolicies(ipsec.RotatePhaseDraining, map[string]uint{"phx-old": 500, "phx-new": 100})
}

func TestBirdRotateInterfacePoliciesFiltersAndMerges(t *testing.T) {
	instances := map[string]ipsec.LinkInstance{
		"runtime-a": {ID: "runtime-a", LinkID: "link-a", StagedInterfaceName: "new-a", RotatePhase: ipsec.RotatePhaseDraining},
		"runtime-b": {ID: "link-b", StagedInterfaceName: "new-b", RotatePhase: ipsec.RotatePhaseDualRunning},
		"idle":      {ID: "idle"},
	}
	spec := bird.BirdInstanceSpec{NetNSName: "mesh", Overlays: []string{"main"}, MetricBase: 100, MetricStaged: 200, MetricDraining: 500}
	outputs := []photonstate.LinkOutput{
		{ID: "link-a", GroupID: "main", NetNS: "mesh", InterfaceName: "shared"},
		{ID: "link-b", GroupID: "main", InterfaceName: "shared"},
		{ID: "link-a#staged", GroupID: "main", InterfaceName: "new-a", RuntimeRole: photonstate.LinkRuntimeStaged},
		{ID: "link-b#staged", GroupID: "main", InterfaceName: "new-b", RuntimeRole: photonstate.LinkRuntimeStaged},
		{ID: "link-a", GroupID: "main", NetNS: "other", InterfaceName: "wrong-ns"},
		{ID: "link-a", GroupID: "other", NetNS: "mesh", InterfaceName: "wrong-overlay"},
		{ID: "missing", GroupID: "main", InterfaceName: "missing"},
		{ID: "idle", GroupID: "main", InterfaceName: "idle"},
		{ID: "link-a", GroupID: "main"},
	}
	want := []bird.BabelInterfacePolicy{{InterfaceName: "new-a", Metric: 100}, {InterfaceName: "new-b", Metric: 200}, {InterfaceName: "shared", Metric: 500}}
	if got := BirdRotateInterfacePolicies(instances, outputs, spec); !reflect.DeepEqual(got, want) {
		t.Fatalf("policies = %v, want %v", got, want)
	}
	slices.Reverse(outputs)
	if got := BirdRotateInterfacePolicies(instances, outputs, spec); !reflect.DeepEqual(got, want) {
		t.Fatalf("reversed input policies = %v", got)
	}
	// No overlay filter accepts every overlay, but never a different namespace.
	if !LinkOutputBelongsToBirdInstance(photonstate.LinkOutput{GroupID: "other"}, "mesh", nil) || LinkOutputBelongsToBirdInstance(photonstate.LinkOutput{NetNS: "other"}, "mesh", nil) {
		t.Fatal("unfiltered overlay changed namespace matching")
	}
}
