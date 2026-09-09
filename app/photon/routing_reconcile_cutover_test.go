package main

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux/linkstate"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestReconcileRoutingFeedsBirdObservationToRotateCutoverGate(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestRoutingOwners(t)
	now := time.Unix(4000, 0)

	appConfig := defaultAppConfig()
	appConfig.DataDir = t.TempDir()
	appConfig.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{
		ID:              "main",
		Provider:        ipsec.ProviderStrongSwan,
		NetNS:           ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "photontesth2", Create: true},
		DefaultPathMode: ipsec.PathModeFamilyRedundant,
	}}
	appConfig.Netns = netnsConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = parseRoutingConfigInstances([]routingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	observationLinks := map[string]linkInstanceState{
		"link-1": {
			ID:                  "link-1",
			GroupID:             "main",
			ActualState:         "up",
			InterfaceName:       "phx-old",
			StagedInterfaceName: "phx-new",
		},
	}

	rt := &AppContext{
		Config: appConfig,
		Clock:  func() time.Time { return now },
	}

	manager := health.NewManager(
		health.ProbeConfig{Interval: -time.Second, Timeout: 100 * time.Millisecond, Burst: 1, LossWindow: 5, MaxConcurrent: 2},
		health.DefaultHysteresisConfig(),
		successfulHealthProber{},
	)
	manager.UpsertTarget(health.ProbeTarget{
		ProbeID:        linkstate.ProbeID("link-1", "staged"),
		InstanceID:     "link-1",
		ProbeRole:      "staged",
		InterfaceName:  "phx-new",
		PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"),
		State:          "up",
		Staged:         true,
	}, now)
	if dispatched := manager.Tick(context.Background(), now); dispatched != 1 {
		t.Fatalf("health probes dispatched = %d, want 1", dispatched)
	}

	client := &fakeBirdClient{status: &bird.BirdObservation{
		Neighbors: []bird.BirdNeighbor{{Interface: "phx-new", Metric: 96}},
	}}
	service := newTestDaemonFromOwners(rt, verified, checkpoint, runtime, config, time.Second)
	setTestIPsecObservation(service, observationLinks, nil)
	service.health = &healthDriver{Manager: manager}
	installTestBirdDrivers(service, &fakeBirdProcessManager{running: false}, func(socketPath string, timeout time.Duration) birdClient {
		return client
	})

	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting without staged route: %v", err)
	}
	if ready := service.ipsecRotateCutoverReady()["link-1"]; ready {
		t.Fatalf("cutover should stay blocked until BIRD has a staged route")
	}

	client.status = &bird.BirdObservation{
		Neighbors: []bird.BirdNeighbor{{Interface: "phx-new", Metric: 96, Routes: 1}},
	}
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting with staged neighbor route: %v", err)
	}
	if ready := service.ipsecRotateCutoverReady()["link-1"]; !ready {
		t.Fatalf("cutover should be ready after BIRD neighbor and staged route converge")
	}

	client.statusErr = errors.New("birdc unavailable")
	if err := service.reconcileRouting(context.Background()); err != nil {
		t.Fatalf("reconcileRouting with stale BIRD observation: %v", err)
	}
	if ready := service.ipsecRotateCutoverReady()["link-1"]; ready {
		t.Fatalf("cutover should be blocked when fresh BIRD observation is unavailable")
	}
}

func TestBirdObservationAcceptsUnselectedBabelRouteOnStagedInterface(t *testing.T) {
	observed := &bird.BirdObservation{
		Neighbors: []bird.BirdNeighbor{{Interface: "phx-new", Metric: 128}},
		Routes: []bird.BirdRoute{{
			Iface:    "phx-new",
			Protocol: "babel1",
			Selected: false,
			Metric:   96,
		}},
	}
	obs := birdObservationForInterface("link-1", "link-1#staged", "phx-new", observed)
	if !obs.Neighbor || !obs.Route || obs.Metric != 96 {
		t.Fatalf("observation = %+v, want neighbor and unselected staged route", obs)
	}
}

func TestBirdRotateInterfacePoliciesPromoteStagedAndDrainOld(t *testing.T) {
	observationLinks := map[string]linkInstanceState{
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
	var observationReconcile *ipsecObservationSummary
	routingInst := RoutingInstance{MetricBase: 100, MetricStaged: 200, MetricDraining: 500}

	wantPolicies := func(phase string, want map[string]uint) {
		t.Helper()
		instance := observationLinks["link-1"]
		instance.RotatePhase = phase
		observationLinks["link-1"] = instance
		got := birdRotateInterfacePolicies(observationLinks, observationReconcile, "photon", []string{"main"}, routingInst)
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
