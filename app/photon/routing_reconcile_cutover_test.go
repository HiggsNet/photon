package main

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
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
	appConfig.Netns = photonlinux.NetNSConfig{Names: map[string]ipsec.NetNSSpec{"photontesth2": {Kind: ipsec.NetNSName, Name: "photontesth2", Create: true}}}
	appConfig.Routing, _ = photonlinux.ParseRoutingConfig([]photonlinux.RoutingInstanceYAML{{ID: "main", NetNS: "photontesth2", Enabled: boolPtr(true), Mode: ipsec.RoutingModeManaged}}, appConfig.Netns, appConfig.DataDir)

	observationLinks := map[string]ipsec.LinkInstance{
		"link-1": {
			ID:                  "link-1",
			GroupID:             "main",
			ActualState:         "up",
			InterfaceName:       "phx-old",
			StagedInterfaceName: "phx-new",
		},
	}

	rt := &testApp{Config: appConfig, Clock: func() time.Time { return now }}

	manager := health.NewManager(
		health.ProbeConfig{Interval: -time.Second, Timeout: 100 * time.Millisecond, Burst: 1, LossWindow: 5, MaxConcurrent: 2},
		health.DefaultHysteresisConfig(),
		successfulHealthProber{},
	)
	manager.UpsertTarget(health.ProbeTarget{
		ProbeID:        healthProbeID("link-1", "staged"),
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
