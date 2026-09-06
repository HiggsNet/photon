package main

import (
	"context"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux/linkstate"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestHealthTargetsParseScopedNetNS(t *testing.T) {
	managedZone := zone.ZonePath("node-a.catofes.")
	runtime := &linuxRuntimeState{
		LinkInstances: map[string]linkInstanceState{
			"link-1": {ActualState: "up"},
		},
		IPsecReconcile: &ipsecReconcileState{
			Desired: []desiredLinkState{{
				InstanceID:      "link-1",
				GroupID:         "blue",
				PeerZone:        zone.ZonePath("node-b.catofes."),
				InterfaceName:   "phx0",
				LocalTunnelAddr: "fd00::1%phx0 netns=photontesth2",
				PeerTunnelAddr:  "fd00::2%phx0 netns=photontesth2",
			}},
		},
	}

	targets := linkstate.HealthTargets(buildLinkOutputs(runtime.LinkInstances, runtime.IPsecReconcile), string(managedZone))
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	target := targets[0]
	if target.NetNS != "photontesth2" {
		t.Fatalf("target NetNS = %q, want photontesth2", target.NetNS)
	}
	if got := target.PeerTunnelAddr.String(); got != "fd00::2" {
		t.Fatalf("peer tunnel addr = %q, want fd00::2", got)
	}
	if got := target.LocalTunnelAddr.String(); got != "fd00::1" {
		t.Fatalf("local tunnel addr = %q, want fd00::1", got)
	}
}

func TestHealthTargetsUseRotatedRuntimeInterface(t *testing.T) {
	managedZone := zone.ZonePath("node-a.catofes.")
	runtime := &linuxRuntimeState{
		LinkInstances: map[string]linkInstanceState{
			"link-1": {
				ActualState:           "up",
				InterfaceName:         "phx-old",
				LocalTunnelAddr:       "fe80::10",
				PeerTunnelAddr:        "fe80::20",
				StagedGeneration:      2,
				RotatePhase:           "testing_new",
				StagedInterfaceName:   "phx-new",
				StagedLocalTunnelAddr: "fe80::11",
				StagedPeerTunnelAddr:  "fe80::21",
			},
		},
		IPsecReconcile: &ipsecReconcileState{
			Desired: []desiredLinkState{{
				InstanceID:      "link-1",
				GroupID:         "blue",
				PeerZone:        zone.ZonePath("node-b.catofes."),
				InterfaceName:   "phx-desired",
				LocalTunnelAddr: "fe80::1%phx-desired netns=photontesth2",
				PeerTunnelAddr:  "fe80::2%phx-desired netns=photontesth2",
			}},
		},
	}

	targets := linkstate.HealthTargets(buildLinkOutputs(runtime.LinkInstances, runtime.IPsecReconcile), string(managedZone))
	if len(targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(targets))
	}
	byRole := map[string]health.ProbeTarget{}
	for _, target := range targets {
		byRole[target.ProbeRole] = target
	}
	if old := byRole["old"]; old.InterfaceName != "phx-old" || old.ProbeID != "link-1#old" || old.Staged {
		t.Fatalf("old target = %+v, want old interface without staged flag", old)
	}
	if old := byRole["old"]; old.LocalTunnelAddr.String() != "fe80::10" || old.PeerTunnelAddr.String() != "fe80::20" {
		t.Fatalf("old target addrs = %s/%s, want persisted old runtime addrs", old.LocalTunnelAddr, old.PeerTunnelAddr)
	}
	if staged := byRole["staged"]; staged.InterfaceName != "phx-new" || staged.ProbeID != "link-1#staged" || !staged.Staged {
		t.Fatalf("staged target = %+v, want staged interface", staged)
	}
	if staged := byRole["staged"]; staged.LocalTunnelAddr.String() != "fe80::11" || staged.PeerTunnelAddr.String() != "fe80::21" {
		t.Fatalf("staged target addrs = %s/%s, want persisted staged runtime addrs", staged.LocalTunnelAddr, staged.PeerTunnelAddr)
	}
	if staged := byRole["staged"]; staged.State != "up" {
		t.Fatalf("staged target state = %q, want up", staged.State)
	}
}

func TestHealthTargetsUsePersistedDesiredTunnelAddressesForActive(t *testing.T) {
	local := zone.ZonePath("less.catofes.")
	peer := zone.ZonePath("more.catofes.")
	group := ipsec.LinkGroupSpec{ID: "blue"}.Normalized()
	runtime := &linuxRuntimeState{
		LinkInstances: map[string]linkInstanceState{
			"link-1": {
				ID:               "link-1",
				ActualState:      "up",
				InterfaceName:    "phxa0f3bb66",
				RemoteGeneration: 1,
			},
		},
		IPsecReconcile: &ipsecReconcileState{
			Desired: []desiredLinkState{{
				InstanceID:      "link-1",
				GroupID:         group.ID,
				PeerZone:        peer,
				LinkID:          "link-1",
				PathKey:         "family:ipv4",
				InterfaceName:   "phxa0f3bb66",
				LocalTunnelAddr: "fe80::7454:3eca:1ff:6f5a%phxa0f3bb66 netns=photontesth2",
				PeerTunnelAddr:  "fe80::91eb:8d94:108b:d6d%phxa0f3bb66 netns=photontesth2",
			}},
		},
	}

	targets := linkstate.HealthTargets(buildLinkOutputs(runtime.LinkInstances, runtime.IPsecReconcile), string(local))
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	target := targets[0]
	if got := target.LocalTunnelAddr.String(); got != "fe80::7454:3eca:1ff:6f5a" {
		t.Fatalf("local tunnel addr = %q, want persisted desired address", got)
	}
	if got := target.PeerTunnelAddr.String(); got != "fe80::91eb:8d94:108b:d6d" {
		t.Fatalf("peer tunnel addr = %q, want persisted desired address", got)
	}
	if target.InterfaceName != "phxa0f3bb66" || target.NetNS != "photontesth2" {
		t.Fatalf("target scope = iface %q netns %q, want phxa0f3bb66/photontesth2", target.InterfaceName, target.NetNS)
	}
	if target.UnderlayFamily != ipsec.FamilyIPv4 {
		t.Fatalf("underlay family = %q, want ipv4", target.UnderlayFamily)
	}
}

func TestHealthTargetsSkipRotateProbeWithoutPersistedRuntimeTunnelAddresses(t *testing.T) {
	local := zone.ZonePath("node-a.catofes.")
	peer := zone.ZonePath("node-b.catofes.")
	group := ipsec.LinkGroupSpec{ID: "blue"}.Normalized()
	linkID := "link-1"
	pathKey := "family:ipv4"
	newLocal, newPeer, err := group.DeriveTunnelAddressesForLink(local, peer, linkID, pathKey, 2, 0)
	if err != nil {
		t.Fatalf("derive staged tunnel addresses: %v", err)
	}
	runtime := &linuxRuntimeState{
		LinkInstances: map[string]linkInstanceState{
			linkID: {
				ID:                  linkID,
				ActualState:         "up",
				InterfaceName:       "phx-old",
				RemoteGeneration:    1,
				StagedGeneration:    2,
				RotatePhase:         "testing_new",
				StagedInterfaceName: "phx-new",
			},
		},
		IPsecReconcile: &ipsecReconcileState{
			Desired: []desiredLinkState{{
				InstanceID:      linkID,
				GroupID:         group.ID,
				PeerZone:        peer,
				LinkID:          linkID,
				PathKey:         pathKey,
				InterfaceName:   "phx-new",
				LocalTunnelAddr: ipsec.FormatScopedTunnelAddress(newLocal, "phx-new", "photontesth2"),
				PeerTunnelAddr:  ipsec.FormatScopedTunnelAddress(newPeer, "phx-new", "photontesth2"),
			}},
		},
	}

	targets := linkstate.HealthTargets(buildLinkOutputs(runtime.LinkInstances, runtime.IPsecReconcile), string(local))
	if len(targets) != 0 {
		t.Fatalf("targets = %+v, want no guessed rotate probes without persisted runtime tunnel addrs", targets)
	}
}

func TestConfigureHealthManagerUsesRealProber(t *testing.T) {
	cfg := defaultHealthConfig()
	cfg.Enabled = true
	cfg.Interval = time.Nanosecond
	cfg.Timeout = time.Nanosecond
	cfg.Jitter = 0
	cfg.FailThreshold = 1

	d := &Daemon{
		App: &AppContext{Config: &appConfig{Health: cfg}},
	}
	driver := &ipsec.DryRunDriver{}
	d.linuxDriver = newTestLinuxDriver(driver, driver)
	t.Cleanup(func() { _ = d.closeLinuxDriver() })
	d.configureHealthManager()
	if d.health == nil {
		t.Fatal("health manager was not configured")
	}

	now := time.Unix(100, 0)
	d.health.SetTargets([]health.ProbeTarget{{
		InstanceID: "link-1",
		State:      "up",
	}}, now)
	if got := d.health.Tick(context.Background(), now.Add(time.Second)); got != 1 {
		t.Fatalf("dispatched probes = %d, want 1", got)
	}
	snapshot := d.health.Snapshot(now.Add(time.Second))
	if len(snapshot) != 1 {
		t.Fatalf("snapshot links = %d, want 1", len(snapshot))
	}
	if strings.Contains(snapshot[0].LastError, "no prober configured") {
		t.Fatalf("health manager used nop prober: last_error=%q", snapshot[0].LastError)
	}
	if snapshot[0].LastError != "peer address missing" {
		t.Fatalf("last_error = %q, want peer address missing", snapshot[0].LastError)
	}
}

func TestHealthStatusAndMetricsUsePacketCounts(t *testing.T) {
	now := time.Unix(1500, 0)
	cfg := defaultHealthConfig()
	cfg.MetricsEnabled = true
	cfg.LocalSpoolPath = t.TempDir()
	cfg.LocalSpoolMaxAge = time.Hour
	manager := health.NewManager(health.ProbeConfig{
		Interval:      time.Nanosecond,
		Burst:         3,
		LossWindow:    20,
		MaxConcurrent: 1,
	}, health.DefaultHysteresisConfig(), packetCountHealthProber{})
	manager.SetTargets([]health.ProbeTarget{{
		InstanceID:     "link-1",
		PeerTunnelAddr: netip.MustParseAddr("192.0.2.2"),
		State:          "up",
	}}, now)
	if got := manager.Tick(context.Background(), now.Add(time.Second)); got != 1 {
		t.Fatalf("dispatched probes = %d, want 1", got)
	}
	d := &Daemon{
		App:    &AppContext{Config: &appConfig{Health: cfg}, Clock: func() time.Time { return now.Add(time.Second) }},
		health: &healthDriver{Manager: manager},
	}
	links := d.healthStatusResponse()
	if len(links) != 1 || links[0].Sent != 3 || links[0].Received != 2 || links[0].Lost != 1 || links[0].LossRatio != 33 || links[0].State != health.HealthStateDegraded {
		t.Fatalf("health status = %+v, want degraded with packet counts 3/2/1 and 33%% loss", links)
	}
	metrics, err := (&observerProvider{daemon: d}).OpenMetrics()
	if err != nil {
		t.Fatalf("OpenMetrics: %v", err)
	}
	for _, want := range []string{
		"photon_link_probe_packets_sent{",
		"} 3\n",
		"photon_link_probe_packets_received{",
		"} 2\n",
		"photon_link_probe_packets_lost{",
		"} 1\n",
	} {
		if !strings.Contains(metrics, want) {
			t.Fatalf("OpenMetrics missing %q:\n%s", want, metrics)
		}
	}
}

type packetCountHealthProber struct{}

func (packetCountHealthProber) Probe(_ context.Context, target health.ProbeTarget, _ health.ProbeConfig) health.ProbeResult {
	return health.ProbeResult{
		InstanceID: target.InstanceID,
		Sent:       3,
		Received:   2,
		Lost:       1,
		RTT:        5 * time.Millisecond,
		Success:    true,
	}
}

func (packetCountHealthProber) Type() string { return health.ProbeTypeICMP }
