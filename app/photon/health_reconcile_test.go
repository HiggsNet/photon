package main

import (
	"context"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestHealthTargetsParseScopedNetNS(t *testing.T) {
	managedZone := zone.ZonePath("node-a.catofes.")
	links := map[string]ipsec.LinkInstance{
		"link-1": {ActualState: "up"},
	}
	reconcile := &ipsecObservationSummary{
		Desired: []photonstate.DesiredLinkObservation{{
			InstanceID:      "link-1",
			GroupID:         "blue",
			PeerZone:        zone.ZonePath("node-b.catofes."),
			InterfaceName:   "phx0",
			LocalTunnelAddr: "fd00::1%phx0 netns=photontesth2",
			PeerTunnelAddr:  "fd00::2%phx0 netns=photontesth2",
		}},
	}

	targets := healthTargets(buildLinkOutputs(links, reconcile), string(managedZone), false)
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
	links := map[string]ipsec.LinkInstance{
		"link-1": {
			ActualState:           "up",
			InterfaceName:         "phx-old",
			LocalTunnelAddr:       netip.MustParseAddr("fe80::10"),
			PeerTunnelAddr:        netip.MustParseAddr("fe80::20"),
			StagedGeneration:      2,
			RotatePhase:           "testing_new",
			StagedInterfaceName:   "phx-new",
			StagedLocalTunnelAddr: netip.MustParseAddr("fe80::11"),
			StagedPeerTunnelAddr:  netip.MustParseAddr("fe80::21"),
		},
	}
	reconcile := &ipsecObservationSummary{
		Desired: []photonstate.DesiredLinkObservation{{
			InstanceID:      "link-1",
			GroupID:         "blue",
			PeerZone:        zone.ZonePath("node-b.catofes."),
			InterfaceName:   "phx-desired",
			LocalTunnelAddr: "fe80::1%phx-desired netns=photontesth2",
			PeerTunnelAddr:  "fe80::2%phx-desired netns=photontesth2",
		}},
	}

	targets := healthTargets(buildLinkOutputs(links, reconcile), string(managedZone), false)
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
		t.Fatalf("old target addrs = %s/%s, want observed old runtime addrs", old.LocalTunnelAddr, old.PeerTunnelAddr)
	}
	if staged := byRole["staged"]; staged.InterfaceName != "phx-new" || staged.ProbeID != "link-1#staged" || !staged.Staged {
		t.Fatalf("staged target = %+v, want staged interface", staged)
	}
	if staged := byRole["staged"]; staged.LocalTunnelAddr.String() != "fe80::11" || staged.PeerTunnelAddr.String() != "fe80::21" {
		t.Fatalf("staged target addrs = %s/%s, want observed staged runtime addrs", staged.LocalTunnelAddr, staged.PeerTunnelAddr)
	}
	if staged := byRole["staged"]; staged.State != "up" {
		t.Fatalf("staged target state = %q, want up", staged.State)
	}
}

func TestHealthTargetsUseObservedDesiredTunnelAddressesForActive(t *testing.T) {
	local := zone.ZonePath("less.catofes.")
	peer := zone.ZonePath("more.catofes.")
	group := ipsec.LinkGroupSpec{ID: "blue"}.Normalized()
	links := map[string]ipsec.LinkInstance{
		"link-1": {
			ID:               "link-1",
			ActualState:      "up",
			InterfaceName:    "phxa0f3bb66",
			RemoteGeneration: 1,
		},
	}
	reconcile := &ipsecObservationSummary{
		Desired: []photonstate.DesiredLinkObservation{{
			InstanceID:      "link-1",
			GroupID:         group.ID,
			PeerZone:        peer,
			LinkID:          "link-1",
			PathKey:         "family:ipv4",
			InterfaceName:   "phxa0f3bb66",
			LocalTunnelAddr: "fe80::7454:3eca:1ff:6f5a%phxa0f3bb66 netns=photontesth2",
			PeerTunnelAddr:  "fe80::91eb:8d94:108b:d6d%phxa0f3bb66 netns=photontesth2",
		}},
	}

	targets := healthTargets(buildLinkOutputs(links, reconcile), string(local), false)
	if len(targets) != 1 {
		t.Fatalf("targets = %d, want 1", len(targets))
	}
	target := targets[0]
	if got := target.LocalTunnelAddr.String(); got != "fe80::7454:3eca:1ff:6f5a" {
		t.Fatalf("local tunnel addr = %q, want observed desired address", got)
	}
	if got := target.PeerTunnelAddr.String(); got != "fe80::91eb:8d94:108b:d6d" {
		t.Fatalf("peer tunnel addr = %q, want observed desired address", got)
	}
	if target.InterfaceName != "phxa0f3bb66" || target.NetNS != "photontesth2" {
		t.Fatalf("target scope = iface %q netns %q, want phxa0f3bb66/photontesth2", target.InterfaceName, target.NetNS)
	}
	if target.UnderlayFamily != ipsec.FamilyIPv4 {
		t.Fatalf("underlay family = %q, want ipv4", target.UnderlayFamily)
	}
}

func TestHealthTargetsSkipRotateProbeWithoutObservedRuntimeTunnelAddresses(t *testing.T) {
	local := zone.ZonePath("node-a.catofes.")
	peer := zone.ZonePath("node-b.catofes.")
	group := ipsec.LinkGroupSpec{ID: "blue"}.Normalized()
	linkID := "link-1"
	pathKey := "family:ipv4"
	newLocal, newPeer, err := group.DeriveTunnelAddressesForLink(local, peer, linkID, pathKey, 2, 0)
	if err != nil {
		t.Fatalf("derive staged tunnel addresses: %v", err)
	}
	links := map[string]ipsec.LinkInstance{
		linkID: {
			ID:                  linkID,
			ActualState:         "up",
			InterfaceName:       "phx-old",
			RemoteGeneration:    1,
			StagedGeneration:    2,
			RotatePhase:         "testing_new",
			StagedInterfaceName: "phx-new",
		},
	}
	reconcile := &ipsecObservationSummary{
		Desired: []photonstate.DesiredLinkObservation{{
			InstanceID:      linkID,
			GroupID:         group.ID,
			PeerZone:        peer,
			LinkID:          linkID,
			PathKey:         pathKey,
			InterfaceName:   "phx-new",
			LocalTunnelAddr: ipsec.FormatScopedTunnelAddress(newLocal, "phx-new", "photontesth2"),
			PeerTunnelAddr:  ipsec.FormatScopedTunnelAddress(newPeer, "phx-new", "photontesth2"),
		}},
	}

	targets := healthTargets(buildLinkOutputs(links, reconcile), string(local), false)
	if len(targets) != 0 {
		t.Fatalf("targets = %+v, want no guessed rotate probes without observed runtime tunnel addrs", targets)
	}
}

func TestReconcileHealthWaitsForEachInstalledChild(t *testing.T) {
	now := time.Unix(100, 0)
	d := &Daemon{
		State: newState(nil, corestate.NewStoreWithCheckpoint(&corestate.VerifiedState{}, nil, nil, nil), nil),
		clock: func() time.Time { return now },
		health: &healthDriver{Manager: health.NewManager(
			health.ProbeConfig{Interval: -time.Second, Burst: 1}, health.DefaultHysteresisConfig(), packetCountHealthProber{},
		)},
	}
	link := ipsec.LinkInstance{
		ID: "link-1", IKEName: "ike-old", XFRMIfID: 11, InterfaceName: "phx-old",
		ActualState: ipsec.LinkStateConnecting, RemoteGeneration: 1,
		LocalTunnelAddr: netip.MustParseAddr("fe80::1"), PeerTunnelAddr: netip.MustParseAddr("fe80::2"),
	}
	old := photonstate.LinkSAObservation{Name: "ike-old", IKEState: "ESTABLISHED", Established: true}
	checkProbes := func(want []string, sas ...photonstate.LinkSAObservation) {
		t.Helper()
		d.linuxObservation.replaceIPsec(map[string]ipsec.LinkInstance{link.ID: link}, &ipsecObservationSummary{ActualSAs: sas})
		if got := d.reconcileHealth(t.Context()); got != len(want) {
			t.Fatalf("dispatched %d probes, want %v", got, want)
		}
		var got []string
		for _, probe := range d.health.Snapshot(now) {
			got = append(got, probe.ProbeID)
		}
		if !slices.Equal(got, want) {
			t.Fatalf("probes = %v, want %v", got, want)
		}
	}

	checkProbes(nil, old)
	link.ActualState = ipsec.LinkStateUp
	checkProbes(nil, old) // IKE alone can already mark the link up.
	old.ChildState, old.XFRMIfID = "INSTALLED", 11
	checkProbes([]string{"link-1"}, old)

	link.ActualState = ipsec.LinkStateConnecting // Preparing the new generation keeps the old SA.
	link.StagedGeneration, link.StagedIKEName, link.StagedXFRMIfID = 2, "ike-new", 22
	link.StagedInterfaceName = "phx-new"
	link.StagedLocalTunnelAddr, link.StagedPeerTunnelAddr = netip.MustParseAddr("fe80::3"), netip.MustParseAddr("fe80::4")
	staged := photonstate.LinkSAObservation{Name: "ike-new", XFRMIfID: 11, ChildState: "INSTALLED"}
	checkProbes([]string{"link-1#old"}, old, staged)
	staged.XFRMIfID = 22
	checkProbes([]string{"link-1#old", "link-1#staged"}, old, staged)
	checkProbes([]string{"link-1#staged"}, staged)
	checkProbes(nil)
}

func TestConfigureHealthManagerUsesRealProber(t *testing.T) {
	cfg := defaultHealthConfig()
	cfg.Enabled = true
	cfg.Probe.Interval = time.Nanosecond
	cfg.Probe.Timeout = time.Nanosecond
	cfg.Probe.Jitter = 0
	cfg.Hysteresis.FailThresholdConsecutive = 1

	d := &Daemon{Config: &appConfig{Health: cfg}}
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
	if failure := snapshot[0].LastFailure; failure != nil && strings.Contains(failure.Error(), "no prober configured") {
		t.Fatalf("health manager used nop prober: last_failure=%v", failure)
	}
	if failure := snapshot[0].LastFailure; failure == nil || failure.Error() != "peer address missing" {
		t.Fatalf("last_failure = %v, want peer address missing", failure)
	}
}

func TestHealthStatusAndMetricsUsePacketCounts(t *testing.T) {
	now := time.Unix(1500, 0)
	cfg := defaultHealthConfig()
	cfg.Spool.Enabled = true
	cfg.Spool.Path = t.TempDir()
	cfg.Spool.MaxAge = time.Hour
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
	d := &Daemon{Config: &appConfig{Health: cfg}, clock: func() time.Time { return now.Add(time.Second) }, health: &healthDriver{Manager: manager}}
	links := d.healthSamples()
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

func TestLargeHealthProjectionSpoolAndMetrics(t *testing.T) {
	now := time.Unix(1500, 0)
	h := health.LinkHealth{
		InstanceID: "link-1", ProbeID: "link-1#staged", ProbeRole: "staged", Sent: 60, Received: 59, Lost: 1,
		LargeProbe: &health.LargeProbeHealth{
			PacketSize: 1200, Interval: time.Minute, LossWindow: 60,
			Sent: 60, Received: 48, Lost: 12, LossRatio: .2, LastRTT: 10 * time.Millisecond,
			LastProbeAt: now, NextProbeAt: now.Add(time.Minute),
		},
	}
	samples := healthSamplesFromSnapshot([]health.LinkHealth{h})
	large := samples[0].LargeProbe
	if large == nil || large.LossRatioPct != 20 || large.Sent != 60 || large.Lost != 12 || large.PacketSize != 1200 || large.LastProbeUnix != now.Unix() {
		t.Fatalf("large view = %+v", large)
	}
	spool := healthSpoolSamples(samples)
	if spool[0].LargeProbe == nil || spool[0].LargeProbe.Lost != 12 || spool[0].Lost != 1 {
		t.Fatalf("spool mixed packet sizes: %+v", spool)
	}
	metrics := health.CollectMetrics([]health.LinkHealth{h})
	values := map[string]float64{}
	for _, sample := range metrics.Samples {
		values[sample.Name] = sample.Value
	}
	if values["photon_link_large_probe_loss_ratio"] != .2 || values["photon_link_large_probe_packets_sent"] != 60 || values["photon_link_probe_packets_lost"] != 1 {
		t.Fatalf("metrics mixed packet sizes: %+v", values)
	}
	if empty := largeProbeSample(&health.LargeProbeHealth{}); empty.LastProbeUnix != 0 || empty.NextProbeUnix != 0 {
		t.Fatal("zero timestamps leaked as negative Unix times")
	}
}
