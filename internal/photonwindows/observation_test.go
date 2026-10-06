package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	"github.com/HiggsNet/photon/pkg/core/observability"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestDaemonObservationLifecycle(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"}
	d := NewDaemon(config, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if _, err := d.Observe(t.Context()); !errors.Is(err, ErrDaemonNotRunning) {
		t.Fatalf("before run: %v", err)
	}
	if err := d.Stop(t.Context()); !errors.Is(err, ErrDaemonNotRunning) {
		t.Fatalf("stop before run: %v", err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	run := make(chan error, 1)
	go func() { run <- d.Run(ctx) }()
	select {
	case <-d.Started():
	case err := <-run:
		t.Fatalf("startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("startup timeout")
	}
	defer d.Stop(t.Context())
	first, err := d.Observe(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !first.Running || first.UDPAddress == "" || first.ObservedAt.IsZero() || first.IKE.Live || first.Wintun.Configured || first.TunnelReady {
		t.Fatalf("unestablished runtime: %+v", first)
	}
	if err := d.Rebind(t.Context()); err != nil {
		t.Fatal(err)
	}
	next, err := d.Observe(t.Context())
	if err != nil || next.UDPAddress == "" || next.TunnelReady || next.ObservedAt.Before(first.ObservedAt) {
		t.Fatalf("after rebind: %+v %v", next, err)
	}
	var wg sync.WaitGroup
	for range 8 {
		wg.Go(func() {
			for range 20 {
				_, err := d.Observe(t.Context())
				if err != nil && !errors.Is(err, net.ErrClosed) {
					t.Errorf("concurrent observe: %v", err)
					return
				}
			}
		})
	}
	for range 3 {
		wg.Go(func() {
			if err := d.Stop(t.Context()); err != nil {
				t.Errorf("concurrent stop: %v", err)
			}
		})
	}
	wg.Wait()
	if err := <-run; err != nil {
		t.Fatal(err)
	}
	if _, err := d.Observe(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("after stop: %v", err)
	}
	reopened := fixture.openState(t, fixture.leftPath, config.ManagedZone)
	reopened.Close()
}

func TestRuntimeObservationRequiresInstalledSource(t *testing.T) {
	f, r := observationFixture(t)
	other := "10.9.0.2/32"
	key, _ := routing.NormalizeIPAMAssignmentKey(other)
	f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: other, AssignedTo: f.config.ManagedZone, Active: true})
	key, _ = routing.NormalizeRouteAnnouncementKey(other)
	f.put(f.config.ManagedZone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: other, Active: true})
	update := babel.Message{Type: babel.TLVUpdate, Prefix: netip.MustParsePrefix("10.1.2.0/24"), RouterID: f.remoteID, NextHop: f.p.peer, Seqno: 8, Metric: 10, Interval: 1600}
	retract := update
	retract.Metric = babel.MetricInfinity
	update.SourcePrefix = netip.MustParsePrefix(other)
	payload, err := babel.Encode([]babel.Message{retract, update})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := babel.BuildPacket(f.p.peer, f.p.local, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !f.inbound(t, packet) {
		t.Fatal("control packet rejected")
	}
	got := observeRuntime(f.config, f.view, f.plan, f.now, f.p.tunnel.socket, f.p.tunnel, r, nil)
	if !got.Babel.Live || got.TunnelReady || len(got.Babel.Routes) != 0 || len(got.Wintun.Addresses) != 1 || got.Wintun.Addresses[0].String() != "10.9.0.1/32" {
		t.Fatalf("planned address leaked as usable: %+v", got)
	}
}

func TestRuntimeObservationBoundsPeerDiagnostics(t *testing.T) {
	f, r := observationFixture(t)
	driver := &corehost.GossipDriver{Observability: observability.NewPeerObservabilityStore(512, time.Hour)}
	for i := range 300 {
		driver.Observability.Update(fmt.Sprintf("peer-%03d", i), f.now, func(p *observability.PeerDiagnostics) {
			p.ActivePullState = strings.Repeat("x", 300)
			p.ActivePullUpdatedUnix = f.now.Unix()
			p.ObjectPullStats = &observability.PeerObjectPullStats{Attempts: 3, Successes: 2, Failures: 1}
		})
	}
	got := observeRuntime(f.config, f.view, f.plan, f.now, nil, f.p.tunnel, r, driver)
	if !got.PeersTruncated || len(got.Peers) != 256 || len(got.Peers[0].PullState) != 256 || got.Peers[0].Peer != "peer-000" || got.Peers[0].PullFailures != 1 {
		t.Fatalf("unbounded peer diagnostics: %+v", got.Peers[0])
	}
	got.Peers[0].PullAttempts = 99
	next := observeRuntime(f.config, f.view, f.plan, f.now, nil, f.p.tunnel, r, driver)
	if next.Peers[0].PullAttempts != 3 {
		t.Fatal("borrowed peer state")
	}
}

func TestDaemonFailedInitializationNeverStarts(t *testing.T) {
	d := NewDaemon(nil, nil)
	if err := d.Run(t.Context()); err == nil {
		t.Fatal("nil config accepted")
	}
	select {
	case <-d.Started():
		t.Fatal("failed initialization signaled start")
	default:
	}
	if _, err := d.Observe(t.Context()); !errors.Is(err, net.ErrClosed) {
		t.Fatal(err)
	}
	if err := d.Stop(t.Context()); err == nil {
		t.Fatal("stop lost initialization error")
	}
}

func observationFixture(t *testing.T) (*pipelineFixture, *leafRuntime) {
	f := runtimeFixture(t)
	device := newRuntimeDevice()
	r := newLeafRuntime(func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
		return device, nil
	})
	t.Cleanup(func() { r.close() })
	if err := r.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); err != nil {
		t.Fatal(err)
	}
	if err := r.complete(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now, runtimeOpenResult(t, r)); err != nil {
		t.Fatal(err)
	}
	f.p = r.pipeline
	f.learn(t)
	return f, r
}

func TestRuntimeObservationFreshAuthorizationAndExpiry(t *testing.T) {
	for _, scenario := range []string{"gateway-revoked", "child-expired", "neighbor-expired", "ike-expired", "stopped"} {
		t.Run(scenario, func(t *testing.T) {
			f, r := observationFixture(t)
			observe := func() Observation {
				return observeRuntime(f.config, f.view, f.plan, f.now, f.p.tunnel.socket, f.p.tunnel, r, nil)
			}
			original := observe()
			if !original.IKE.Live || !original.IKE.ChildLive || !original.Babel.Live || !original.TunnelReady || !original.Wintun.Configured || len(original.Babel.Routes) != 1 {
				t.Fatalf("initial: %+v", original)
			}
			original.Wintun.Addresses[0] = netip.MustParsePrefix("192.0.2.1/32")
			original.Babel.Routes[0].Origin = "mutated"
			if after := observe(); after.Wintun.Addresses[0] == original.Wintun.Addresses[0] || after.Babel.Routes[0].Origin == "mutated" {
				t.Fatal("borrowed runtime storage")
			}
			switch scenario {
			case "gateway-revoked":
				gateway := f.plan.Selected.Zone
				profile, err := ipsec.ParseProfileRecord(f.view.State.Network.Zones[gateway].Records[ipsec.RecordKeyProfile])
				if err != nil {
					t.Fatal(err)
				}
				profile.Enabled = false
				f.put(gateway, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, profile)
			case "child-expired":
				f.p.tunnel.expiresAt = f.now
			case "neighbor-expired":
				f.now = f.now.Add(2 * time.Minute)
			case "ike-expired":
				f.p.tunnel.ikeExpiresAt = f.now
			case "stopped":
				if err := r.stop(); err != nil {
					t.Fatal(err)
				}
				f.p.tunnel.stop()
			}
			after := observe()
			if after.TunnelReady || after.Babel.Live || len(after.Babel.Routes) != 0 {
				t.Fatalf("stale route readiness: %+v", after)
			}
			if scenario == "gateway-revoked" || scenario == "ike-expired" || scenario == "stopped" {
				if after.IKE.Live || after.IKE.ChildLive {
					t.Fatalf("stale SA: %+v", after.IKE)
				}
			}
			if scenario == "child-expired" && (!after.IKE.Live || after.IKE.ChildLive) {
				t.Fatalf("child lifetime: %+v", after.IKE)
			}
			if scenario == "stopped" && after.Wintun.Configured {
				t.Fatal("closed device reported configured")
			}
		})
	}
}

func TestRuntimeObservationBoundsAuthorizedRouteTable(t *testing.T) {
	f, r := observationFixture(t)
	var updates []babel.Message
	for i := range 270 {
		prefix := netip.PrefixFrom(netip.AddrFrom4([4]byte{10, 1, byte(3 + i/256), byte(i % 256)}), 32)
		key, _ := routing.NormalizeRouteAnnouncementKey(prefix.String())
		f.put(f.plan.Selected.Zone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix.String(), Active: true})
		updates = append(updates, babel.Message{Type: babel.TLVUpdate, Prefix: prefix, RouterID: f.remoteID, NextHop: f.p.peer, Seqno: 8, Metric: 10, Interval: 1600})
	}
	authorize := currentBabelRouteAuthorizer(f.config, f.view, f.now)
	for _, update := range updates {
		payload, err := babel.Encode([]babel.Message{update})
		if err != nil {
			t.Fatal(err)
		}
		packet, err := babel.BuildPacket(f.p.peer, f.p.local, payload)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.p.leaf.Receive(packet, f.now, authorize); err != nil {
			t.Fatal(err)
		}
	}
	got := observeRuntime(f.config, f.view, f.plan, f.now, nil, f.p.tunnel, r, nil)
	if !got.TunnelReady || !got.RoutesTruncated || len(got.Babel.Routes) != 256 {
		t.Fatalf("route bound: ready=%v truncated=%v routes=%d", got.TunnelReady, got.RoutesTruncated, len(got.Babel.Routes))
	}
}
