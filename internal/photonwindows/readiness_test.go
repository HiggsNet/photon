package photonwindows

import (
	"context"
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestReadinessUsesVerifiedUsableHostAssignmentAndAnnouncement(t *testing.T) {
	for _, scenario := range []string{"unassigned", "subnet", "shared", "outside-split", "revoked", "bad-assignment-signature", "unannounced", "manual-withdrawal", "usable-ipv4-only", "wrong-root", "missing-authority", "missing-parent"} {
		t.Run(scenario, func(t *testing.T) {
			config, view, now, put := gatewayPlanFixture(t)
			config.ManagedZone = "node-a.catofes."
			config.Overlay.SplitRoutes = append(config.Overlay.SplitRoutes, netip.MustParsePrefix("fd00::/8"))
			prefix := "10.9.0.1/32"
			assignment := routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: config.ManagedZone, Active: true}
			want := ReadinessStageAddressAssignment
			announce := false
			switch scenario {
			case "subnet":
				prefix, assignment.Prefix = "10.9.0.0/24", "10.9.0.0/24"
			case "shared":
				assignment.Shared = true
			case "outside-split":
				config.Overlay.SplitRoutes = []netip.Prefix{netip.MustParsePrefix("10.1.0.0/16")}
			case "revoked":
				assignment.Active = false
			case "unannounced", "manual-withdrawal":
				want = ReadinessStageAddressAnnouncement
			case "usable-ipv4-only":
				want, announce = "", true
			case "wrong-root":
				config.TrustedRootPublicKey = append([]byte(nil), config.TrustedRootPublicKey...)
				config.TrustedRootPublicKey[0] ^= 1
				want = ""
			case "missing-authority":
				view.State.Network.Zones[config.ManagedZone].Authority = nil
				want = ""
			case "missing-parent":
				view.State.Network.Zones[config.ManagedZone.Parent()].Authority = nil
				want = ""
			}
			key, _ := routing.NormalizeIPAMAssignmentKey(prefix)
			if scenario != "unassigned" {
				put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, assignment)
			}
			if scenario == "bad-assignment-signature" {
				view.State.Network.Zones[zone.RootZone].Records[key].Signature[0] ^= 1
			}
			if announce || scenario == "manual-withdrawal" {
				key, _ = routing.NormalizeRouteAnnouncementKey(prefix)
				put(config.ManagedZone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix, Active: announce})
			}
			got := observeLeafReadiness(config, view, now)
			if got.Stage != want || len(got.Reason) > 256 {
				t.Fatalf("readiness %+v, want stage %q", got, want)
			}
			if scenario == "wrong-root" || scenario == "missing-authority" || scenario == "missing-parent" {
				if got.Reason == "" {
					t.Fatal("missing trust failure detail")
				}
			} else if scenario == "usable-ipv4-only" {
				if got.Reason != "" {
					t.Fatalf("missing other address family reported as a blocker: %+v", got)
				}
			} else if got.Reason == "" {
				t.Fatal("missing canonical address rejection")
			}
			if scenario == "outside-split" && !strings.Contains(got.Reason, "configured split routes") {
				t.Fatal("outside-split address presented as an unconditional missing assignment")
			}
		})
	}
}

func TestReadinessUnavailableRouteAuthorityIsNotMissingAssignment(t *testing.T) {
	_, _, err := requiredLeafDeviceIntentFromSet(nil, nil)
	if !errors.Is(err, errLeafRouteAuthorityUnavailable) || errors.Is(err, errLeafHostAssignmentUnavailable) {
		t.Fatalf("unavailable authority confused with missing assignment: %v", err)
	}
}

func TestLeafRuntimeRecoversWhenSignedAssignmentArrives(t *testing.T) {
	f := runtimeFixture(t)
	key, _ := routing.NormalizeIPAMAssignmentKey("10.9.0.1/32")
	delete(f.view.State.Network.Zones[zone.RootZone].Records, key)
	device := newRuntimeDevice()
	opens := 0
	r := newLeafRuntime(func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
		opens++
		return device, nil
	})
	t.Cleanup(func() { r.close() })
	if err := r.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); !errors.Is(err, errLeafHostAssignmentUnavailable) {
		t.Fatalf("unassigned control plane unavailable: %v", err)
	}
	if opens != 0 || r.pending || r.device != nil || r.pipeline == nil || r.pipeline.device != nil || len(r.pipeline.addresses) != 0 {
		t.Fatal("unassigned node opened or attached a device")
	}
	f.p = r.pipeline
	f.learn(t)
	observation := func() Observation {
		return observeRuntime(f.config, f.view, f.plan, f.now, f.p.tunnel.socket, f.p.tunnel, r, nil)
	}
	before := observation()
	if before.Readiness.Stage != ReadinessStageAddressAssignment || before.TunnelReady || before.Wintun.Configured || !before.Babel.Live || !before.Babel.Local.IsLinkLocalUnicast() || before.Babel.Local != f.p.local || before.Babel.Neighbor != f.p.peer {
		t.Fatalf("missing assignment not observable: %+v", before)
	}
	// Synchronize a real signed root snapshot through the common store. Keep
	// the same SA, leaf runtime and device factory throughout the transition.
	applySignedHostAssignment(t, f)
	if err := r.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); err != nil {
		t.Fatal(err)
	}
	if err := r.complete(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now, runtimeOpenResult(t, r)); err != nil {
		t.Fatal(err)
	}
	f.p = r.pipeline
	if after := observation(); after.Readiness.Stage != "" || !after.Wintun.Configured || after.TunnelReady || opens != 1 {
		t.Fatalf("assignment was not attached without premature readiness: %+v", after)
	}
	f.learn(t)
	after := observation()
	if !after.TunnelReady || after.Readiness.Stage != "" || !after.IKE.ChildLive || after.IKE.Generation != before.IKE.Generation || len(after.Wintun.Addresses) != 1 || after.Wintun.Addresses[0].String() != "10.9.0.1/32" {
		t.Fatalf("same runtime did not recover after assignment and authenticated Babel: %+v", after)
	}
}

func TestControlOnlyPipelineRequiresMatchingDeviceAndBusinessHosts(t *testing.T) {
	local, peer := netip.MustParseAddr("fe80::1"), netip.MustParseAddr("fe80::2")
	tunnel := &gatewayTunnel{socket: &packetSockets{}}
	device := &memoryPacketDevice{}
	for _, scenario := range []struct {
		name   string
		device packetDevice
		hosts  []netip.Addr
		valid  bool
	}{
		{"control-only", nil, nil, true},
		{"attached-business", device, []netip.Addr{netip.MustParseAddr("10.9.0.1")}, true},
		{"device-without-hosts", device, nil, false},
		{"hosts-without-device", nil, []netip.Addr{netip.MustParseAddr("10.9.0.1")}, false},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			p, err := newGatewayBabelPipeline(tunnel, scenario.device, local, peer, [8]byte{1}, scenario.hosts)
			if (err == nil) != scenario.valid || (p != nil) != scenario.valid {
				t.Fatalf("pipeline=%v error=%v, want valid=%t", p, err, scenario.valid)
			}
		})
	}
}

func TestControlOnlyRuntimeKeepsAuthenticatedBabelAndRejectsBusiness(t *testing.T) {
	f := runtimeFixture(t)
	key, _ := routing.NormalizeIPAMAssignmentKey("10.9.0.1/32")
	delete(f.view.State.Network.Zones[zone.RootZone].Records, key)
	r := newLeafRuntime(func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
		t.Error("control-only runtime called the OS device factory")
		return nil, errors.New("unexpected device request")
	})
	t.Cleanup(func() { r.close() })
	if err := r.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); !errors.Is(err, errLeafHostAssignmentUnavailable) || r.pipeline == nil {
		t.Fatalf("control-only reconciliation: %v", err)
	}
	f.p = r.pipeline
	f.learn(t)
	payload, err := babel.Encode([]babel.Message{{Type: babel.TLVHello, Seqno: 2, Interval: 400}})
	if err != nil {
		t.Fatal(err)
	}
	hostControl, err := babel.BuildPacket(f.p.local, f.p.peer, payload)
	if err != nil {
		t.Fatal(err)
	}
	foreign := netip.MustParseAddr("fe80::ffff")
	if foreign == f.p.peer {
		foreign = netip.MustParseAddr("fe80::fffe")
	}
	foreignControl, err := babel.BuildPacket(foreign, f.p.local, payload)
	if err != nil {
		t.Fatal(err)
	}
	if f.p.SubmitPacket(f.config, f.view, f.plan, f.now, hostControl) || f.inbound(t, foreignControl) {
		t.Fatal("control-only runtime accepted host-injected or foreign-source control")
	}
	if f.p.SubmitPacket(f.config, f.view, f.plan, f.now, f.packet(true)) || f.inbound(t, f.packet(false)) {
		t.Fatal("control-only runtime accepted business traffic")
	}
	if len(f.device.written) != 0 || r.ready(f.config, f.view, f.plan, f.now) || r.readySnapshot(f.config, f.view, f.plan, f.now) {
		t.Fatal("control-only runtime leaked a business packet or readiness")
	}
	got := observeRuntime(f.config, f.view, f.plan, f.now, f.p.tunnel.socket, f.p.tunnel, r, nil)
	if got.TunnelReady || got.Wintun.Configured || !got.IKE.ChildLive || !got.Babel.Live || got.Babel.Local != f.p.local || got.Babel.Neighbor != f.p.peer {
		t.Fatalf("authenticated user-space control mistaken for a business attachment: %+v", got)
	}
}

func TestManualAddressWithdrawalKeepsOnlyControlAndDoesNotOpenDevice(t *testing.T) {
	f := runtimeFixture(t)
	key, _ := routing.NormalizeRouteAnnouncementKey("10.9.0.1/32")
	f.put(f.config.ManagedZone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.9.0.1/32", Active: false})
	r := newLeafRuntime(func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
		t.Error("manual withdrawal opened a business device")
		return nil, errors.New("unexpected device request")
	})
	t.Cleanup(func() { r.close() })
	for range 2 {
		if err := r.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); !errors.Is(err, errLeafHostAnnouncementUnavailable) || r.pipeline == nil || r.device != nil {
			t.Fatalf("manual withdrawal did not retain only control: %v", err)
		}
	}
	f.p = r.pipeline
	f.learn(t)
	got := observeRuntime(f.config, f.view, f.plan, f.now, f.p.tunnel.socket, f.p.tunnel, r, nil)
	if got.TunnelReady || got.Wintun.Configured || !got.Babel.Live || got.Readiness.Stage != ReadinessStageAddressAnnouncement {
		t.Fatalf("withdrawn announcement presented as missing assignment or ready: %+v", got)
	}
}

func TestAssignmentWithdrawalReturnsToControlOnlyAndRejectsCryptoCompletion(t *testing.T) {
	for _, direction := range []string{"outbound", "inbound"} {
		t.Run(direction, func(t *testing.T) {
			f, r := observationFixture(t)
			var completion dataplaneCompletion
			if direction == "outbound" {
				if !f.p.SubmitPacket(f.config, f.view, f.plan, f.now, f.packet(true)) {
					t.Fatal("authorized packet was not submitted")
				}
				completion = f.businessCompletion(t)
			} else {
				completion = f.inboundCompletion(t, f.packet(false))
			}
			generation := f.p.tunnel.generation
			key, _ := routing.NormalizeIPAMAssignmentKey("10.9.0.1/32")
			f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: "10.9.0.1/32", AssignedTo: f.config.ManagedZone, Active: false})
			f.view.Revision++
			if err := r.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); !errors.Is(err, errLeafHostAssignmentUnavailable) {
				t.Fatal(err)
			}
			if r.device != nil || r.pipeline == nil || r.pipeline.device != nil || len(r.pipeline.addresses) != 0 || r.pipeline.tunnel.generation != generation {
				t.Fatal("assignment withdrawal did not retain only the same-SA control plane")
			}
			f.p = r.pipeline
			if f.accept(t, completion) {
				t.Fatal("pre-withdrawal crypto completion delivered after device removal")
			}
			f.learn(t)
			if f.p.SubmitPacket(f.config, f.view, f.plan, f.now, f.packet(true)) || f.inbound(t, f.packet(false)) {
				t.Fatal("withdrawn host continued business traffic")
			}
			got := observeRuntime(f.config, f.view, f.plan, f.now, f.p.tunnel.socket, f.p.tunnel, r, nil)
			if got.TunnelReady || got.Wintun.Configured || !got.Babel.Live || got.Readiness.Stage != ReadinessStageAddressAssignment {
				t.Fatalf("withdrawal observation: %+v", got)
			}
		})
	}
}

func TestControlOnlyRuntimeInvalidatesUntrustedOrExpiredAttachment(t *testing.T) {
	for _, scenario := range []string{"generation", "child-expired", "ike-expired", "overlay-signature", "root-pin"} {
		t.Run(scenario, func(t *testing.T) {
			f := runtimeFixture(t)
			key, _ := routing.NormalizeIPAMAssignmentKey("10.9.0.1/32")
			delete(f.view.State.Network.Zones[zone.RootZone].Records, key)
			r := newLeafRuntime(nil)
			t.Cleanup(func() { r.close() })
			if err := r.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); !errors.Is(err, errLeafHostAssignmentUnavailable) || r.pipeline == nil {
				t.Fatalf("initial control-only pipeline: %v", err)
			}
			f.p = r.pipeline
			switch scenario {
			case "generation":
				f.p.tunnel.generation++
			case "child-expired":
				f.p.tunnel.expiresAt = f.now
			case "ike-expired":
				f.p.tunnel.ikeExpiresAt = f.now
			case "overlay-signature":
				f.view.State.Network.Zones[f.config.ManagedZone].Records[ipsec.OverlayIntentRecordKey(f.config.Overlay.ID)].Signature[0] ^= 1
			case "root-pin":
				f.config.TrustedRootPublicKey = append([]byte(nil), f.config.TrustedRootPublicKey...)
				f.config.TrustedRootPublicKey[0] ^= 1
			}
			if err := r.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); err == nil || r.pipeline != nil || r.device != nil {
				t.Fatalf("invalid control attachment survived: pipeline=%v error=%v", r.pipeline, err)
			}
		})
	}
}

func applySignedHostAssignment(t *testing.T, f *pipelineFixture) {
	t.Helper()
	store := corestate.NewStore(&corestate.VerifiedState{ManagedZone: f.config.ManagedZone, TrustedRootPublicKey: f.config.TrustedRootPublicKey, Network: zone.CloneNetworkState(f.view.State.Network)}, nil, nil)
	defer store.Close()
	key, _ := routing.NormalizeIPAMAssignmentKey("10.9.0.1/32")
	f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: "10.9.0.1/32", AssignedTo: f.config.ManagedZone, Active: true})
	snapshot, err := corestate.Snapshot(f.view.State.Network, zone.RootZone)
	if err != nil {
		t.Fatal(err)
	}
	limits := corestate.DefaultSyncLimits()
	limits.MaxBytes = 8 << 20 // Match the production object-pull snapshot budget.
	result, err := store.ApplyRemoteBatch(t.Context(), "gateway", []corestate.RemoteSnapshot{{Snapshot: snapshot, ExpectedRoot: corestate.ZoneRoot(corestate.ZoneStateFromSnapshot(snapshot)), Limits: limits}}, f.now)
	if err != nil || len(result.Outcomes) != 1 || result.Outcomes[0].Err != nil || !result.Changes.NetworkChanged {
		t.Fatalf("signed assignment sync: %+v, %v", result, err)
	}
	f.view = store.ReadView()
}
