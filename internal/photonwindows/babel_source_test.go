package photonwindows

import (
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
)

func addSourceHost(f *pipelineFixture, prefix string, shared bool) {
	key, _ := routing.NormalizeIPAMAssignmentKey(prefix)
	f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: f.config.ManagedZone, Active: true, Shared: shared})
	key, _ = routing.NormalizeRouteAnnouncementKey(prefix)
	f.put(f.config.ManagedZone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: prefix, Active: true})
}
func learnSourceRoute(t *testing.T, f *pipelineFixture, source string) {
	t.Helper()
	payload, err := babel.Encode([]babel.Message{
		{Type: babel.TLVHello, Seqno: 2, Interval: 400},
		{Type: babel.TLVIHU, Address: f.p.local, Metric: 100, Interval: 400},
		{Type: babel.TLVUpdate, Prefix: netip.MustParsePrefix("10.1.2.0/24"), SourcePrefix: netip.MustParsePrefix(source), RouterID: f.remoteID, NextHop: f.p.peer, Seqno: 8, Metric: 10, Interval: 1600},
	})
	if err != nil {
		t.Fatal(err)
	}
	packet, err := babel.BuildPacket(f.p.peer, f.p.local, payload)
	if err != nil {
		t.Fatal(err)
	}
	if !f.inbound(t, packet) {
		t.Fatal("authenticated source route control refused")
	}
}

func TestSourceSpecificAdmissionOnlyNarrowsLocalHosts(t *testing.T) {
	f := newPipelineFixture(t)
	route := sadr.Route{Destination: netip.MustParsePrefix("10.1.2.0/24"), RouterID: f.remoteID, NextHop: f.p.peer, Metric: 100, ExpiresAt: f.now.Add(time.Minute)}
	for _, tc := range []struct {
		source string
		want   bool
	}{
		{"10.0.0.0/8", true}, {"10.9.0.1/32", true},
		{"10.8.0.0/16", false}, {"10.0.0.1/8", false}, {"0.0.0.0/0", false},
		{"2001:db8::/32", false}, {"::ffff:10.0.0.0/104", false},
	} {
		route.Source = netip.MustParsePrefix(tc.source)
		if got := currentBabelRouteAuthorizer(f.config, f.view, f.now)(route); got != tc.want {
			t.Fatalf("source %s: %v want %v", tc.source, got, tc.want)
		}
	}
	// The destination owner owns neither the broad source pool nor the local host.
	// Shared/anycast or a subnet without the selected host's announcement is
	// not a local host witness.
	addSourceHost(f, "10.9.0.1/32", true)
	route.Source = netip.MustParsePrefix("10.0.0.0/8")
	if currentBabelRouteAuthorizer(f.config, f.view, f.now)(route) {
		t.Fatal("shared source host admitted")
	}
	key, _ := routing.NormalizeIPAMAssignmentKey("10.9.0.1/32")
	delete(f.view.State.Network.Zones[zone.RootZone].Records, key)
	hostKey, _ := routing.NormalizeRouteAnnouncementKey("10.9.0.1/32")
	delete(f.view.State.Network.Zones[f.config.ManagedZone].Records, hostKey)
	addSourceHost(f, "10.9.0.0/24", false)
	if currentBabelRouteAuthorizer(f.config, f.view, f.now)(route) {
		t.Fatal("subnet announcement substituted for the selected local host announcement")
	}
	f.put(f.config.ManagedZone, hostKey, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.9.0.1/32", Active: true})
	if !currentBabelRouteAuthorizer(f.config, f.view, f.now)(route) {
		t.Fatal("selected and announced subnet host refused")
	}
}

func TestSourceSpecificIPv6HostAndBroadFilters(t *testing.T) {
	f := newPipelineFixture(t)
	f.config.Overlay.SplitRoutes = append(f.config.Overlay.SplitRoutes, netip.MustParsePrefix("2001:db8::/32"))
	pool := "2001:db8::/32"
	key, _ := routing.NormalizeIPAMPoolKey(pool)
	f.put(zone.RootZone, key, routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{Version: 1, Prefix: pool, DelegatedTo: zone.RootZone, Active: true})
	// Keep the /64 IPAM assignment, but announce only the selected /128.
	localAssignment := "2001:db8:1::/64"
	key, _ = routing.NormalizeIPAMAssignmentKey(localAssignment)
	f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: localAssignment, AssignedTo: f.config.ManagedZone, Active: true})
	key, _ = routing.NormalizeRouteAnnouncementKey("2001:db8:1::1/128")
	f.put(f.config.ManagedZone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "2001:db8:1::1/128", Active: true})
	dst := "2001:db8:2::/64"
	key, _ = routing.NormalizeIPAMAssignmentKey(dst)
	f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: dst, AssignedTo: "node-a.catofes.", Active: true})
	key, _ = routing.NormalizeRouteAnnouncementKey(dst)
	f.put("node-a.catofes.", key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: dst, Active: true})
	r := sadr.Route{Destination: netip.MustParsePrefix(dst), RouterID: f.remoteID, NextHop: f.p.peer, Metric: 100, ExpiresAt: f.now.Add(time.Minute)}
	for _, tc := range []struct {
		source string
		want   bool
	}{{"2001:db8::/32", true}, {"2001:db8:1::1/128", true}, {"2001:db8:3::/64", false}, {"2001:db8::1/32", false}, {"::/0", false}, {"10.0.0.0/8", false}} {
		r.Source = netip.MustParsePrefix(tc.source)
		if got := currentBabelRouteAuthorizer(f.config, f.view, f.now)(r); got != tc.want {
			t.Fatalf("source %s: %v want %v", tc.source, got, tc.want)
		}
	}
	// Exercise the same source contract through both IPv6 crypto completions.
	local := netip.MustParseAddr("2001:db8:1::1")
	remote := netip.MustParseAddr("2001:db8:2::3")
	f.p.addresses = append(f.p.addresses, local)
	payload, err := babel.Encode([]babel.Message{
		{Type: babel.TLVHello, Seqno: 1, Interval: 400},
		{Type: babel.TLVIHU, Address: f.p.local, Metric: 100, Interval: 400},
		{Type: babel.TLVUpdate, Prefix: r.Destination, SourcePrefix: netip.PrefixFrom(local, 128), RouterID: f.remoteID, NextHop: f.p.peer, Metric: 10, Seqno: 1, Interval: 1600},
	})
	if err != nil {
		t.Fatal(err)
	}
	control, err := babel.BuildPacket(f.p.peer, f.p.local, payload)
	if err != nil || !f.inbound(t, control) {
		t.Fatal("IPv6 source update refused", err)
	}
	packet := make([]byte, 48)
	packet[0], packet[6], packet[7] = 0x60, 17, 64
	binary.BigEndian.PutUint16(packet[4:6], 8)
	copy(packet[8:24], local.AsSlice())
	copy(packet[24:40], remote.AsSlice())
	binary.BigEndian.PutUint16(packet[40:42], 1234)
	binary.BigEndian.PutUint16(packet[42:44], 443)
	binary.BigEndian.PutUint16(packet[44:46], 8)
	if !f.submitFromDevice(t, packet) || !f.accept(t, f.businessCompletion(t)) {
		t.Fatal("IPv6 source-specific outbound completion refused")
	}
	f.receiveBusiness(t)
	copy(packet[8:24], remote.AsSlice())
	copy(packet[24:40], local.AsSlice())
	if !f.inbound(t, packet) {
		t.Fatal("IPv6 source-specific inbound completion refused")
	}
	// Owning a subnet does not attach every address in it to this leaf.
	copy(packet[24:40], netip.MustParseAddr("2001:db8:1::2").AsSlice())
	if f.inbound(t, packet) {
		t.Fatal("unselected subnet address reached the host")
	}
	copy(packet[24:40], local.AsSlice())
	completion := f.inboundCompletion(t, packet)
	key, _ = routing.NormalizeIPAMAssignmentKey(localAssignment)
	f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: localAssignment, AssignedTo: f.config.ManagedZone, Active: false})
	f.view.Revision++
	if f.accept(t, completion) {
		t.Fatal("queued IPv6 business packet survived subnet withdrawal")
	}
}

func TestSourceSpecificPipelineBothDirectionsAndFallback(t *testing.T) {
	f := newPipelineFixture(t)
	learnSourceRoute(t, f, "10.9.0.1/32")
	if !f.submitFromDevice(t, f.packet(true)) || !f.accept(t, f.businessCompletion(t)) {
		t.Fatal("constrained outbound refused")
	}
	f.receiveBusiness(t)
	if !f.inbound(t, f.packet(false)) {
		t.Fatal("reverse lookup did not match original local destination")
	}
	addSourceHost(f, "10.9.0.2/32", false)
	f.p.addresses = append(f.p.addresses, netip.MustParseAddr("10.9.0.2"))
	packet := f.packet(false)
	packet[19] = 2
	if f.inbound(t, packet) {
		t.Fatal("inbound local destination outside Source admitted")
	}
	// An authorized second local host may only use the ordinary fallback.
	constrained := f.p.leaf.Candidates(f.now, currentBabelRouteAuthorizer(f.config, f.view, f.now))[0]
	fallback := constrained
	fallback.Source = netip.Prefix{}
	fallback.Metric = 300
	selected := f.p.tunnel.lookupBabelRoutes(f.config, f.view, f.plan, f.view.Revision, []sadr.Route{fallback, constrained}, netip.MustParseAddr("10.9.0.2"), netip.MustParseAddr("10.1.2.3"), f.now)
	if len(selected) != 1 || selected[0].Source.IsValid() {
		t.Fatal("wrong fallback", selected)
	}
	if len(f.p.tunnel.lookupBabelRoutes(f.config, f.view, f.plan, f.view.Revision, []sadr.Route{constrained}, netip.MustParseAddr("10.9.0.3"), netip.MustParseAddr("10.1.2.3"), f.now)) != 0 {
		t.Fatal("lookup admitted nonlocal source")
	}
	for _, m := range f.p.leaf.Tick(f.now) {
		if m.Type == babel.TLVUpdate && m.Metric != babel.MetricInfinity && (m.RouterID == f.remoteID || m.SourcePrefix.IsValid()) {
			t.Fatal("learned source-specific route redistributed")
		}
	}
}

func TestSourceSpecificQueuedCompletionRechecksAuthority(t *testing.T) {
	for _, direction := range []string{"outbound", "inbound"} {
		for _, scenario := range []string{"assignment", "announcement", "destination-announcement"} {
			t.Run(direction+"/"+scenario, func(t *testing.T) {
				f := newPipelineFixture(t)
				learnSourceRoute(t, f, "10.0.0.0/8")
				var completion dataplaneCompletion
				if direction == "outbound" {
					if !f.submitFromDevice(t, f.packet(true)) {
						t.Fatal("submit failed")
					}
					completion = f.businessCompletion(t)
				} else {
					completion = f.inboundCompletion(t, f.packet(false))
				}
				switch scenario {
				case "assignment":
					key, _ := routing.NormalizeIPAMAssignmentKey("10.9.0.1/32")
					f.put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: "10.9.0.1/32", AssignedTo: f.config.ManagedZone, Active: false})
				case "announcement":
					key, _ := routing.NormalizeRouteAnnouncementKey("10.9.0.1/32")
					f.put(f.config.ManagedZone, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.9.0.1/32", Active: false})
				case "destination-announcement":
					key, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
					f.put("node-a.catofes.", key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: false})
				}
				f.view.Revision++
				if f.accept(t, completion) || len(f.device.written) != 0 {
					t.Fatal("queued packet survived source authorization revocation")
				}
			})
		}
	}
}
