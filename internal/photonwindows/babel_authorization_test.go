package photonwindows

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestCurrentFullBabelOriginBinding(t *testing.T) {
	config, view, now, put := gatewayPlanFixture(t)
	peer := zone.ZonePath("node-a.catofes.")
	id := [8]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}
	binding := routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{"1234567890abcdef"}, ExpiresAt: now.Add(time.Minute).Unix()}
	put(peer, routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, binding)
	if got := currentBabelOrigins(config, view, now)[id]; got != peer {
		t.Fatal("signed full ID not bound", got)
	}
	if len(currentBabelOrigins(config, view, now.Add(time.Minute))) != 0 {
		t.Fatal("expired binding retained")
	}
	if len(currentBabelOrigins(config, view, now.Add(-time.Second))) != 0 {
		t.Fatal("future binding accepted after clock rollback")
	}
	put(peer, routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, routing.BabelIdentityRecord{Version: 1, ExpiresAt: now.Add(time.Minute).Unix()})
	if len(currentBabelOrigins(config, view, now)) != 0 {
		t.Fatal("withdrawn identity retained")
	}
	put(peer, routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, binding)
	put("catofes.", routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, binding)
	if len(currentBabelOrigins(config, view, now)) != 0 {
		t.Fatal("cross-zone collision selected an arbitrary origin")
	}
	delete(view.State.Network.Zones["catofes."].Records, routing.RecordKeyBabelIdentity)
	record := view.State.Network.Zones[peer].Records[routing.RecordKeyBabelIdentity]
	record.Signature[0] ^= 1
	if len(currentBabelOrigins(config, view, now)) != 0 {
		t.Fatal("invalid signature accepted")
	}
}

func TestBabelRouteLookupRequiresCurrentSAOriginAndExactPrefix(t *testing.T) {
	config, view, now, put := gatewayPlanFixture(t)
	peer := zone.ZonePath("node-a.catofes.")
	// Give the already-authorized parent its own local transport facts. This
	// keeps local and gateway ownership distinct in the admission fixture.
	config.ManagedZone = "catofes."
	for key, record := range view.State.Network.Zones[peer].Records {
		if len(key) < 6 || key[:6] != "ipsec/" {
			continue
		}
		var value any
		if err := json.Unmarshal(record.Value, &value); err != nil {
			t.Fatal(err)
		}
		put(config.ManagedZone, key, record.Type, value)
	}
	resolver := gatewayResolvedHosts{"gateway.example": {{IP: net.ParseIP("192.0.2.4")}}}
	plan := planGateway(context.Background(), config, view, now, resolver)
	if plan.Selected == nil {
		t.Fatal("fixture has no gateway", plan)
	}
	local, err := localTransportAuthorization(config, view, now)
	if err != nil {
		t.Fatal(err)
	}
	sa := &dataplaneSA{gateway: *plan.Selected, endpoint: netip.AddrPortFrom(netip.MustParseAddr(plan.Selected.Contact.Address), plan.Selected.Contact.IKEPort)}
	tunnel := &gatewayTunnel{phase: 3, session: &ike.Initiator{}, plan: plan, data: &gatewayDataplane{ctx: context.Background(), active: sa, sas: map[uint32]*dataplaneSA{0: sa}}, localAuthorization: local, expiresAt: now.Add(time.Hour), ikeExpiresAt: now.Add(time.Hour)}
	r := sadr.Route{Destination: netip.MustParsePrefix("10.1.2.0/24"), NextHop: netip.MustParseAddr("fe80::1"), RouterID: [8]byte{0x12, 0x34, 0x56, 0x78, 0x90, 0xab, 0xcd, 0xef}, Metric: 100, ExpiresAt: now.Add(time.Minute)}
	src, dst := netip.MustParseAddr("10.9.0.1"), netip.MustParseAddr("10.1.2.3")
	localHost := src.String() + "/32"
	assignmentKey, _ := routing.NormalizeIPAMAssignmentKey(localHost)
	put(zone.RootZone, assignmentKey, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: localHost, AssignedTo: config.ManagedZone, Active: true})
	announcementKey, _ := routing.NormalizeRouteAnnouncementKey(localHost)
	put(config.ManagedZone, announcementKey, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: localHost, Active: true})
	lookup := func() []sadr.Route {
		return tunnel.lookupBabelRoutes(config, view, plan, view.Revision, []sadr.Route{r}, src, dst, now)
	}
	if len(lookup()) != 0 {
		t.Fatal("prefix permission alone accepted missing origin")
	}
	binding := routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{"1234567890abcdef"}, ExpiresAt: now.Add(time.Minute).Unix()}
	put(peer, routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, binding)
	if len(lookup()) != 1 {
		t.Fatal("current signed exact origin/prefix rejected")
	}
	for _, mutate := range []func(){
		func() { tunnel.expiresAt = now },
		func() { tunnel.ikeExpiresAt = now },
		func() { tunnel.data.generation++ },
	} {
		mutate()
		if len(lookup()) != 0 {
			t.Fatal("expired or stale SA accepted")
		}
		tunnel.expiresAt, tunnel.ikeExpiresAt = now.Add(time.Hour), now.Add(time.Hour)
		tunnel.data.generation = tunnel.generation
	}
	r.RouterID[0] ^= 1
	if len(lookup()) != 0 {
		t.Fatal("low 32-bit ID match granted permission")
	}
	r.RouterID[0] ^= 1
	r.Source = netip.MustParsePrefix("10.0.0.0/8")
	if len(lookup()) != 1 {
		t.Fatal("source constraint covering the current local host was rejected")
	}
	r.Source = netip.Prefix{}
	if len(tunnel.lookupBabelRoutes(config, view, plan, view.Revision+1, []sadr.Route{r}, src, dst, now)) != 0 {
		t.Fatal("stale planned revision installed")
	}
	r.Destination = netip.MustParsePrefix("10.1.0.0/16")
	if len(lookup()) != 0 {
		t.Fatal("supernet inherited exact announcement permission")
	}
	r.Destination = netip.MustParsePrefix("10.1.2.0/24")
	// Move the valid binding to a different authorized zone: equal prefixes in
	// another origin are not an excuse to associate this origin with its gateway.
	delete(view.State.Network.Zones[peer].Records, routing.RecordKeyBabelIdentity)
	put("catofes.", routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, binding)
	if len(lookup()) != 0 {
		t.Fatal("gateway substituted for signed origin")
	}
	delete(view.State.Network.Zones["catofes."].Records, routing.RecordKeyBabelIdentity)
	put(peer, routing.RecordKeyBabelIdentity, routing.RecordTypeBabelIdentity, binding)
	key, _ := routing.NormalizeRouteAnnouncementKey(r.Destination.String())
	put(peer, key, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: r.Destination.String(), Active: false})
	if len(lookup()) != 0 {
		t.Fatal("revoked announcement retained in route table")
	}
}
