package photonwindows

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"net/netip"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func gatewayPlanFixture(t *testing.T) (*Config, corestate.View, time.Time, func(zone.ZonePath, string, string, any)) {
	t.Helper()
	network, _, private := signedNetwork(t)
	// Use the same test signer at the root so the fixture can sign IPAM facts.
	root := private.Public().(ed25519.PublicKey)
	network.Zones[zone.RootZone].Authority = photoncrypto.ConfiguredRootAuthority(root)
	if err := photoncrypto.SignDelegation(network.Zones[zone.RootZone].Delegations["catofes."], zone.RootZone, private); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	peer := zone.ZonePath("node-a.catofes.")
	config := &Config{ManagedZone: "windows.catofes.", TrustedRootPublicKey: root, Overlay: OverlayConfig{ID: "main", SplitRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, Gateway: GatewayConfig{AllowedZones: []zone.ZonePath{peer}}}
	put := func(path zone.ZonePath, key, kind string, value any) {
		t.Helper()
		data, err := json.Marshal(value)
		if err != nil {
			t.Fatal(err)
		}
		record := &zone.Record{Zone: path, Key: key, Type: kind, Value: data, Version: 1, Timestamp: now.Unix()}
		if err := photoncrypto.SignRecord(record, private); err != nil {
			t.Fatal(err)
		}
		network.Zones[path].Records[key] = record
	}
	_, key, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	put(peer, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{Version: 1, Enabled: true, Provider: ipsec.ProviderStrongSwan, IKEIdentity: string(peer), TransportKeyFingerprint: key.Fingerprint, Role: ipsec.RoleIn, AddressFamilies: []string{ipsec.FamilyIPv4}, PathModes: []string{ipsec.PathModeFamilyRedundant}})
	put(peer, ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, key)
	put(peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{Version: 1, UpdatedAt: now.Unix(), Addresses: []ipsec.AddressAdvertisement{{ID: "dns", Source: ipsec.SourceManualDNS, Host: "gateway.example", Family: ipsec.FamilyIPv4, TTLSeconds: 60}}})
	put(peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed, Current: &ipsec.PortSelection{Generation: 1, IKE: ipsec.PortBinding{Advertised: 500}, NATT: ipsec.PortBinding{Advertised: 4500}}})
	put(peer, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{Version: 1, OverlayID: "main", Provider: ipsec.ProviderStrongSwan, PathKeys: []string{ipsec.DefaultPathKey}, TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDisabled}})
	poolKey, _ := routing.NormalizeIPAMPoolKey("10.0.0.0/8")
	put(zone.RootZone, poolKey, routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/8", DelegatedTo: zone.RootZone, Active: true})
	assignmentKey, _ := routing.NormalizeIPAMAssignmentKey("10.1.0.0/16")
	put(zone.RootZone, assignmentKey, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: "10.1.0.0/16", AssignedTo: peer, Active: true})
	routeKey, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
	put(peer, routeKey, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.1.2.0/24", Active: true})
	return config, corestate.View{Revision: 7, State: &corestate.VerifiedState{Network: network}}, now, put
}

func TestGatewayPlanDNSSelectionAndRevalidation(t *testing.T) {
	config, view, now, _ := gatewayPlanFixture(t)
	config.Gateway.AllowedZones = append([]zone.ZonePath{"absent.catofes."}, config.Gateway.AllowedZones...)
	resolver := gatewayResolvedHosts{"gateway.example": {{IP: net.ParseIP("192.0.2.4")}, {IP: net.ParseIP("127.0.0.1")}, {IP: net.ParseIP("192.0.2.3")}}}
	plan := planGateway(context.Background(), config, view, now, resolver)
	if plan.Selected == nil || plan.Selected.Contact.Address != "192.0.2.3" || plan.Selected.Identity != "node-a.catofes." || len(plan.Selected.PublicKey) != ed25519.PublicKeySize || plan.Revision != 7 {
		t.Fatalf("selection = %+v", plan)
	}
	if len(plan.Routes) != 1 || plan.Routes[0].Origin != "node-a.catofes." || plan.Routes[0].Prefix.String() != "10.1.2.0/24" {
		t.Fatalf("routes = %+v", plan.Routes)
	}
	if refreshed := RevalidateGatewayPlan(config, view, plan, now.Add(time.Second)); refreshed.Selected == nil {
		t.Fatalf("fresh revalidation: %+v", refreshed)
	}
	if expired := RevalidateGatewayPlan(config, view, plan, now.Add(61*time.Second)); expired.Selected != nil {
		t.Fatal("expired DNS advertisement accepted")
	}
	view.Revision++
	if stale := RevalidateGatewayPlan(config, view, plan, now); stale.Selected != nil {
		t.Fatal("old revision accepted")
	}
}

type blockingGatewayResolver struct{}

func (blockingGatewayResolver) LookupIPAddr(ctx context.Context, _ string) ([]net.IPAddr, error) {
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestGatewayPlanDNSCancellation(t *testing.T) {
	config, view, now, _ := gatewayPlanFixture(t)
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	plan := planGateway(ctx, config, view, now, blockingGatewayResolver{})
	if plan.Selected != nil || plan.Rejected == "" || time.Since(started) > time.Second {
		t.Fatalf("cancelled plan = %+v", plan)
	}
}

func TestGatewayRouteAuthorizationRejectsInvalidFacts(t *testing.T) {
	for _, scenario := range []string{"invalid-pool-signature", "invalid-assignment-signature", "invalid-route-signature", "wrong-origin", "outside-split", "expired-authority", "expired-delegation", "missing-assignment"} {
		t.Run(scenario, func(t *testing.T) {
			config, view, now, _ := gatewayPlanFixture(t)
			network := view.State.Network
			peer := zone.ZonePath("node-a.catofes.")
			poolKey, _ := routing.NormalizeIPAMPoolKey("10.0.0.0/8")
			assignmentKey, _ := routing.NormalizeIPAMAssignmentKey("10.1.0.0/16")
			routeKey, _ := routing.NormalizeRouteAnnouncementKey("10.1.2.0/24")
			switch scenario {
			case "invalid-pool-signature":
				network.Zones[zone.RootZone].Records[poolKey].Signature[0] ^= 1
			case "invalid-assignment-signature":
				network.Zones[zone.RootZone].Records[assignmentKey].Signature[0] ^= 1
			case "invalid-route-signature":
				network.Zones[peer].Records[routeKey].Signature[0] ^= 1
			case "wrong-origin":
				network.Zones[peer].Records[routeKey].Zone = "catofes."
			case "outside-split":
				config.Overlay.SplitRoutes = []netip.Prefix{netip.MustParsePrefix("10.2.0.0/16")}
			case "expired-authority":
				network.Zones[peer].Authority.Keys[0].NotAfter = now.Unix()
			case "expired-delegation":
				expired := now.Add(-time.Second)
				network.Zones["catofes."].Delegations[peer].ExpiresAt = &expired
			case "missing-assignment":
				delete(network.Zones[zone.RootZone].Records, assignmentKey)
			}
			if routes := authorizedGatewayRoutes(config, view, now); len(routes) != 0 {
				t.Fatalf("invalid routes accepted: %+v", routes)
			}
		})
	}
}

func TestGatewayRouteOriginIsNotAssumedToBeGateway(t *testing.T) {
	config, view, now, put := gatewayPlanFixture(t)
	assignmentKey, _ := routing.NormalizeIPAMAssignmentKey("10.2.0.0/16")
	put(zone.RootZone, assignmentKey, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: "10.2.0.0/16", AssignedTo: "catofes.", Active: true})
	routeKey, _ := routing.NormalizeRouteAnnouncementKey("10.2.3.0/24")
	put("catofes.", routeKey, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.2.3.0/24", Active: true})
	routes := authorizedGatewayRoutes(config, view, now)
	if len(routes) != 2 || routes[0].Origin != "catofes." || routes[0].Prefix.String() != "10.2.3.0/24" {
		t.Fatalf("origin was replaced by gateway: %+v", routes)
	}
}

func TestGatewayPlanRevalidationDeduplicatesDNSAcrossContacts(t *testing.T) {
	config, view, now, put := gatewayPlanFixture(t)
	peer := config.Gateway.AllowedZones[0]
	// Port overlap yields multiple contacts for each DNS address. Other
	// candidates may also resolve the same hostname to that same address.
	put(peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed,
		Current:  &ipsec.PortSelection{Generation: 2, IKE: ipsec.PortBinding{Advertised: 501}, NATT: ipsec.PortBinding{Advertised: 4501}},
		Previous: []ipsec.PortSelection{{Generation: 1, IKE: ipsec.PortBinding{Advertised: 500}, NATT: ipsec.PortBinding{Advertised: 4500}}},
	})
	plan := planGateway(context.Background(), config, view, now, gatewayResolvedHosts{"gateway.example": {{IP: net.ParseIP("192.0.2.3")}}})
	if plan.Selected == nil || len(plan.Candidates[0].Contacts) != 2 {
		t.Fatalf("initial contacts: %+v", plan)
	}
	plan.Candidates = append(plan.Candidates, plan.Candidates[0])
	for i := 0; i < 3; i++ {
		plan = RevalidateGatewayPlan(config, view, plan, now.Add(time.Duration(i)*time.Second))
		if plan.Selected == nil || len(plan.Candidates) != 1 || len(plan.Candidates[0].Contacts) != 2 {
			t.Fatalf("revalidation %d expanded contacts: %+v", i, plan)
		}
	}
}

func TestGatewayPlanTransportSelectionDoesNotAuthorizeRoutes(t *testing.T) {
	config, view, now, _ := gatewayPlanFixture(t)
	assignmentKey, _ := routing.NormalizeIPAMAssignmentKey("10.1.0.0/16")
	delete(view.State.Network.Zones[zone.RootZone].Records, assignmentKey)
	plan := planGateway(context.Background(), config, view, now, gatewayResolvedHosts{"gateway.example": {{IP: net.ParseIP("192.0.2.3")}}})
	if plan.Selected == nil || len(plan.Routes) != 0 {
		t.Fatalf("transport selection must not imply routing authorization: %+v", plan)
	}
}
