package photonwindows

import (
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestLeafHostAssignmentsAndManualWithdrawal(t *testing.T) {
	network, _, private := signedNetwork(t)
	root := private.Public().(ed25519.PublicKey)
	network.Zones[zone.RootZone].Authority = photoncrypto.ConfiguredRootAuthority(root)
	if err := photoncrypto.SignDelegation(network.Zones[zone.RootZone].Delegations["catofes."], zone.RootZone, private); err != nil {
		t.Fatal(err)
	}
	now := time.Now().Truncate(time.Second)
	put := func(path zone.ZonePath, key, kind string, value any) {
		encoded, _ := json.Marshal(value)
		record := &zone.Record{Zone: path, Key: key, Type: kind, Value: encoded, Version: 1, Timestamp: now.Unix()}
		if err := photoncrypto.SignRecord(record, private); err != nil {
			t.Fatal(err)
		}
		network.Zones[path].Records[key] = record
	}
	config := &Config{ManagedZone: "node-a.catofes.", TrustedRootPublicKey: root, Overlay: OverlayConfig{SplitRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2a0d:2905:1::/48")}}}
	for _, pool := range config.Overlay.SplitRoutes {
		poolKey, _ := routing.NormalizeIPAMPoolKey(pool.String())
		put(zone.RootZone, poolKey, routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{Version: 1, Prefix: pool.String(), DelegatedTo: zone.RootZone, Active: true})
	}
	for _, prefix := range []string{"10.1.0.1/32", "10.2.0.0/24", "10.3.0.0/24", "2a0d:2905:1:3f::/64"} {
		key, _ := routing.NormalizeIPAMAssignmentKey(prefix)
		put(zone.RootZone, key, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: prefix, AssignedTo: config.ManagedZone, Active: true})
	}
	manualKey, _ := routing.NormalizeRouteAnnouncementKey("10.3.0.1/32")
	put(config.ManagedZone, manualKey, routing.RecordTypeRouteAnnouncement, routing.RouteAnnouncementRecord{Version: 1, Prefix: "10.3.0.1/32", Active: false})
	source := &State{common: corestate.NewStore(&corestate.VerifiedState{ManagedZone: config.ManagedZone, TrustedRootPublicKey: root, IdentityPrivateKey: private, Network: network}, nil, nil)}
	if err := source.EnsureLocalLeafRoutes(t.Context(), config, now); err != nil {
		t.Fatal(err)
	}
	addresses, routes := leafDeviceIntent(config, source.common.ReadView(), now)
	if len(addresses) != 3 || addresses[0].String() != "10.1.0.1/32" || addresses[1].String() != "10.2.0.1/32" || addresses[2].String() != "2a0d:2905:1:3f::1/128" || len(routes) != 2 {
		t.Fatal("wrong host selection or manual withdrawal overridden", addresses, routes)
	}
	// Derived hosts are signed route announcements, never new overlapping IPAM
	// assignments or advertisements for the entire assigned subnet.
	set := currentAuthorizedRouteSet(config, source.common.ReadView(), now)
	if len(set.AllAssignments) != 4 || len(set.Announced[config.ManagedZone]) != 3 {
		t.Fatal("subnet assignment was replaced or advertised wholesale", set)
	}
	revision := source.common.VerifiedRevision()
	if err := source.EnsureLocalLeafRoutes(t.Context(), config, now); err != nil || source.common.VerifiedRevision() != revision {
		t.Fatal("steady reconciliation rewrote state", err)
	}
	for _, prefix := range []string{"10.1.0.1/32", "10.2.0.0/24", "2a0d:2905:1:3f::/64"} {
		if _, err := source.common.ApplyLocalIntent(t.Context(), corestate.RevokeIPAMAssignmentIntent{Zone: zone.RootZone, Prefix: prefix}, now); err != nil {
			t.Fatal(err)
		}
	}
	if err := source.EnsureLocalLeafRoutes(t.Context(), config, now); err != nil {
		t.Fatal(err)
	}
	if addresses, _ := leafDeviceIntent(config, source.common.ReadView(), now); len(addresses) != 0 {
		t.Fatal("revoked host address retained")
	}
	for _, address := range addresses {
		key, _ := routing.NormalizeRouteAnnouncementKey(address.String())
		record := source.common.ReadView().State.Network.Zones[config.ManagedZone].Records[key]
		announcement, err := routing.ParseRouteAnnouncementRecord(record)
		if err != nil || announcement.Active {
			t.Fatal("auto announcement not withdrawn", address, err)
		}
	}
}

func TestLeafAssignedHostsSubnetBoundaries(t *testing.T) {
	config := &Config{ManagedZone: "node-a.catofes.", Overlay: OverlayConfig{SplitRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("2001:db8::/32")}}}
	for _, tc := range []struct {
		prefix, want string
		shared       bool
		owner        zone.ZonePath
	}{
		{"10.2.0.0/24", "10.2.0.1/32", false, config.ManagedZone},
		{"10.2.0.0/31", "10.2.0.1/32", false, config.ManagedZone},
		{"10.2.0.0/32", "10.2.0.0/32", false, config.ManagedZone},
		{"2001:db8:1::/64", "2001:db8:1::1/128", false, config.ManagedZone},
		{"2001:db8:1::/127", "2001:db8:1::1/128", false, config.ManagedZone},
		{"2001:db8:1::/128", "2001:db8:1::/128", false, config.ManagedZone},
		{"2001:db8:1::/64", "", true, config.ManagedZone},
		{"2001:db8:1::/64", "", false, "node-b.catofes."},
		{"2001:db9::/64", "", false, config.ManagedZone},
		{"fe80::/64", "", false, config.ManagedZone},
	} {
		t.Run(tc.prefix+"/"+string(tc.owner), func(t *testing.T) {
			set := &routing.AuthorizedRouteSet{AllAssignments: []*routing.AssignmentEntry{{Prefix: netip.MustParsePrefix(tc.prefix), AssignedTo: tc.owner, Shared: tc.shared}}}
			hosts := leafAssignedHosts(config, set)
			if tc.want == "" {
				if len(hosts) != 0 {
					t.Fatal("unusable assignment selected", hosts)
				}
			} else if len(hosts) != 1 || hosts[0].String() != tc.want {
				t.Fatalf("hosts = %v, want %s", hosts, tc.want)
			}
		})
	}
}

func TestLeafLinkLocalMatchesLinuxEpoch(t *testing.T) {
	config, view, now, put := gatewayPlanFixture(t)
	config.ManagedZone = "catofes."
	for _, paths := range [][]string{{ipsec.DefaultPathKey}, {"family:ipv4"}} {
		for _, generation := range []uint64{1, 2, 4} {
			overlay := ipsec.OverlayIntentRecord{Version: 1, OverlayID: config.Overlay.ID, Provider: ipsec.ProviderStrongSwan, PathKeys: paths, TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6}}
			for _, path := range []zone.ZonePath{config.ManagedZone, "node-a.catofes."} {
				put(path, ipsec.OverlayIntentRecordKey(config.Overlay.ID), ipsec.RecordTypeOverlayIntent, overlay)
			}
			plan := GatewayPlan{Selected: &GatewaySelection{Zone: "node-a.catofes.", Contact: ipsec.ContactPoint{Address: "192.0.2.1", Generation: generation}}}
			local, peer, err := leafLinkLocalAddresses(config, view, plan, now)
			if err != nil {
				t.Fatal(err)
			}
			group := ipsec.LinkGroupSpec{ID: config.Overlay.ID, TunnelAddressSpec: overlay.TunnelAddress}
			base := ipsec.TransportLinkSpec{LocalZone: plan.Selected.Zone, PeerZone: config.ManagedZone, LinkID: ipsec.StableLinkID(config.ManagedZone, plan.Selected.Zone, group.ID, paths[0]), PathKey: paths[0]}
			linux, err := ipsec.RuntimeSpecForPortGeneration(base, group, generation)
			if err != nil {
				t.Fatal(err)
			}
			if local != linux.PeerTunnelAddr || peer != linux.LocalTunnelAddr {
				t.Fatal("Windows/Linux addresses are not mirrored", local, peer, linux)
			}
		}
	}
	overlay := ipsec.OverlayIntentRecord{Version: 1, OverlayID: config.Overlay.ID, Provider: ipsec.ProviderStrongSwan, PathKeys: []string{ipsec.DefaultPathKey}, TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDisabled}}
	put(config.ManagedZone, ipsec.OverlayIntentRecordKey(config.Overlay.ID), ipsec.RecordTypeOverlayIntent, overlay)
	if _, _, err := leafLinkLocalAddresses(config, view, GatewayPlan{Selected: &GatewaySelection{Zone: "node-a.catofes."}}, now); err == nil {
		t.Fatal("guessed OS automatic link-local accepted")
	}
}
