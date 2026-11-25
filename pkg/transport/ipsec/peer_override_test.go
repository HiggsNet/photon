package ipsec

import (
	"context"
	"encoding/json"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestPeerOverrideRoles(t *testing.T) {
	const (
		a zone.ZonePath = "node-a.catofes."
		b zone.ZonePath = "node-b.catofes."
	)
	now := time.Unix(5000, 0)
	for _, tc := range []struct {
		name, aRole, bRole, aInitiator, bInitiator string
		conflict                                   bool
	}{
		{name: "legacy preference", aInitiator: InitiatorRolePrimary, bInitiator: InitiatorRoleSecondaryStandby},
		{name: "reverse with only B configured", bRole: RoleOut, bInitiator: InitiatorRolePrimary},
		{name: "reverse with A passive", aRole: RoleIn, bInitiator: InitiatorRolePrimary},
		{name: "explicit compatible roles", aRole: RoleIn, bRole: RoleOut, bInitiator: InitiatorRolePrimary},
		{name: "two initiators", aRole: RoleOut, bRole: RoleOut, conflict: true},
		{name: "two responders", aRole: RoleIn, bRole: RoleIn, conflict: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ns := zone.NewNetworkState()
			addIPsecNode(t, ns, a, RoleBoth, []AddressAdvertisement{{ID: "a", Source: SourceManualAddress, Address: "192.0.2.1"}}, now)
			addIPsecNode(t, ns, b, RoleBoth, []AddressAdvertisement{{ID: "b", Source: SourceManualAddress, Address: "192.0.2.2"}}, now)
			key := OverlayIntentRecordKey("ipsec-main")
			groupA, groupB := LinkGroupSpec{ID: "ipsec-main"}, LinkGroupSpec{ID: "ipsec-main"}
			if tc.aRole != "" {
				groupA.PeerOverrides = []PeerOverride{{Peer: b, Role: tc.aRole}}
			}
			if tc.bRole != "" {
				groupB.PeerOverrides = []PeerOverride{{Peer: a, Role: tc.bRole}}
			}
			sides := []struct {
				local, peer zone.ZonePath
				group       LinkGroupSpec
				initiator   string
			}{{a, b, groupA, tc.aInitiator}, {b, a, groupB, tc.bInitiator}}
			for _, side := range sides {
				intent := BuildOverlayIntentRecords([]LinkGroupSpec{side.group}, []string{FamilyIPv4}, nil, now)[0]
				ns.Zones[side.local].Records[key] = record(t, side.local, key, RecordTypeOverlayIntent, intent)
			}
			for _, side := range sides {
				plan, err := PlanTransportLinks(t.Context(), ns, side.local, []LinkGroupSpec{side.group}, LinkPlannerOptions{Now: now})
				if err != nil {
					t.Fatal(err)
				}
				if tc.conflict {
					if len(plan.Desired) != 0 || !hasSkip(plan.Skipped, side.peer, SkipRoleMismatch) {
						t.Fatalf("%s planned a link despite conflicting roles: %+v", side.local, plan)
					}
					continue
				}
				spec := desiredSpecForPeer(t, plan, side.peer)
				if spec.InitiatorRole != side.initiator || (len(spec.ContactPoints) == 0) != (side.initiator == "") {
					t.Fatalf("%s wanted %q, got %+v", side.local, side.initiator, spec)
				}
			}
		})
	}
}

func TestPeerOverrideEndpoints(t *testing.T) {
	const (
		local zone.ZonePath = "node-a.catofes."
		peer  zone.ZonePath = "node-b.catofes."
	)
	now := time.Unix(5000, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, local, RoleOut, nil, now)
	addIPsecNode(t, ns, peer, RoleIn, []AddressAdvertisement{
		{ID: "v4", Source: SourceManualDNS, Host: "peer.example", Family: FamilyIPv4},
		{ID: "v6", Source: SourceManualAddress, Address: "2001:db8::2"},
		{ID: "mislabeled", Source: SourceManualAddress, Address: "192.0.2.90", Family: FamilyIPv6, Priority: 100, Reachability: ReachabilityPublic},
	}, now)
	setIPsecNATProfile(t, ns, peer, RoleIn, NATProfile{Hint: NATHintBehindNAT}, now)
	natt := uint16(44500)
	address := netip.MustParseAddr("10.20.0.40")
	group := LinkGroupSpec{ID: "ipsec-main", PeerOverrides: []PeerOverride{{Peer: peer, Endpoints: map[string]EndpointOverride{
		FamilyIPv4: {Address: address, NATTPort: &natt},
	}}}}
	mobike := true
	opts := LinkPlannerOptions{Now: now, MOBIKE: &mobike, DNSResolver: overrideUnusedDNS{t}}
	plan, err := PlanTransportLinks(t.Context(), ns, local, []LinkGroupSpec{group}, opts)
	if err != nil || len(plan.Desired) != 2 {
		t.Fatalf("plan = %+v, error = %v", plan, err)
	}
	ipv4, ipv6 := plan.Desired[0], plan.Desired[1]
	if ipv4.PathKey != "family:ipv4" || ipv4.MOBIKE || len(ipv4.ContactPoints) != 1 {
		t.Fatalf("IPv4 spec = %+v", ipv4)
	}
	point := ipv4.ContactPoints[0]
	if point.Address != address.String() || point.Host != "" || point.NATTPort != natt || point.Source != SourcePeerOverride || point.Generation != 1 {
		t.Fatalf("IPv4 contact = %+v", point)
	}
	conn, err := BuildStrongSwanConnection(ipv4)
	if err != nil || conn["remote_port"] != "44500" || conn["remote_addrs"].([]string)[0] != address.String() {
		t.Fatalf("StrongSwan connection = %+v, error = %v", conn, err)
	}
	if ipv6.PathKey != "family:ipv6" || !ipv6.MOBIKE || ipv6.ContactPoints[0].Address != "2001:db8::2" {
		t.Fatalf("IPv6 spec = %+v", ipv6)
	}

	ports := PortRecord{
		Version: 1, Mode: PortModeRange,
		Range:    &PortRange{From: 44400, To: 44599},
		Current:  &PortSelection{Generation: 2, IKE: PortBinding{Advertised: 44403}, NATT: PortBinding{Advertised: 44401}},
		Previous: []PortSelection{{Generation: 1, IKE: PortBinding{Advertised: 44402}, NATT: PortBinding{Advertised: 44400}, ValidUntil: now.Add(time.Minute).Unix()}},
	}
	ns.Zones[peer].Records[RecordKeyPorts] = record(t, peer, RecordKeyPorts, RecordTypePorts, ports)
	plan, err = PlanTransportLinks(t.Context(), ns, local, []LinkGroupSpec{group}, opts)
	if err != nil || len(plan.Desired) != 1 || plan.Desired[0].PathKey != "family:ipv6" || !hasSkip(plan.Skipped, peer, SkipPeerOverrideEndpoint) {
		t.Fatalf("explicit port must not substitute for range mode: %+v, error = %v", plan, err)
	}

	group.PeerOverrides[0].Endpoints[FamilyIPv4] = EndpointOverride{Address: address}
	plan, err = PlanTransportLinks(t.Context(), ns, local, []LinkGroupSpec{group}, opts)
	if err != nil || len(plan.Desired) != 2 || plan.Desired[0].Generation != 2 || plan.Desired[0].ContactPoints[0].NATTPort != 44401 {
		t.Fatalf("address-only pin must follow the signed generation: %+v, error = %v", plan, err)
	}
	opts.ContactPointQuality = map[zone.ZonePath]map[string]ContactPointQuality{peer: {
		plan.Desired[0].ContactPoints[0].Key(): {BackoffUntil: now.Add(time.Minute)},
	}}
	plan, err = PlanTransportLinks(t.Context(), ns, local, []LinkGroupSpec{group}, opts)
	if err != nil || len(plan.Desired) != 2 || plan.Desired[0].Generation != 1 ||
		plan.Desired[0].ContactPoints[0].NATTPort != 44400 || plan.Desired[0].ContactPoints[0].Address != address.String() {
		t.Fatalf("grace-period fallback must keep the pinned address: %+v, error = %v", plan, err)
	}

	group.DenyRules = []string{"strongswan://node-b.catofes."}
	plan, err = PlanTransportLinks(t.Context(), ns, local, []LinkGroupSpec{group}, opts)
	if err != nil || len(plan.Desired) != 0 || !hasSkip(plan.Skipped, peer, SkipPolicyDenied) {
		t.Fatalf("pin must respect deny rules: %+v, error = %v", plan, err)
	}
}

type overrideUnusedDNS struct{ t *testing.T }

func (r overrideUnusedDNS) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	r.t.Fatalf("queried DNS for pinned family: %s", host)
	return nil, nil
}

func TestPeerOverridePublication(t *testing.T) {
	const local zone.ZonePath = "node-a.catofes."
	const peer zone.ZonePath = "node-b.catofes."
	now := time.Unix(5000, 0)
	natt := uint16(44500)
	overrides := []PeerOverride{
		{Peer: peer, Role: RoleOut, Endpoints: map[string]EndpointOverride{
			FamilyIPv4: {Address: netip.MustParseAddr("192.0.2.40"), NATTPort: &natt},
		}},
		{Peer: "address-only.catofes.", Endpoints: map[string]EndpointOverride{
			FamilyIPv6: {Address: netip.MustParseAddr("2001:db8::40")},
		}},
	}
	groups := []LinkGroupSpec{{ID: "ipsec-main", PeerOverrides: overrides}}
	families := []string{FamilyIPv4, FamilyIPv6}
	intent := BuildOverlayIntentRecords(groups, families, nil, now)[0]
	key := OverlayIntentRecordKey(intent.OverlayID)
	existing := map[string]*zone.Record{key: record(t, local, key, RecordTypeOverlayIntent, intent)}
	value, err := json.Marshal(intent)
	if err != nil || len(intent.PeerRoles) != 1 || intent.PeerRoles[peer] != RoleOut ||
		strings.Contains(string(value), "192.0.2.40") || strings.Contains(string(value), "44500") ||
		strings.Contains(string(value), "address-only.catofes.") {
		t.Fatalf("published intent = %s, error = %v", value, err)
	}
	overrides[0].Endpoints[FamilyIPv4] = EndpointOverride{Address: netip.MustParseAddr("192.0.2.41")}
	later := now.Add(time.Minute)
	same := BuildOverlayIntentRecords(groups, families, existing, later)[0]
	if same.UpdatedAt != intent.UpdatedAt {
		t.Fatal("local endpoint edit republished Gossip intent")
	}
	overrides[0].Role = ""
	changed := BuildOverlayIntentRecords(groups, families, existing, later)[0]
	if len(changed.PeerRoles) != 0 || changed.UpdatedAt != later.Unix() {
		t.Fatalf("removing role override did not update intent: %+v", changed)
	}
}
