package ipsec

import (
	"context"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestPlanTransportLinksBuildsDesiredSpecsFromActiveState(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29"),
	}
	setOverlayIntentTunnelAddress(t, ns, "node-b.catofes.", group.normalizedTunnelAddress(), now)
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d, skips = %+v", len(plan.Desired), plan.Skipped)
	}
	spec := plan.Desired[0]
	if spec.PeerZone != "node-b.catofes." || spec.InitiatorRole != InitiatorRolePrimary {
		t.Fatalf("spec = %+v", spec)
	}
	if spec.IKEIdentity != "node-a.catofes." {
		t.Fatalf("IKEIdentity = %q, want local zone", spec.IKEIdentity)
	}
	if spec.LocalTunnelAddr.String() != "10.44.0.1" || spec.PeerTunnelAddr.String() != "10.44.0.2" {
		t.Fatalf("tunnel addresses = %s, %s", spec.LocalTunnelAddr, spec.PeerTunnelAddr)
	}
	if len(spec.ContactPoints) != 1 || spec.ContactPoints[0].Address != "198.51.100.20" {
		t.Fatalf("contact points = %+v", spec.ContactPoints)
	}
}

func TestPlanTransportLinksSkipsLifecycleExcludedPeer(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main", TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29")}
	setOverlayIntentTunnelAddress(t, ns, "node-b.catofes.", group.normalizedTunnelAddress(), now)

	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{
		Now:           now,
		ExcludedPeers: map[zone.ZonePath]string{"node-b.catofes.": "cleanup_after_exceeded"},
	})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 0 || !hasSkip(plan.Skipped, "node-b.catofes.", SkipLifecycleCleanup) {
		t.Fatalf("plan = %+v, want lifecycle cleanup skip and no desired link", plan)
	}
}

func TestPlanTransportLinksDerivesRuntimeNamesFromActiveGeneration(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	base := plan.Desired[0]
	if base.Generation != 1 {
		t.Fatalf("base generation = %d, want advertised generation 1", base.Generation)
	}
	if base.TransportID != RuntimeConnectionID(base.LinkID, 0, base.Provider) {
		t.Fatalf("base transport id = %q, want baseline %q", base.TransportID, RuntimeConnectionID(base.LinkID, 0, base.Provider))
	}
	if base.XFRMIfID != RuntimeXFRMIfID(base.LinkID, 0, base.Provider) || base.InterfaceName != StableInterfaceName(RuntimeXFRMIfID(base.LinkID, 0, base.Provider)) {
		t.Fatalf("base runtime = transport %q if_id %d interface %q", base.TransportID, base.XFRMIfID, base.InterfaceName)
	}

	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: DefaultIKEPort},
			NATT:       PortBinding{Advertised: 4501},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		UpdatedAt: now.Unix(),
	})
	plan, err = PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks after rotate: %v", err)
	}
	rotated := plan.Desired[0]
	if rotated.Generation != 2 || contactGeneration(rotated) != 2 {
		t.Fatalf("rotated generation = %d contact = %d, want 2", rotated.Generation, contactGeneration(rotated))
	}
	if rotated.TransportID != RuntimeConnectionID(rotated.LinkID, 2, rotated.Provider) {
		t.Fatalf("rotated transport id = %q, want %q", rotated.TransportID, RuntimeConnectionID(rotated.LinkID, 2, rotated.Provider))
	}
	if rotated.XFRMIfID != RuntimeXFRMIfID(rotated.LinkID, 2, rotated.Provider) || rotated.InterfaceName != StableInterfaceName(RuntimeXFRMIfID(rotated.LinkID, 2, rotated.Provider)) {
		t.Fatalf("rotated runtime = transport %q if_id %d interface %q", rotated.TransportID, rotated.XFRMIfID, rotated.InterfaceName)
	}
	if rotated.AddressEpoch != 2 {
		t.Fatalf("rotated address epoch = %d, want 2", rotated.AddressEpoch)
	}
}

func TestPlanTransportLinksRequiresOverlayIntent(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	delete(ns.Zones["node-b.catofes."].Records, OverlayIntentRecordKey("ipsec-main"))

	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{{ID: "ipsec-main"}}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 0 || !hasSkip(plan.Skipped, "node-b.catofes.", SkipMissingOverlayIntent) {
		t.Fatalf("plan desired=%+v skips=%+v, want missing overlay intent skip", plan.Desired, plan.Skipped)
	}
}

func TestPlanTransportLinksSkipsOverlayIntentMismatch(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	delete(ns.Zones["node-b.catofes."].Records, OverlayIntentRecordKey("ipsec-main"))
	ns.Zones["node-b.catofes."].Records[OverlayIntentRecordKey("ipsec-other")] = record(t, "node-b.catofes.", OverlayIntentRecordKey("ipsec-other"), RecordTypeOverlayIntent, OverlayIntentRecord{
		Version:       1,
		OverlayID:     "ipsec-other",
		Provider:      ProviderStrongSwan,
		PathKeys:      []string{"family:ipv4"},
		TunnelAddress: TunnelAddressSpec{Mode: TunnelAddressDerivedLinkLocal, Family: FamilyIPv6},
		UpdatedAt:     now.Unix(),
	})

	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{{ID: "ipsec-main"}}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 0 || !hasSkip(plan.Skipped, "node-b.catofes.", SkipMissingOverlayIntent) {
		t.Fatalf("plan desired=%+v skips=%+v, want missing matching overlay intent skip", plan.Desired, plan.Skipped)
	}
}

func TestPlanTransportLinksMirrorsTunnelAddressesForPeerPair(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		TunnelAddressPool: netip.MustParsePrefix("10.44.0.0/29"),
	}
	tunnel := group.normalizedTunnelAddress()
	setOverlayIntentTunnelAddress(t, ns, "node-a.catofes.", tunnel, now)
	setOverlayIntentTunnelAddress(t, ns, "node-b.catofes.", tunnel, now)
	planA, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(a): %v", err)
	}
	planB, err := PlanTransportLinks(context.Background(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(b): %v", err)
	}
	if len(planA.Desired) != 1 || len(planB.Desired) != 1 {
		t.Fatalf("desired A/B = %+v / %+v", planA.Desired, planB.Desired)
	}
	a := planA.Desired[0]
	b := planB.Desired[0]
	if a.LocalTunnelAddr != b.PeerTunnelAddr || a.PeerTunnelAddr != b.LocalTunnelAddr {
		t.Fatalf("tunnel addresses are not mirrored: A local=%s peer=%s, B local=%s peer=%s", a.LocalTunnelAddr, a.PeerTunnelAddr, b.LocalTunnelAddr, b.PeerTunnelAddr)
	}
}

func TestPlanTransportLinksSkipsOverlayIntentTunnelAddressMismatch(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{
		ID: "ipsec-main",
		TunnelAddressSpec: TunnelAddressSpec{
			Mode:   TunnelAddressDerivedPool,
			Family: FamilyIPv4,
			Pool:   netip.MustParsePrefix("10.44.0.0/29"),
		},
	}

	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 0 || !hasSkip(plan.Skipped, "node-b.catofes.", SkipOverlayIntentMismatch) {
		t.Fatalf("plan desired=%+v skips=%+v, want overlay tunnel address mismatch skip", plan.Desired, plan.Skipped)
	}
}

func TestPlanTransportLinksMirrorsDerivedTunnelAddressesForPeerPair(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Family: FamilyIPv4, Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Family: FamilyIPv4, Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{
		ID: "ipsec-main",
		TunnelAddressSpec: TunnelAddressSpec{
			Mode:   TunnelAddressDerivedLinkLocal,
			Family: FamilyIPv6,
		},
	}
	planA, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(a): %v", err)
	}
	planB, err := PlanTransportLinks(context.Background(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(b): %v", err)
	}
	if len(planA.Desired) != 1 || len(planB.Desired) != 1 {
		t.Fatalf("desired A/B = %+v / %+v", planA.Desired, planB.Desired)
	}
	a := planA.Desired[0]
	b := planB.Desired[0]
	if a.LocalTunnelAddr != b.PeerTunnelAddr || a.PeerTunnelAddr != b.LocalTunnelAddr {
		t.Fatalf("derived tunnel addresses are not mirrored: A local=%s peer=%s, B local=%s peer=%s", a.LocalTunnelAddr, a.PeerTunnelAddr, b.LocalTunnelAddr, b.PeerTunnelAddr)
	}
}

func TestPlanTransportLinksDerivedTunnelAddressStableWhenEarlierPeerAdded(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-c.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "c-public", Source: SourceManualAddress, Address: "198.51.100.30", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{
		ID:                "ipsec-main",
		TunnelAddressSpec: TunnelAddressSpec{Mode: TunnelAddressDerivedLinkLocal, Family: FamilyIPv6},
	}

	first, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(first): %v", err)
	}
	firstSpec := desiredSpecForPeer(t, first, "node-c.catofes.")

	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	second, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(second): %v", err)
	}
	secondSpec := desiredSpecForPeer(t, second, "node-c.catofes.")

	if firstSpec.InterfaceName != secondSpec.InterfaceName || firstSpec.XFRMIfID != secondSpec.XFRMIfID {
		t.Fatalf("interface changed: first=%s/%d second=%s/%d", firstSpec.InterfaceName, firstSpec.XFRMIfID, secondSpec.InterfaceName, secondSpec.XFRMIfID)
	}
	if firstSpec.LocalTunnelAddr != secondSpec.LocalTunnelAddr || firstSpec.PeerTunnelAddr != secondSpec.PeerTunnelAddr {
		t.Fatalf("derived tunnel addresses changed after adding earlier peer: first=%s/%s second=%s/%s",
			firstSpec.LocalTunnelAddr, firstSpec.PeerTunnelAddr, secondSpec.LocalTunnelAddr, secondSpec.PeerTunnelAddr)
	}
}

func TestPlanTransportLinksHonorsBothTieBreakAndInboundRole(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(a): %v", err)
	}
	if len(plan.Desired) != 1 || plan.Desired[0].PeerZone != "node-b.catofes." {
		t.Fatalf("node-a plan = %+v skips=%+v", plan.Desired, plan.Skipped)
	}
	if plan.Roles[plan.Desired[0].TransportID] != InitiatorRolePrimary {
		t.Fatalf("node-a role = %q, want primary", plan.Roles[plan.Desired[0].TransportID])
	}
	plan, err = PlanTransportLinks(context.Background(), ns, "node-b.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(b): %v", err)
	}
	if len(plan.Desired) != 1 || plan.Desired[0].PeerZone != "node-a.catofes." {
		t.Fatalf("node-b should keep a standby desired spec: desired=%+v skips=%+v", plan.Desired, plan.Skipped)
	}
	if plan.Roles[plan.Desired[0].TransportID] != InitiatorRoleSecondaryStandby {
		t.Fatalf("node-b role = %q, want secondary-standby", plan.Roles[plan.Desired[0].TransportID])
	}
}

func TestPlanTransportLinksKeepsInboundResponderDesired(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-local", Source: SourceLocal, Address: "192.168.8.20", Priority: 100, TTLSeconds: 300,
	}}, now)

	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 || plan.Desired[0].PeerZone != "node-b.catofes." {
		t.Fatalf("inbound responder desired = %+v skips=%+v, want one", plan.Desired, plan.Skipped)
	}
	spec := plan.Desired[0]
	if IsActiveInitiatorRole(spec.InitiatorRole) || len(spec.ContactPoints) != 0 {
		t.Fatalf("inbound responder spec = %+v, want trap-style spec without contact points", spec)
	}
	if plan.Roles[spec.TransportID] != "" {
		t.Fatalf("inbound responder role = %q, want empty responder role", plan.Roles[spec.TransportID])
	}
}

func TestPlanTransportLinksSkipsRevokedPeerAndMissingContactPoint(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-local", Source: SourceLocal, Address: "192.168.8.20", Priority: 100, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-c.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "c-public", Source: SourceManualAddress, Address: "198.51.100.30", Priority: 100, TTLSeconds: 300,
	}}, now)
	ns.Zones["catofes."] = zone.NewZoneState("catofes.", nil)
	ns.Zones["catofes."].Revocations["node-c.catofes."] = &zone.DelegationRevocation{
		ChildZone:  "node-c.catofes.",
		ParentZone: "catofes.",
		RevokedAt:  now.Add(-time.Minute).Unix(),
	}
	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 0 {
		t.Fatalf("desired = %+v", plan.Desired)
	}
	if !hasSkip(plan.Skipped, "node-b.catofes.", SkipNoContactPoints) {
		t.Fatalf("missing no-contact skip: %+v", plan.Skipped)
	}
	if !hasSkip(plan.Skipped, "node-c.catofes.", SkipRevokedZone) {
		t.Fatalf("missing revoked skip: %+v", plan.Skipped)
	}
}

func TestPlanTransportLinksUsesContactPointQualityForPortFallback(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Advertised: 500},
			NATT:       PortBinding{Advertised: 4500},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		Previous: []PortSelection{{
			Generation: 1,
			IKE:        PortBinding{Advertised: 1500},
			NATT:       PortBinding{Advertised: 14500},
			ValidUntil: now.Add(10 * time.Minute).Unix(),
		}},
		UpdatedAt: now.Unix(),
	})
	currentKey := ContactPoint{
		AddressID:  "b-public",
		Address:    "198.51.100.20",
		Generation: 2,
		IKEPort:    500,
		NATTPort:   4500,
	}.Key()
	group := LinkGroupSpec{ID: "ipsec-main", DefaultPathMode: PathModeExhaustive}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{
		Now: now,
		ContactPointQuality: map[zone.ZonePath]map[string]ContactPointQuality{
			"node-b.catofes.": {
				currentKey: {
					Failures:     2,
					BackoffUntil: now.Add(time.Minute),
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d skips=%+v", len(plan.Desired), plan.Skipped)
	}
	point := plan.Desired[0].ContactPoints[0]
	if point.Current || point.IKEPort != 1500 {
		t.Fatalf("first contact point = %+v, want previous grace port", point)
	}
	if plan.Desired[0].ContactPoints[1].Failures != 2 {
		t.Fatalf("current point quality missing: %+v", plan.Desired[0].ContactPoints)
	}
}

func TestPlanTransportLinksDoesNotUseAdvertisedLocalPortAsStrongSwanLocalPort(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleBoth, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	ns.Zones["node-a.catofes."].Records[RecordKeyPorts] = record(t, "node-a.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeRange,
		Range:   &PortRange{From: 33400, To: 33499},
		Current: &PortSelection{
			Generation: 2,
			IKE:        PortBinding{Local: DefaultIKEPort, Advertised: 33402},
			NATT:       PortBinding{Local: DefaultNATTPort, Advertised: 33403},
		},
		UpdatedAt: now.Unix(),
	})
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeRange,
		Range:   &PortRange{From: 30000, To: 30099},
		Current: &PortSelection{
			Generation: 7,
			IKE:        PortBinding{Local: DefaultIKEPort, Advertised: 30001},
			NATT:       PortBinding{Local: DefaultNATTPort, Advertised: 30002},
		},
		UpdatedAt: now.Unix(),
	})

	group := LinkGroupSpec{ID: "ipsec-main", DefaultPathMode: PathModeFamilyRedundant}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d, want 1; skips=%+v", len(plan.Desired), plan.Skipped)
	}
	spec := plan.Desired[0]
	if spec.LocalIKEPort != 0 {
		t.Fatalf("LocalIKEPort = %d, want zero so charon uses its actual listener", spec.LocalIKEPort)
	}
	if len(spec.ContactPoints) != 1 || spec.ContactPoints[0].IKEPort != 30001 {
		t.Fatalf("remote contact points = %+v, want peer advertised port", spec.ContactPoints)
	}
	conn, err := BuildStrongSwanConnection(spec)
	if err != nil {
		t.Fatalf("BuildStrongSwanConnection: %v", err)
	}
	if got := conn["remote_port"]; got != "30002" {
		t.Fatalf("remote_port = %v, want peer advertised NAT-T port 30002", got)
	}
	if got := conn["encap"]; got != "yes" {
		t.Fatalf("encap = %v, want yes for NAT-T custom server port", got)
	}
	if got := conn["local_port"]; got != "4500" {
		t.Fatalf("local_port = %v, want NAT-T source port 4500 for custom server port", got)
	}
}

func TestPlanTransportLinksSkipsBehindNATWithoutInboundEvidence(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-lan", Source: SourceLocal, Address: "192.168.8.20", Priority: 100, Reachability: ReachabilityPrivate, TTLSeconds: 300,
	}}, now)
	setIPsecNATProfile(t, ns, "node-b.catofes.", RoleIn, NATProfile{Hint: NATHintBehindNAT, InboundReachable: NATReachableFalse}, now)

	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{
		Now:               now,
		AllowPrivateLocal: true,
	})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 0 {
		t.Fatalf("desired = %+v, want no fake reachable NAT link", plan.Desired)
	}
	if !hasSkip(plan.Skipped, "node-b.catofes.", SkipNoInboundNATEvidence) {
		t.Fatalf("skips = %+v, want %s", plan.Skipped, SkipNoInboundNATEvidence)
	}
}

func TestPlanTransportLinksAllowsNATOutboundToPublicPeer(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-lan", Source: SourceLocal, Address: "192.168.8.10", Priority: 100, Reachability: ReachabilityPrivate, TTLSeconds: 300,
	}}, now)
	setIPsecNATProfile(t, ns, "node-a.catofes.", RoleOut, NATProfile{Hint: NATHintBehindNAT, InboundReachable: NATReachableFalse}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-public", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)

	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d skips=%+v", len(plan.Desired), plan.Skipped)
	}
	if plan.Desired[0].PeerZone != "node-b.catofes." || plan.Desired[0].ContactPoints[0].Address != "198.51.100.20" {
		t.Fatalf("desired = %+v", plan.Desired)
	}
}

func TestPlanTransportLinksAllowsNATObservedExternalPort(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-observed", Source: SourceReflector, Address: "203.0.113.20", Priority: 100, Reachability: ReachabilityNATObserved, TTLSeconds: 300,
	}}, now)
	setIPsecNATProfile(t, ns, "node-b.catofes.", RoleIn, NATProfile{Hint: NATHintBehindNAT, InboundReachable: NATReachableUnknown}, now)
	ns.Zones["node-b.catofes."].Records[RecordKeyPorts] = record(t, "node-b.catofes.", RecordKeyPorts, RecordTypePorts, PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 1,
			IKE:        PortBinding{Advertised: 500, Observed: 35000},
			NATT:       PortBinding{Advertised: 4500, Observed: 35001},
			ValidUntil: now.Add(time.Hour).Unix(),
		},
		UpdatedAt: now.Unix(),
	})

	group := LinkGroupSpec{ID: "ipsec-main"}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d skips=%+v", len(plan.Desired), plan.Skipped)
	}
	point := plan.Desired[0].ContactPoints[0]
	if !point.ObservedPort || point.IKEPort != 35000 || point.NATTPort != 35001 {
		t.Fatalf("contact point = %+v, want observed external ports", point)
	}
}

func TestPlanTransportLinksAppliesMeshPolicyRules(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{
		{ID: "b-manual", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300},
		{ID: "b-discovery", Source: SourceDiscovery, Address: "198.51.100.21", Priority: 1, Reachability: ReachabilityPublic, TTLSeconds: 300},
	}, now)
	addIPsecNode(t, ns, "node-c.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "c-public", Source: SourceManualAddress, Address: "198.51.100.30", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-d.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "d-public", Source: SourceManualAddress, Address: "198.51.100.40", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-e.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "e-discovery", Source: SourceDiscovery, Address: "198.51.100.50", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)

	group := LinkGroupSpec{
		ID:           "ipsec-main",
		ConnectRules: []string{"strongswan://*.catofes.?role=in&source=discovery&mode=exhaustive&max_peers=1"},
		DenyRules:    []string{"strongswan://node-d.catofes."},
	}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired len = %d skips=%+v", len(plan.Desired), plan.Skipped)
	}
	spec := plan.Desired[0]
	if spec.PeerZone != "node-b.catofes." || spec.PathMode != PathModeExhaustive {
		t.Fatalf("spec = %+v", spec)
	}
	if len(spec.ContactPoints) != 1 || spec.ContactPoints[0].Source != SourceDiscovery || spec.ContactPoints[0].Address != "198.51.100.21" {
		t.Fatalf("contact points = %+v, want discovery-only address from policy source filter", spec.ContactPoints)
	}
	if !hasSkip(plan.Skipped, "node-c.catofes.", SkipPolicyNoMatch) {
		t.Fatalf("missing policy no-match skip: %+v", plan.Skipped)
	}
	if !hasSkip(plan.Skipped, "node-d.catofes.", SkipPolicyDenied) {
		t.Fatalf("missing policy denied skip: %+v", plan.Skipped)
	}
	if !hasSkip(plan.Skipped, "node-e.catofes.", SkipMaxPeers) {
		t.Fatalf("missing policy max-peers skip: %+v", plan.Skipped)
	}
}

func TestPlanTransportLinksPolicyFamilyFiltersOutboundContactPoints(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{
		{ID: "b-v4", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300},
		{ID: "b-v6", Source: SourceManualAddress, Address: "2001:db8::20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300},
	}, now)

	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{{
		ID:           "ipsec-main",
		ConnectRules: []string{"strongswan://node-b.catofes.?role=in&family=ipv4"},
	}}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 1 {
		t.Fatalf("desired = %+v skips=%+v, want one IPv4 link", plan.Desired, plan.Skipped)
	}
	spec := plan.Desired[0]
	if spec.PathKey != "family:ipv4" || len(spec.ContactPoints) != 1 || spec.ContactPoints[0].Family != FamilyIPv4 || spec.ContactPoints[0].Address != "198.51.100.20" {
		t.Fatalf("spec = %+v, want only IPv4 contact", spec)
	}
}

func TestPlanTransportLinksDryRunDualStackModes(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{
		{ID: "b-v4-primary", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300},
		{ID: "b-v4-backup", Source: SourceManualAddress, Address: "198.51.100.21", Priority: 10, Reachability: ReachabilityPublic, TTLSeconds: 300},
		{ID: "b-v6-primary", Source: SourceManualAddress, Address: "2001:db8::20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300},
		{ID: "b-v6-backup", Source: SourceManualAddress, Address: "2001:db8::21", Priority: 10, Reachability: ReachabilityPublic, TTLSeconds: 300},
	}, now)

	group := LinkGroupSpec{ID: "ipsec-main", DefaultPathMode: PathModeFamilyRedundant}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(family): %v", err)
	}
	if len(plan.Desired) != 2 {
		t.Fatalf("desired len = %d skips=%+v, want one spec per family", len(plan.Desired), plan.Skipped)
	}
	for _, spec := range plan.Desired {
		if spec.InitiatorRole != InitiatorRolePrimary {
			t.Fatalf("spec role = %q, want primary", spec.InitiatorRole)
		}
		if len(spec.ContactPoints) != 1 {
			t.Fatalf("family-redundant contacts = %+v, want one per spec", spec.ContactPoints)
		}
		if spec.ContactPoints[0].RankReason == "" {
			t.Fatalf("contact missing rank reason: %+v", spec.ContactPoints[0])
		}
	}
	families := []string{plan.Desired[0].ContactPoints[0].Family, plan.Desired[1].ContactPoints[0].Family}
	if families[0] != FamilyIPv4 || families[1] != FamilyIPv6 {
		t.Fatalf("family order = %v, want [ipv4, ipv6]", families)
	}

	group.DefaultPathMode = PathModeExhaustive
	plan, err = PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(exhaustive): %v", err)
	}
	if len(plan.Desired) != 1 || len(plan.Desired[0].ContactPoints) != 4 {
		t.Fatalf("exhaustive desired = %+v skips=%+v", plan.Desired, plan.Skipped)
	}
}

func TestPlanTransportLinksFamilyRedundantStableIDsDifferPerFamily(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{
		{ID: "b-v4", Source: SourceManualAddress, Address: "198.51.100.20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300},
		{ID: "b-v6", Source: SourceManualAddress, Address: "2001:db8::20", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300},
	}, now)

	group := LinkGroupSpec{ID: "ipsec-main", DefaultPathMode: PathModeFamilyRedundant}
	plan, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks: %v", err)
	}
	if len(plan.Desired) != 2 {
		t.Fatalf("desired len = %d, want 2", len(plan.Desired))
	}
	byPath := map[string]TransportLinkSpec{}
	ids := map[string]bool{}
	ifIDs := map[uint32]bool{}
	ifNames := map[string]bool{}
	for _, spec := range plan.Desired {
		byPath[spec.PathKey] = spec
		if ids[spec.TransportID] {
			t.Fatalf("duplicate TransportID %q", spec.TransportID)
		}
		if ids[spec.InterfaceName] {
			t.Fatalf("duplicate InterfaceName %q", spec.InterfaceName)
		}
		if ifIDs[spec.XFRMIfID] {
			t.Fatalf("duplicate XFRMIfID %d", spec.XFRMIfID)
		}
		ids[spec.TransportID] = true
		ifIDs[spec.XFRMIfID] = true
		ifNames[spec.InterfaceName] = true
	}
	for _, pathKey := range []string{"family:ipv4", "family:ipv6"} {
		spec, ok := byPath[pathKey]
		if !ok {
			t.Fatalf("missing desired spec for %s: %+v", pathKey, plan.Desired)
		}
		if spec.LinkID != StableLinkID("node-a.catofes.", "node-b.catofes.", "ipsec-main", pathKey) {
			t.Fatalf("%s LinkID = %q, want stable path-derived id", pathKey, spec.LinkID)
		}
		if spec.TransportID != RuntimeConnectionID(spec.LinkID, 0, spec.Provider) {
			t.Fatalf("%s TransportID = %q, want runtime id from LinkID", pathKey, spec.TransportID)
		}
	}
	if byPath["family:ipv4"].LinkID == byPath["family:ipv6"].LinkID {
		t.Fatalf("family-specific LinkID reused across paths: %+v", byPath)
	}

	ns.Zones["node-b.catofes."].Records[OverlayIntentRecordKey("ipsec-main")] = record(t, "node-b.catofes.", OverlayIntentRecordKey("ipsec-main"), RecordTypeOverlayIntent, OverlayIntentRecord{
		Version:       1,
		OverlayID:     "ipsec-main",
		Provider:      ProviderStrongSwan,
		PathKeys:      []string{"family:ipv4"},
		TunnelAddress: TunnelAddressSpec{Mode: TunnelAddressDerivedLinkLocal, Family: FamilyIPv6},
		UpdatedAt:     now.Unix(),
	})
	plan, err = PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{Now: now})
	if err != nil {
		t.Fatalf("PlanTransportLinks(single-family intent): %v", err)
	}
	if len(plan.Desired) != 1 || plan.Desired[0].PathKey != "family:ipv4" {
		t.Fatalf("single-family intent desired = %+v skips=%+v, want only family:ipv4", plan.Desired, plan.Skipped)
	}
}

func TestPlanTransportLinksDryRunDNSRefreshUpdatesContactPoint(t *testing.T) {
	now := time.Unix(1717171717, 0)
	ns := zone.NewNetworkState()
	addIPsecNode(t, ns, "node-a.catofes.", RoleOut, []AddressAdvertisement{{
		ID: "a-public", Source: SourceManualAddress, Address: "198.51.100.10", Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)
	addIPsecNode(t, ns, "node-b.catofes.", RoleIn, []AddressAdvertisement{{
		ID: "b-dns", Source: SourceManualDNS, Host: "node-b.example.com", Families: []string{FamilyIPv4}, RefreshSeconds: 30, Priority: 100, Reachability: ReachabilityPublic, TTLSeconds: 300,
	}}, now)

	group := LinkGroupSpec{
		ID:                 "ipsec-main",
		AddressSourceOrder: []string{SourceManualDNS},
	}
	first, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{
		Now: now,
		DNSResolver: staticDNSResolver{
			"node-b.example.com": {{IP: net.ParseIP("198.51.100.20")}},
		},
	})
	if err != nil {
		t.Fatalf("PlanTransportLinks(first): %v", err)
	}
	second, err := PlanTransportLinks(context.Background(), ns, "node-a.catofes.", []LinkGroupSpec{group}, LinkPlannerOptions{
		Now: now.Add(31 * time.Second),
		DNSResolver: staticDNSResolver{
			"node-b.example.com": {{IP: net.ParseIP("198.51.100.21")}},
		},
	})
	if err != nil {
		t.Fatalf("PlanTransportLinks(second): %v", err)
	}
	if len(first.Desired) != 1 || len(second.Desired) != 1 {
		t.Fatalf("plans = %+v / %+v", first, second)
	}
	firstPoint := first.Desired[0].ContactPoints[0]
	secondPoint := second.Desired[0].ContactPoints[0]
	if firstPoint.Host != "node-b.example.com" || firstPoint.Address != "198.51.100.20" {
		t.Fatalf("first contact = %+v", firstPoint)
	}
	if secondPoint.Host != "node-b.example.com" || secondPoint.Address != "198.51.100.21" {
		t.Fatalf("second contact = %+v", secondPoint)
	}
	if first.Desired[0].TransportID != second.Desired[0].TransportID || first.Desired[0].XFRMIfID != second.Desired[0].XFRMIfID {
		t.Fatalf("DNS refresh changed stable link identity: %+v vs %+v", first.Desired[0], second.Desired[0])
	}
}
