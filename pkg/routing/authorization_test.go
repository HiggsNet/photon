package routing

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func mustKeyRoute(prefix string) string {
	key, err := NormalizeRouteAnnouncementKey(prefix)
	if err != nil {
		panic(err)
	}
	return key
}

func mustKeyAssignment(prefix string) string {
	key, err := NormalizeIPAMAssignmentKey(prefix)
	if err != nil {
		panic(err)
	}
	return key
}

func mustKeyPool(prefix string) string {
	key, err := NormalizeIPAMPoolKey(prefix)
	if err != nil {
		panic(err)
	}
	return key
}

func mustJSON(v any) []byte {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}

func mkRecord(z zone.ZonePath, key, typ string, value []byte) *zone.Record {
	return &zone.Record{Zone: z, Key: key, Type: typ, Value: value}
}

func addZone(ns *zone.NetworkState, path, parent zone.ZonePath, records ...*zone.Record) {
	zs := zone.NewZoneState(path, &zone.ZoneAuthority{Zone: path})
	for _, rec := range records {
		zs.Records[rec.Key] = rec
	}
	ns.Zones[path] = zs

	if parent != "" && parent != path {
		parentZS := ns.Zones[parent]
		if parentZS != nil {
			parentZS.Delegations[path] = &zone.Delegation{ZoneName: path}
		}
	}
}

func addRecords(ns *zone.NetworkState, path zone.ZonePath, records ...*zone.Record) {
	zs := ns.Zones[path]
	if zs == nil {
		panic("zone not found: " + string(path))
	}
	for _, rec := range records {
		zs.Records[rec.Key] = rec
	}
}

func addIPAMPoolRecord(ns *zone.NetworkState, source zone.ZonePath, prefix string, delegatedTo zone.ZonePath) {
	addRecords(ns, source,
		mkRecord(source, mustKeyPool(prefix), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: prefix, DelegatedTo: delegatedTo, Active: true})),
	)
}

func hasCode(errors []RouteAuthorizationError, code string) bool {
	for _, e := range errors {
		if e.Code == code {
			return true
		}
	}
	return false
}

func TestBasicAnnouncementSameZone(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addIPAMPoolRecord(ns, "catofes.", "10.0.1.0/24", "pek.catofes.")
	addZone(ns, "pek.catofes.", "catofes.",
		mkRecord("pek.catofes.", mustKeyPool("10.0.1.0/24"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.1.0/24", DelegatedTo: "pek.catofes.", Active: true})),
		mkRecord("pek.catofes.", mustKeyAssignment("10.0.1.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "pek.catofes.", Active: true, Shared: true, Tag: "edge.cn"})),
		mkRecord("pek.catofes.", mustKeyRoute("10.0.1.0/24"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.1.0/24", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if ars.Announced["pek.catofes."] == nil {
		t.Fatalf("expected announcements for pek.catofes.")
	}
	entry := ars.Announced["pek.catofes."][netip.MustParsePrefix("10.0.1.0/24")]
	if entry == nil {
		t.Fatalf("expected 10.0.1.0/24 to be authorized")
	}
	if entry.AssignmentTag != "edge.cn" {
		t.Fatalf("assignment tag = %q, want edge.cn", entry.AssignmentTag)
	}
}

func TestParentAggregateAnnouncement(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addZone(ns, "pek.catofes.", "catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("10.0.0.0/16"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/16"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/16", AssignedTo: "pek.catofes.", Active: true})),
		mkRecord("catofes.", mustKeyRoute("10.0.0.0/16"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.0.0/16", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if ars.Announced["catofes."] == nil || ars.Announced["catofes."][netip.MustParsePrefix("10.0.0.0/16")] == nil {
		t.Fatalf("expected parent aggregate announcement to be authorized")
	}
}

func TestWithdrawnAnnouncementNotAuthorized(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addIPAMPoolRecord(ns, "catofes.", "10.0.1.0/24", "pek.catofes.")
	addZone(ns, "pek.catofes.", "catofes.",
		mkRecord("pek.catofes.", mustKeyPool("10.0.1.0/24"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.1.0/24", DelegatedTo: "pek.catofes.", Active: true})),
		mkRecord("pek.catofes.", mustKeyAssignment("10.0.1.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "pek.catofes.", Active: true})),
		mkRecord("pek.catofes.", mustKeyRoute("10.0.1.0/24"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.1.0/24", Active: false})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if len(ars.Announced) != 0 {
		t.Fatalf("withdrawn announcement should not appear in authorized set")
	}
}

func TestNoAssignmentRejected(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.",
		mkRecord("pek.catofes.", mustKeyRoute("10.0.1.0/24"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.1.0/24", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "route_unauthorized_no_assignment") {
		t.Fatalf("expected route_unauthorized_no_assignment error, got %+v", ars.Errors)
	}
	if len(ars.Announced) != 0 {
		t.Fatalf("expected no authorized announcements")
	}
}

func TestMoreSpecificAnnouncementAllowed(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("10.0.0.0/16"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "catofes.", Active: true})),
		mkRecord("catofes.", mustKeyPool("10.0.1.0/24"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.1.0/24", DelegatedTo: "pek.catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/16"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/16", AssignedTo: "pek.catofes.", Active: true})),
	)
	addRecords(ns, "pek.catofes.",
		mkRecord("pek.catofes.", mustKeyRoute("10.0.1.0/24"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.1.0/24", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if ars.Announced["pek.catofes."] == nil || ars.Announced["pek.catofes."][netip.MustParsePrefix("10.0.1.0/24")] == nil {
		t.Fatalf("expected more-specific announcement to be authorized")
	}
}

func TestMoreBroadAnnouncementRejected(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("10.0.1.0/24"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.1.0/24", DelegatedTo: "catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.1.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "pek.catofes.", Active: true})),
	)
	addRecords(ns, "pek.catofes.",
		mkRecord("pek.catofes.", mustKeyRoute("10.0.0.0/16"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.0.0/16", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "route_unauthorized_no_assignment") {
		t.Fatalf("expected route_unauthorized_no_assignment error, got %+v", ars.Errors)
	}
	if len(ars.Announced) != 0 {
		t.Fatalf("expected broad announcement to be rejected")
	}
}

func TestSiblingOverlapUnauthorized(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "child1.catofes.", "catofes.")
	addZone(ns, "child2.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.1.0/24", "catofes.")

	// A single parent assignment usable by the whole subtree; both siblings
	// announce the exact same prefix, which must be rejected.
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("10.0.1.0/24"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.1.0/24", DelegatedTo: "catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.1.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "catofes.", Active: true})),
	)
	addRecords(ns, "child1.catofes.",
		mkRecord("child1.catofes.", mustKeyRoute("10.0.1.0/24"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.1.0/24", Active: true})),
	)
	addRecords(ns, "child2.catofes.",
		mkRecord("child2.catofes.", mustKeyRoute("10.0.1.0/24"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.1.0/24", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "route_overlap_unauthorized") {
		t.Fatalf("expected route_overlap_unauthorized error, got %+v", ars.Errors)
	}
	if ars.Announced["child1.catofes."] != nil || ars.Announced["child2.catofes."] != nil {
		t.Fatalf("expected overlapping sibling announcements to be rejected")
	}
}

func TestRevokedZoneAnnouncementRejected(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "node1.catofes.", "catofes.")

	// Delegation and matching revocation.
	ns.Zones["catofes."].Delegations["node1.catofes."] = &zone.Delegation{
		ZoneName:       "node1.catofes.",
		AuthorityEpoch: 1,
		AuthorityHash:  []byte{1},
	}
	ns.Zones["catofes."].Revocations["node1.catofes."] = &zone.DelegationRevocation{
		ChildZone:             "node1.catofes.",
		ParentZone:            "catofes.",
		RevokedAuthorityEpoch: 1,
		RevokedAuthorityHash:  []byte{1},
		RevokedAt:             100,
	}

	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyAssignment("10.0.1.1/32"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.1/32", AssignedTo: "node1.catofes.", Active: true})),
	)
	addRecords(ns, "node1.catofes.",
		mkRecord("node1.catofes.", mustKeyRoute("10.0.1.1/32"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.1.1/32", Active: true})),
	)

	now := time.Unix(200, 0)
	if !ns.IsZoneRevoked("node1.catofes.", now) {
		t.Fatal("node1.catofes. should be revoked in this test")
	}

	ars, err := BuildAuthorizedRouteSet(ns, now)
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "route_zone_revoked") {
		t.Fatalf("expected route_zone_revoked error, got %+v", ars.Errors)
	}
	if len(ars.Announced) != 0 {
		t.Fatalf("revoked zone announcement should not be authorized")
	}
}

func TestIPv6Authorization(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "2001:db8::/31", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "2001:db8::/32", "catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("2001:db8::/32"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "2001:db8::/32", DelegatedTo: "catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("2001:db8::/32"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "2001:db8::/32", AssignedTo: "pek.catofes.", Active: true})),
	)
	addRecords(ns, "pek.catofes.",
		mkRecord("pek.catofes.", mustKeyRoute("2001:db8:1::/48"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "2001:db8:1::/48", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if ars.Announced["pek.catofes."] == nil || ars.Announced["pek.catofes."][netip.MustParsePrefix("2001:db8:1::/48")] == nil {
		t.Fatalf("expected IPv6 announcement to be authorized")
	}
}

func TestParentCannotAnnounceAssignmentToDescendant(t *testing.T) {
	// root assigns a prefix to pek.catofes.; catofes. must not announce it.
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addRecords(ns, zone.RootZone,
		mkRecord(zone.RootZone, mustKeyPool("10.0.0.0/8"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/8", DelegatedTo: zone.RootZone, Active: true})),
		mkRecord(zone.RootZone, mustKeyAssignment("10.0.0.0/8"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/8", AssignedTo: "pek.catofes.", Active: true})),
	)
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyRoute("10.0.0.0/8"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.0.0/8", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "route_unauthorized_no_assignment") {
		t.Fatalf("expected route_unauthorized_no_assignment error, got %+v", ars.Errors)
	}
	if ars.Announced["catofes."] != nil {
		t.Fatalf("expected catofes. announcement to be rejected")
	}
}

func TestPoolEnforcementValid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addZone(ns, "pek.catofes.", "catofes.",
		mkRecord("pek.catofes.", mustKeyPool("10.0.0.0/24"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/24", DelegatedTo: "pek.catofes.", Active: true})),
		mkRecord("pek.catofes.", mustKeyAssignment("10.0.0.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/24", AssignedTo: "pek.catofes.", Active: true})),
	)
	addIPAMPoolRecord(ns, "catofes.", "10.0.0.0/24", "pek.catofes.")

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if ars.Assignments[netip.MustParsePrefix("10.0.0.0/24")] == nil {
		t.Fatalf("expected assignment to be kept")
	}
}

func TestPoolEnforcementAncestorPoolValid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addZone(ns, "pek.catofes.", "catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("10.0.0.0/16"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "pek.catofes.", Active: true})),
	)
	addRecords(ns, "pek.catofes.",
		mkRecord("pek.catofes.", mustKeyAssignment("10.0.0.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/24", AssignedTo: "pek.catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if ars.Assignments[netip.MustParsePrefix("10.0.0.0/24")] == nil {
		t.Fatalf("expected assignment to be kept")
	}
}

func TestPoolEnforcementInvalidDelegatedTo(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addZone(ns, "sh.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")

	// catofes delegates the pool to pek, but sh tries to assign from it.
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("10.0.0.0/16"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "pek.catofes.", Active: true})),
	)
	addRecords(ns, "sh.catofes.",
		mkRecord("sh.catofes.", mustKeyAssignment("10.0.0.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/24", AssignedTo: "sh.catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "ipam_assignment_pool_mismatch") {
		t.Fatalf("expected ipam_assignment_pool_mismatch error, got %+v", ars.Errors)
	}
	if ars.Assignments[netip.MustParsePrefix("10.0.0.0/24")] != nil {
		t.Fatalf("expected invalid assignment to be removed")
	}
}

func TestPoolEnforcementNoPool(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.",
		mkRecord("pek.catofes.", mustKeyAssignment("10.0.0.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/24", AssignedTo: "pek.catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "ipam_assignment_pool_mismatch") {
		t.Fatalf("expected ipam_assignment_pool_mismatch error, got %+v", ars.Errors)
	}
	if ars.Assignments[netip.MustParsePrefix("10.0.0.0/24")] != nil {
		t.Fatalf("expected invalid assignment to be removed")
	}
}

func TestIPAMPoolRootBootstrapValid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if len(ars.AllPools) != 1 || ars.AllPools[0].DelegatedTo != zone.RootZone {
		t.Fatalf("AllPools = %+v, want root bootstrap pool", ars.AllPools)
	}
}

func TestIPAMPoolDelegationRequiresOwnedCoveringPool(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "ipam_pool_owner_mismatch") {
		t.Fatalf("expected ipam_pool_owner_mismatch, got %+v", ars.Errors)
	}
	if len(ars.AllPools) != 0 {
		t.Fatalf("AllPools = %+v, want no valid pools", ars.AllPools)
	}
}

func TestIPAMPoolNestedDelegationFromCurrentOwnerValid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addIPAMPoolRecord(ns, "catofes.", "10.0.1.0/24", "pek.catofes.")

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if len(ars.AllPools) != 3 {
		t.Fatalf("AllPools len = %d, want 3: %+v", len(ars.AllPools), ars.AllPools)
	}
}

func TestIPAMPoolSiblingOverlapRejected(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "other.", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.1.0/24", "other.")

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "ipam_pool_overlap") {
		t.Fatalf("expected ipam_pool_overlap, got %+v", ars.Errors)
	}
}

func TestIPAMAssignmentDoesNotInheritAncestorPool(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyAssignment("10.0.1.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "ipam_assignment_pool_mismatch") {
		t.Fatalf("expected ipam_assignment_pool_mismatch, got %+v", ars.Errors)
	}
	if len(ars.AllAssignments) != 0 {
		t.Fatalf("AllAssignments = %+v, want none", ars.AllAssignments)
	}
}

func TestIPAMAssignmentUsesExplicitDelegatedPool(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyAssignment("10.0.1.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if len(ars.AllAssignments) != 1 {
		t.Fatalf("AllAssignments len = %d, want 1", len(ars.AllAssignments))
	}
}

func TestAssignmentOverlapSameZoneHierarchicalValid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addZone(ns, "node1.pek.catofes.", "pek.catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.1.0.0/16", "catofes.")
	addIPAMPoolRecord(ns, "catofes.", "10.1.0.0/16", "pek.catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("10.0.0.0/16"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/16"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/16", AssignedTo: "pek.catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.1.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "node1.pek.catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if len(ars.Assignments) != 2 {
		t.Fatalf("expected 2 assignments, got %d", len(ars.Assignments))
	}
}

func TestAssignmentOverlapSameZoneSiblingInvalid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addZone(ns, "sh.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("10.0.0.0/16"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/16"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/16", AssignedTo: "pek.catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.1.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "sh.catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "ipam_assignment_overlap") {
		t.Fatalf("expected ipam_assignment_overlap error, got %+v", ars.Errors)
	}
	if len(ars.Assignments) != 0 {
		t.Fatalf("expected overlapping assignments to be removed, got %d", len(ars.Assignments))
	}
}

func TestAssignmentOverlapSameZoneSameAssigneeInvalid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("10.0.0.0/16"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/16"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/16", AssignedTo: "pek.catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.1.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "pek.catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "ipam_assignment_overlap") {
		t.Fatalf("expected ipam_assignment_overlap error, got %+v", ars.Errors)
	}
}

func TestAssignmentOverlapCrossZoneDelegationChainValid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("10.0.0.0/16"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "catofes.", Active: true})),
		mkRecord("catofes.", mustKeyPool("10.0.1.0/24"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.1.0/24", DelegatedTo: "pek.catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/16"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/16", AssignedTo: "pek.catofes.", Active: true})),
	)
	addRecords(ns, "pek.catofes.",
		mkRecord("pek.catofes.", mustKeyPool("10.0.1.0/24"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.1.0/24", DelegatedTo: "pek.catofes.", Active: true})),
		mkRecord("pek.catofes.", mustKeyAssignment("10.0.1.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "pek.catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("unexpected errors: %+v", ars.Errors)
	}
	if len(ars.Assignments) != 2 {
		t.Fatalf("expected 2 assignments, got %d", len(ars.Assignments))
	}
}

func TestAssignmentOverlapCrossZoneSiblingInvalid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addZone(ns, "sh.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addIPAMPoolRecord(ns, "catofes.", "10.0.0.0/23", "pek.catofes.")
	addIPAMPoolRecord(ns, "catofes.", "10.0.0.0/24", "sh.catofes.")
	addRecords(ns, "pek.catofes.",
		mkRecord("pek.catofes.", mustKeyPool("10.0.0.0/23"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/23", DelegatedTo: "pek.catofes.", Active: true})),
		mkRecord("pek.catofes.", mustKeyAssignment("10.0.0.0/23"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/23", AssignedTo: "pek.catofes.", Active: true})),
	)
	addRecords(ns, "sh.catofes.",
		mkRecord("sh.catofes.", mustKeyPool("10.0.0.0/24"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/24", DelegatedTo: "sh.catofes.", Active: true})),
		mkRecord("sh.catofes.", mustKeyAssignment("10.0.0.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/24", AssignedTo: "sh.catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "ipam_assignment_overlap") {
		t.Fatalf("expected ipam_assignment_overlap error, got %+v", ars.Errors)
	}
	if len(ars.Assignments) != 0 {
		t.Fatalf("expected overlapping assignments to be removed, got %d", len(ars.Assignments))
	}
}

func TestAssignmentOverlapCrossZoneNoContainmentValid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.1.0.0/16", "catofes.")
	addIPAMPoolRecord(ns, "catofes.", "10.1.0.0/16", "pek.catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyPool("10.0.0.0/16"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "catofes.", Active: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/16"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/16", AssignedTo: "pek.catofes.", Active: true})),
	)
	addRecords(ns, "pek.catofes.",
		mkRecord("pek.catofes.", mustKeyPool("10.1.0.0/16"), RecordTypeIPAMPool,
			mustJSON(IPAMPoolRecord{Version: 1, Prefix: "10.1.0.0/16", DelegatedTo: "pek.catofes.", Active: true})),
		mkRecord("pek.catofes.", mustKeyAssignment("10.1.0.0/16"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.1.0.0/16", AssignedTo: "pek.catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("expected no errors for non-overlapping assignments: %+v", ars.Errors)
	}
	if len(ars.Assignments) != 2 {
		t.Fatalf("expected 2 assignments, got %d", len(ars.Assignments))
	}
}

func TestAnycastAssignmentOverlapCrossZoneValid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addZone(ns, "sh.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	// The owner publishes both shared anycast assignments. Sibling zones do
	// not need overlapping pools to announce the assigned prefix.
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/24")+"#pek", RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/24", AssignedTo: "pek.catofes.", Active: true, Shared: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/24")+"#sh", RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/24", AssignedTo: "sh.catofes.", Active: true, Shared: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("expected no errors for anycast shared assignments: %+v", ars.Errors)
	}
	// Both assignments should be kept (they share the same prefix, but AllAssignments has both).
	count := 0
	for _, entry := range ars.AllAssignments {
		if entry.Prefix == netip.MustParsePrefix("10.0.0.0/24") {
			count++
		}
	}
	if count != 2 {
		t.Fatalf("expected 2 anycast assignments for 10.0.0.0/24, got %d", count)
	}
}

func TestSharedAssignmentTagConflictRejected(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addZone(ns, "sh.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyAssignment("10.0.1.0/24")+"#pek", RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.1.0/24", AssignedTo: "pek.catofes.", Active: true, Shared: true, Tag: "socks5.cn"})),
		mkRecord("catofes.", mustKeyAssignment("10.0.2.0/24")+"#sh", RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.2.0/24", AssignedTo: "sh.catofes.", Active: true, Shared: true, Tag: "socks5.cn"})),
	)
	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if !hasCode(ars.Errors, "ipam_assignment_tag_conflict") || len(ars.AllAssignments) != 0 {
		t.Fatalf("assignments=%+v errors=%+v", ars.AllAssignments, ars.Errors)
	}
}

func TestAnycastAssignmentOnlyOneSharedStillRejected(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addZone(ns, "sh.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	// One shared and one non-shared assignment from the same owner should still
	// be rejected as an assignment overlap.
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/24")+"#pek", RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/24", AssignedTo: "pek.catofes.", Active: true, Shared: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/24"), RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/24", AssignedTo: "sh.catofes.", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if !hasCode(ars.Errors, "ipam_assignment_overlap") {
		t.Fatalf("expected ipam_assignment_overlap when only one side is shared, got %+v", ars.Errors)
	}
}

func TestAnycastRouteAnnouncementOverlapValid(t *testing.T) {
	ns := zone.NewNetworkState()
	addZone(ns, zone.RootZone, "")
	addZone(ns, "catofes.", zone.RootZone)
	addZone(ns, "pek.catofes.", "catofes.")
	addZone(ns, "sh.catofes.", "catofes.")
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addIPAMPoolRecord(ns, zone.RootZone, "10.0.0.0/16", "catofes.")
	// The owner publishes shared assignments and both assigned zones announce.
	addRecords(ns, "catofes.",
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/24")+"#pek", RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/24", AssignedTo: "pek.catofes.", Active: true, Shared: true})),
		mkRecord("catofes.", mustKeyAssignment("10.0.0.0/24")+"#sh", RecordTypeIPAMAssignment,
			mustJSON(IPAMAssignmentRecord{Version: 1, Prefix: "10.0.0.0/24", AssignedTo: "sh.catofes.", Active: true, Shared: true})),
	)
	addRecords(ns, "pek.catofes.",
		mkRecord("pek.catofes.", mustKeyRoute("10.0.0.0/24"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.0.0/24", Active: true})),
	)
	addRecords(ns, "sh.catofes.",
		mkRecord("sh.catofes.", mustKeyRoute("10.0.0.0/24"), RecordTypeRouteAnnouncement,
			mustJSON(RouteAnnouncementRecord{Version: 1, Prefix: "10.0.0.0/24", Active: true})),
	)

	ars, err := BuildAuthorizedRouteSet(ns, time.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) != 0 {
		t.Fatalf("expected no errors for anycast route announcements: %+v", ars.Errors)
	}
	// Both zones should have their announcements authorized.
	if ars.Announced["pek.catofes."] == nil || ars.Announced["pek.catofes."][netip.MustParsePrefix("10.0.0.0/24")] == nil {
		t.Fatalf("expected pek.catofes. announcement to be authorized")
	}
	if ars.Announced["sh.catofes."] == nil || ars.Announced["sh.catofes."][netip.MustParsePrefix("10.0.0.0/24")] == nil {
		t.Fatalf("expected sh.catofes. announcement to be authorized")
	}
}

func TestLocalAssignedPrefixesUsesAllAssignments(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	ars := &AuthorizedRouteSet{
		Assignments: map[netip.Prefix]*AssignmentEntry{
			prefix: {Prefix: prefix, Source: "catofes.", AssignedTo: "node-b.catofes."},
		},
		AllAssignments: []*AssignmentEntry{
			{Prefix: prefix, Source: "catofes.", AssignedTo: "node-b.catofes."},
			{Prefix: prefix, Source: "catofes.", AssignedTo: "node-a.catofes."},
		},
	}

	got := LocalAssignedPrefixes(ars, "node-a.catofes.", true)
	if len(got) != 1 || got[0] != prefix {
		t.Fatalf("LocalAssignedPrefixes = %+v, want [%s]", got, prefix)
	}
}
