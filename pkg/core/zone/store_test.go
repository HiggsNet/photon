package zone

import (
	"errors"
	"testing"
	"time"
)

func TestZonePathParentAndAncestors(t *testing.T) {
	zp := ZonePath("node1.pek.catofes.")

	if got, want := zp.Parent(), ZonePath("pek.catofes."); got != want {
		t.Fatalf("Parent() = %q, want %q", got, want)
	}

	got := zp.Ancestors()
	want := []ZonePath{"node1.pek.catofes.", "pek.catofes.", "catofes.", "."}
	if len(got) != len(want) {
		t.Fatalf("Ancestors() len = %d, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("Ancestors()[%d] = %q, want %q", i, got[i], want[i])
		}
	}
}

func TestZonePathParentBoundaryInputs(t *testing.T) {
	for _, tc := range []struct{ path, parent ZonePath }{
		{"", "."}, {".", "."}, {"node", "."}, {"node.", "."},
		{"node.site.", "site."}, {"node.site", "site."},
		{".site.", "site."}, {"node..site.", ".site."},
		{"..", "."}, {"...", ".."}, {"node..", "."},
	} {
		if got := tc.path.Parent(); got != tc.parent {
			t.Errorf("%q.Parent() = %q, want %q", tc.path, got, tc.parent)
		}
	}
}

func TestNetworkStateGetFallback(t *testing.T) {
	ns := NewNetworkState()
	ns.Zones[RootZone] = NewZoneState(RootZone, nil)
	ns.Zones["catofes."] = NewZoneState("catofes.", nil)
	ns.Zones["pek.catofes."] = NewZoneState("pek.catofes.", nil)

	rootRecord := &Record{Zone: RootZone, Key: "policy/allowed-transports", Value: []byte("wireguard")}
	siteRecord := &Record{Zone: "catofes.", Key: "policy/mtu", Value: []byte("1400")}

	if err := ns.Put(rootRecord); err != nil {
		t.Fatalf("Put(rootRecord): %v", err)
	}
	if err := ns.Put(siteRecord); err != nil {
		t.Fatalf("Put(siteRecord): %v", err)
	}

	got, err := ns.Get("pek.catofes./policy/mtu")
	if err != nil {
		t.Fatalf("Get(site fallback): %v", err)
	}
	if got != siteRecord {
		t.Fatalf("Get(site fallback) returned wrong record")
	}

	got, err = ns.Get("pek.catofes./policy/allowed-transports")
	if err != nil {
		t.Fatalf("Get(root fallback): %v", err)
	}
	if got != rootRecord {
		t.Fatalf("Get(root fallback) returned wrong record")
	}
}

func TestNetworkStatePutAcceptsSignedFastForward(t *testing.T) {
	ns := NewNetworkState()
	ns.ConfigureRecordValidation(
		func(record *Record, authority *ZoneAuthority, now time.Time) error { return nil },
		func(record *Record) []byte { return []byte{byte(record.Version)} },
	)
	ns.Zones["node1.catofes."] = NewZoneState("node1.catofes.", &ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
	})

	v2 := &Record{
		Zone:     "node1.catofes.",
		Key:      "identity",
		Version:  2,
		PrevHash: []byte{1},
	}
	if err := ns.PutAt(v2, time.Unix(123, 0)); err != nil {
		t.Fatalf("PutAt(v2): %v", err)
	}
	if got := ns.Zones["node1.catofes."].Records["identity"]; got != v2 {
		t.Fatalf("active record = %#v, want v2", got)
	}

	v100 := &Record{
		Zone:    "node1.catofes.",
		Key:     "identity",
		Version: 100,
	}
	if err := ns.PutAt(v100, time.Unix(123, 0)); err != nil {
		t.Fatalf("PutAt(v100): %v", err)
	}
	if got := ns.Zones["node1.catofes."].Records["identity"]; got != v100 {
		t.Fatalf("active record = %#v, want v100", got)
	}
	if got := len(ns.Zones["node1.catofes."].RecordHistory["identity"]); got != 1 {
		t.Fatalf("history length = %d, want 1", got)
	}
}

func TestNetworkStatePutRejectsDirectNextPrevHashConflict(t *testing.T) {
	ns := NewNetworkState()
	ns.ConfigureRecordValidation(
		func(record *Record, authority *ZoneAuthority, now time.Time) error { return nil },
		func(record *Record) []byte { return []byte{byte(record.Version)} },
	)
	ns.Zones["node1.catofes."] = NewZoneState("node1.catofes.", &ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
	})

	v1 := &Record{Zone: "node1.catofes.", Key: "identity", Version: 1}
	if err := ns.PutAt(v1, time.Unix(123, 0)); err != nil {
		t.Fatalf("PutAt(v1): %v", err)
	}
	v2Conflict := &Record{Zone: "node1.catofes.", Key: "identity", Version: 2, PrevHash: []byte{99}}
	if err := ns.PutAt(v2Conflict, time.Unix(123, 0)); !errors.Is(err, ErrRecordConflict) {
		t.Fatalf("PutAt(v2Conflict) = %v, want ErrRecordConflict", err)
	}
}

func TestNetworkStatePutRejectsSameVersionConflict(t *testing.T) {
	ns := NewNetworkState()
	ns.ConfigureRecordValidation(
		func(record *Record, authority *ZoneAuthority, now time.Time) error { return nil },
		func(record *Record) []byte { return record.Value },
	)
	ns.Zones["node1.catofes."] = NewZoneState("node1.catofes.", &ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
	})

	first := &Record{Zone: "node1.catofes.", Key: "identity", Value: []byte("node-a"), Version: 1}
	if err := ns.PutAt(first, time.Unix(123, 0)); err != nil {
		t.Fatalf("PutAt(first): %v", err)
	}
	conflict := &Record{Zone: "node1.catofes.", Key: "identity", Value: []byte("node-b"), Version: 1}
	if err := ns.PutAt(conflict, time.Unix(123, 0)); !errors.Is(err, ErrRecordConflict) {
		t.Fatalf("PutAt(conflict) = %v, want ErrRecordConflict", err)
	}
	if got := ns.Zones["node1.catofes."].Records["identity"]; got != first {
		t.Fatalf("active record changed to %#v, want first record", got)
	}
}

func TestNetworkStatePutBoundsRecordHistory(t *testing.T) {
	ns := NewNetworkState()
	ns.ConfigureRecordValidation(
		func(record *Record, authority *ZoneAuthority, now time.Time) error { return nil },
		func(record *Record) []byte { return []byte{byte(record.Version)} },
	)
	ns.Zones["node1.catofes."] = NewZoneState("node1.catofes.", &ZoneAuthority{
		Zone:      "node1.catofes.",
		Epoch:     1,
		Threshold: 1,
	})

	for version := uint64(1); version <= MaxRecordHistoryPerKey+2; version++ {
		record := &Record{Zone: "node1.catofes.", Key: "identity", Version: version}
		if err := ns.PutAt(record, time.Unix(123, 0)); err != nil {
			t.Fatalf("PutAt(v%d): %v", version, err)
		}
	}

	history := ns.Zones["node1.catofes."].RecordHistory["identity"]
	if got := len(history); got != MaxRecordHistoryPerKey {
		t.Fatalf("history length = %d, want %d", got, MaxRecordHistoryPerKey)
	}
	if got := history[0].Version; got != 2 {
		t.Fatalf("oldest retained version = %d, want 2", got)
	}
}

func TestNetworkStateRevocationCoversSubtreeAndSkipsGet(t *testing.T) {
	ns := NewNetworkState()
	ns.Zones[RootZone] = NewZoneState(RootZone, nil)
	ns.Zones["catofes."] = NewZoneState("catofes.", nil)
	ns.Zones["node1.catofes."] = NewZoneState("node1.catofes.", nil)
	ns.Zones[RootZone].Revocations["catofes."] = &DelegationRevocation{
		ChildZone:             "catofes.",
		ParentZone:            RootZone,
		RevokedAuthorityEpoch: 1,
		RevokedAuthorityHash:  []byte{1},
		RevokedAt:             100,
	}
	ns.Zones["node1.catofes."].Records["identity"] = &Record{
		Zone:    "node1.catofes.",
		Key:     "identity",
		Value:   []byte("node1"),
		Version: 1,
	}

	now := time.Unix(123, 0)
	if !ns.IsZoneRevoked("catofes.", now) {
		t.Fatalf("catofes. is not revoked")
	}
	if !ns.IsZoneRevoked("node1.catofes.", now) {
		t.Fatalf("node1.catofes. is not covered by parent revocation")
	}
	if _, err := ns.Get("node1.catofes./identity"); !errors.Is(err, ErrRecordNotFound) {
		t.Fatalf("Get revoked record = %v, want ErrRecordNotFound", err)
	}
	if err := ns.PutAt(&Record{Zone: "node1.catofes.", Key: "new", Version: 1}, now); !errors.Is(err, ErrZoneRevoked) {
		t.Fatalf("PutAt revoked subtree = %v, want ErrZoneRevoked", err)
	}
}

func TestNetworkStateRevocationAllowsHigherEpochRedelegation(t *testing.T) {
	ns := NewNetworkState()
	ns.Zones[RootZone] = NewZoneState(RootZone, nil)
	ns.Zones["catofes."] = NewZoneState("catofes.", &ZoneAuthority{Zone: "catofes.", Epoch: 2})
	ns.Zones[RootZone].Delegations["catofes."] = &Delegation{
		ZoneName:       "catofes.",
		AuthorityEpoch: 2,
		AuthorityHash:  []byte{2},
	}
	ns.Zones[RootZone].Revocations["catofes."] = &DelegationRevocation{
		ChildZone:             "catofes.",
		ParentZone:            RootZone,
		RevokedAuthorityEpoch: 1,
		RevokedAuthorityHash:  []byte{1},
		RevokedAt:             100,
	}

	if ns.IsZoneRevoked("catofes.", time.Unix(123, 0)) {
		t.Fatalf("higher epoch delegation should supersede older revocation")
	}
}
