package main

import (
	"testing"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestLookupRecordDetail(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)
	if err := putRecordDirect(rt, managed, "site/name", []byte(`{"name":"pek"}`), "policy.json"); err != nil {
		t.Fatalf("putRecordDirect: %v", err)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}

	record, err := lookupRecordDetailFromNetwork(common.State.Network, managed, "site/name", 0)
	if err != nil {
		t.Fatalf("lookupRecordDetail: %v", err)
	}
	if record.Zone != string(managed) || record.Key != "site/name" || record.Type != "policy.json" {
		t.Fatalf("record detail = %#v", record)
	}
	if record.Value != `{"name":"pek"}` || record.ValueJSON == nil || record.RecordHash == "" {
		t.Fatalf("record detail missing value fields: %#v", record)
	}
	if len(record.RecordHistory) != 0 {
		t.Fatalf("record_history should be omitted by default: %#v", record)
	}

	if err := putRecordDirect(rt, managed, "site/name", []byte(`{"name":"pek-2"}`), "policy.json"); err != nil {
		t.Fatalf("putRecordDirect second version: %v", err)
	}
	if err := putRecordDirect(rt, managed, "site/name", []byte(`{"name":"pek-3"}`), "policy.json"); err != nil {
		t.Fatalf("putRecordDirect third version: %v", err)
	}
	common, _, err = loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews after history writes: %v", err)
	}
	record, err = lookupRecordDetailFromNetwork(common.State.Network, managed, "site/name", 2)
	if err != nil {
		t.Fatalf("lookupRecordDetail with history: %v", err)
	}
	history := record.RecordHistory
	if len(history) != 2 {
		t.Fatalf("history len = %d, want 2", len(history))
	}
	if history[0].Version != 2 || history[1].Version != 1 {
		t.Fatalf("history versions = %#v, want latest history first", history)
	}

	if _, err := lookupRecordDetailFromNetwork(common.State.Network, managed, "missing", 0); err == nil {
		t.Fatal("lookupRecordDetail missing record error = nil")
	}
	if _, err := lookupRecordDetailFromNetwork(common.State.Network, zone.ZonePath("missing."), "site/name", 0); err == nil {
		t.Fatal("lookupRecordDetail missing zone error = nil")
	}
	if _, err := lookupRecordDetailFromNetwork(common.State.Network, managed, "site/name", -1); err == nil {
		t.Fatal("lookupRecordDetail negative history error = nil")
	}
}
