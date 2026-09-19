package ipsec

import (
	"testing"
	"time"
)

func TestPlanPortRecordDefaultsToStandardPorts(t *testing.T) {
	now := time.Unix(1717171717, 0)
	record, err := PlanPortRecord(PortPlanOptions{Now: now, Generation: 7})
	if err != nil {
		t.Fatalf("PlanPortRecord: %v", err)
	}
	if record.Mode != PortModeFixed || record.Range != nil {
		t.Fatalf("record mode = %+v", record)
	}
	if record.Current.Generation != 7 {
		t.Fatalf("generation = %d", record.Current.Generation)
	}
	if record.Current.IKE.Local != DefaultIKEPort || record.Current.IKE.Advertised != DefaultIKEPort {
		t.Fatalf("IKE binding = %+v", record.Current.IKE)
	}
	if record.Current.NATT.Local != DefaultNATTPort || record.Current.NATT.Advertised != DefaultNATTPort {
		t.Fatalf("NATT binding = %+v", record.Current.NATT)
	}
	if record.UpdatedAt != now.Unix() {
		t.Fatalf("UpdatedAt = %d, want %d", record.UpdatedAt, now.Unix())
	}
}

func TestPlanPortRecordRangeIsStableByGeneration(t *testing.T) {
	now := time.Unix(1717171717, 0)
	record, err := PlanPortRecord(PortPlanOptions{
		Mode:       PortModeRange,
		Range:      &PortRange{From: 30000, To: 30003},
		Generation: 5,
		Now:        now,
	})
	if err != nil {
		t.Fatalf("PlanPortRecord: %v", err)
	}
	if record.Range == nil || record.Range.From != 30000 || record.Range.To != 30003 {
		t.Fatalf("range = %+v", record.Range)
	}
	if record.Current.IKE.Local != DefaultIKEPort || record.Current.NATT.Local != DefaultNATTPort {
		t.Fatalf("local ports = %+v, want charon defaults", record.Current)
	}
	if record.Current.IKE.Advertised != 30000 || record.Current.NATT.Advertised != 30001 {
		t.Fatalf("advertised ports = %+v, want selected range ports", record.Current)
	}
	again, err := PlanPortRecord(PortPlanOptions{
		Mode:       PortModeRange,
		Range:      &PortRange{From: 30000, To: 30003},
		Generation: 5,
		Now:        now.Add(time.Minute),
	})
	if err != nil {
		t.Fatalf("PlanPortRecord(again): %v", err)
	}
	if record.Current.IKE.Advertised != again.Current.IKE.Advertised || record.Current.NATT.Advertised != again.Current.NATT.Advertised {
		t.Fatalf("range selection changed: %+v vs %+v", record.Current, again.Current)
	}
}

func TestSelectPortsFromRangeUsesDisjointPairsAcrossRotate(t *testing.T) {
	r := PortRange{From: 33500, To: 33599}
	ike2, natt2, err := SelectPortsFromRange(r, 2)
	if err != nil {
		t.Fatalf("SelectPortsFromRange(generation 2): %v", err)
	}
	ike3, natt3, err := SelectPortsFromRange(r, 3)
	if err != nil {
		t.Fatalf("SelectPortsFromRange(generation 3): %v", err)
	}
	if ike2 != 33502 || natt2 != 33503 {
		t.Fatalf("generation 2 ports = %d/%d, want 33502/33503", ike2, natt2)
	}
	if ike3 != 33504 || natt3 != 33505 {
		t.Fatalf("generation 3 ports = %d/%d, want 33504/33505", ike3, natt3)
	}
	if ike2 == ike3 || ike2 == natt3 || natt2 == ike3 || natt2 == natt3 {
		t.Fatalf("adjacent generations overlap: generation 2 = %d/%d, generation 3 = %d/%d", ike2, natt2, ike3, natt3)
	}
}

func TestSelectPortsFromRangeWrapKeepsAdjacentGenerationsDisjoint(t *testing.T) {
	r := PortRange{From: 30000, To: 30005}
	ike3, natt3, err := SelectPortsFromRange(r, 3)
	if err != nil {
		t.Fatalf("SelectPortsFromRange(generation 3): %v", err)
	}
	ike4, natt4, err := SelectPortsFromRange(r, 4)
	if err != nil {
		t.Fatalf("SelectPortsFromRange(generation 4): %v", err)
	}
	if ike3 != 30004 || natt3 != 30005 || ike4 != 30000 || natt4 != 30001 {
		t.Fatalf("wrapped ports = generation 3 %d/%d, generation 4 %d/%d", ike3, natt3, ike4, natt4)
	}
}

func TestPlanPortRecordCarriesPreviousCurrentWithGrace(t *testing.T) {
	now := time.Unix(1717171717, 0)
	previous, err := PlanPortRecord(PortPlanOptions{
		FixedIKE:   30412,
		FixedNATT:  30413,
		Generation: 41,
		Now:        now.Add(-time.Minute),
	})
	if err != nil {
		t.Fatalf("PlanPortRecord(previous): %v", err)
	}
	rotated, err := PlanPortRecord(PortPlanOptions{
		Mode:          PortModeRange,
		Range:         &PortRange{From: 31000, To: 31009},
		Generation:    42,
		Previous:      previous,
		PreviousGrace: 10 * time.Minute,
		Now:           now,
	})
	if err != nil {
		t.Fatalf("PlanPortRecord(rotated): %v", err)
	}
	if len(rotated.Previous) != 1 {
		t.Fatalf("previous len = %d, want 1", len(rotated.Previous))
	}
	if rotated.Previous[0].Generation != 41 || rotated.Previous[0].IKE.Advertised != 30412 {
		t.Fatalf("previous selection = %+v", rotated.Previous[0])
	}
	if rotated.Previous[0].ValidUntil != now.Add(10*time.Minute).Unix() {
		t.Fatalf("ValidUntil = %d", rotated.Previous[0].ValidUntil)
	}
}

func TestPlanPortRecordDropsExpiredPreviousSelections(t *testing.T) {
	now := time.Unix(1717171717, 0)
	previous := &PortRecord{
		Version: 1,
		Mode:    PortModeFixed,
		Current: &PortSelection{
			Generation: 42,
			IKE:        PortBinding{Advertised: 500},
			NATT:       PortBinding{Advertised: 4500},
		},
		Previous: []PortSelection{{
			Generation: 41,
			IKE:        PortBinding{Advertised: 30100},
			NATT:       PortBinding{Advertised: 30101},
			ValidUntil: now.Add(-time.Second).Unix(),
		}},
	}
	record, err := PlanPortRecord(PortPlanOptions{
		FixedIKE:      500,
		FixedNATT:     4500,
		Generation:    42,
		Previous:      previous,
		PreviousGrace: time.Minute,
		Now:           now,
	})
	if err != nil {
		t.Fatalf("PlanPortRecord: %v", err)
	}
	if len(record.Previous) != 0 {
		t.Fatalf("previous = %+v, want empty", record.Previous)
	}
}

func TestPlanPortRecordRejectsTinyRange(t *testing.T) {
	_, err := PlanPortRecord(PortPlanOptions{
		Mode:       PortModeRange,
		Range:      &PortRange{From: 30000, To: 30002},
		Generation: 1,
	})
	if err == nil {
		t.Fatalf("PlanPortRecord should reject a range without two complete port pairs")
	}
}

// Publication must preserve timestamps until rotation is due, so periodic
// reconciliation does not continually republish unchanged protocol records.
func TestPlanPortPublicationRotationBoundary(t *testing.T) {
	start := time.Unix(5000, 0)
	r := &PortRange{From: 30000, To: 30099}
	previous, err := PlanPortRecord(PortPlanOptions{Mode: PortModeRange, Range: r, Generation: 4, Now: start})
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name             string
		offset, interval time.Duration
		generation       uint64
	}{
		{"before", time.Hour - time.Nanosecond, time.Hour, 4},
		{"exact boundary", time.Hour, time.Hour, 4},
		{"after", time.Hour + time.Nanosecond, time.Hour, 5},
		{"disabled", 2 * time.Hour, 0, 4},
		{"long gap advances once", 24 * time.Hour, time.Hour, 5},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := start.Add(tc.offset)
			got, err := PlanPortPublication(PortModeRange, r, tc.interval, time.Hour, previous, now)
			if err != nil {
				t.Fatal(err)
			}
			if got.Current.Generation != tc.generation {
				t.Fatalf("generation = %d, want %d", got.Current.Generation, tc.generation)
			}
			if tc.generation == 4 {
				if got != previous || got.UpdatedAt != start.Unix() {
					t.Fatal("unchanged record was replaced")
				}
			} else {
				if got.UpdatedAt != now.Unix() || len(got.Previous) != 1 || got.Previous[0].Generation != 4 || got.Previous[0].ValidUntil != now.Add(time.Hour).Unix() {
					t.Fatalf("rotation lost timestamp or grace: %+v", got)
				}
				if got.Current.IKE.Advertised == previous.Current.IKE.Advertised {
					t.Fatal("rotation reused old port pair")
				}
			}
			if previous.Current.Generation != 4 || previous.UpdatedAt != start.Unix() || len(previous.Previous) != 0 {
				t.Fatal("mutated previous record")
			}
		})
	}
	withoutTimestamp := *previous
	withoutTimestamp.UpdatedAt = 0
	got, err := PlanPortPublication(PortModeRange, r, time.Hour, time.Hour, &withoutTimestamp, start)
	if err != nil || got.Current.Generation != 5 {
		t.Fatalf("missing timestamp: record=%+v err=%v", got, err)
	}
}

func TestPlanPortPublicationConfigurationChanges(t *testing.T) {
	now := time.Unix(5000, 0)
	r := &PortRange{From: 30000, To: 30099}
	first, err := PlanPortPublication(PortModeRange, r, time.Hour, time.Hour, nil, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Current.Generation != 1 || first.Current.IKE.Local != DefaultIKEPort || first.Current.NATT.Local != DefaultNATTPort {
		t.Fatalf("initial record: %+v", first)
	}
	changedRange := &PortRange{From: 31000, To: 31099}
	changed, err := PlanPortPublication(PortModeRange, changedRange, time.Hour, time.Hour, first, now.Add(time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if changed == first || changed.Current.Generation != 1 || changed.Current.IKE.Advertised != 31000 {
		t.Fatalf("range change ignored: %+v", changed)
	}
	fixed, err := PlanPortPublication("", changedRange, time.Hour, time.Hour, changed, now.Add(2*time.Minute))
	if err != nil {
		t.Fatal(err)
	}
	if fixed.Mode != PortModeFixed || fixed.Range != nil || fixed.Current.IKE.Advertised != DefaultIKEPort {
		t.Fatalf("fixed mode: %+v", fixed)
	}
	// Fixed mode ignores the configured range and automatic rotation interval.
	reused, err := PlanPortPublication(PortModeFixed, r, time.Hour, time.Hour, fixed, now.Add(24*time.Hour))
	if err != nil || reused != fixed {
		t.Fatalf("fixed record replaced: %+v %v", reused, err)
	}
	if _, err := PlanPortPublication(PortModeRange, nil, time.Hour, time.Hour, nil, now); err == nil {
		t.Fatal("missing range accepted")
	}
}
