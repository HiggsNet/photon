package ipsec

import (
	"bytes"
	"encoding/json"
	"slices"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestOverlayPolicyPublicationStableUntilConfigurationChanges(t *testing.T) {
	now := time.Unix(5000, 0)
	groups := []LinkGroupSpec{{ID: "main"}}
	families := []string{FamilyIPv4}
	existing := map[string]*zone.Record{}
	var previous []byte
	var stamp int64
	for i, step := range []struct {
		connect, deny []string
		changed       bool
	}{
		{changed: true}, // legacy wire representation remains unchanged
		{},
		{connect: []string{"strongswan://*.catofes."}, changed: true},
		{connect: []string{"strongswan://*.catofes."}},
		{connect: []string{"strongswan://*.catofes."}, deny: []string{"strongswan://blocked.catofes."}, changed: true},
		{connect: []string{"strongswan://*.catofes."}, deny: []string{"strongswan://blocked.catofes."}},
		{changed: true}, // removing policy is also a real update
		{},
	} {
		groups[0].ConnectRules, groups[0].DenyRules = step.connect, step.deny
		at := now.Add(time.Duration(i) * time.Minute)
		intent := BuildOverlayIntentRecords(groups, families, existing, at)[0]
		value, err := json.Marshal(intent)
		if err != nil {
			t.Fatal(err)
		}
		if step.changed {
			if bytes.Equal(value, previous) || intent.UpdatedAt != at.Unix() {
				t.Fatalf("step %d: missing update", i)
			}
		} else if !bytes.Equal(value, previous) || intent.UpdatedAt != stamp {
			t.Fatalf("step %d: unchanged policy caused republication", i)
		}
		if len(step.connect) == 0 && len(step.deny) == 0 && (bytes.Contains(value, []byte(`"connect"`)) || bytes.Contains(value, []byte(`"deny"`))) {
			t.Fatal("empty policy changed legacy wire representation")
		}
		key := OverlayIntentRecordKey(intent.OverlayID)
		existing[key] = &zone.Record{Key: key, Type: RecordTypeOverlayIntent, Value: value}
		previous, stamp = value, intent.UpdatedAt
	}
}

func TestProfilePublicationFamiliesAndConservativeNAT(t *testing.T) {
	addresses := AddressRecord{Addresses: []AddressAdvertisement{
		{Address: "2001:db8::1", Reachability: ReachabilityPublic},
		{Host: "vpn.example", Families: []string{FamilyIPv4, FamilyIPv6, "invalid"}},
		{Address: "192.0.2.1"},
	}}
	profile := BuildProfileRecord("node.example.", "fingerprint", "", []LinkGroupSpec{{ID: "a"}, {ID: "b", DefaultPathMode: PathModeExhaustive}, {ID: "c"}}, addresses)
	if !slices.Equal(profile.AddressFamilies, []string{FamilyIPv6, FamilyIPv4}) || !slices.Equal(profile.PathModes, []string{PathModeFamilyRedundant, PathModeExhaustive}) {
		t.Fatalf("families or path modes: %+v", profile)
	}
	if profile.NAT.Hint != NATHintPublic || profile.NAT.InboundReachable != NATReachableUnknown {
		t.Fatalf("public address must not prove inbound reachability: %+v", profile.NAT)
	}
	fallback := BuildProfileRecord("node.example.", "", RoleOut, nil, AddressRecord{})
	if !slices.Equal(fallback.AddressFamilies, []string{FamilyIPv4, FamilyIPv6}) || !slices.Equal(fallback.PathModes, []string{PathModeFamilyRedundant}) || fallback.Role != RoleOut || fallback.NAT.Hint != NATHintUnknown {
		t.Fatalf("fallback profile: %+v", fallback)
	}
	mapped := AddressRecord{Addresses: []AddressAdvertisement{{Address: "::ffff:192.0.2.1"}}}
	if !slices.Equal(mapped.PublicationFamilies(), []string{FamilyIPv6}) {
		t.Fatal("changed IPv4-mapped IPv6 declaration semantics")
	}
}

func TestOverlayPublicationFamilyChangesAndInvalidRecords(t *testing.T) {
	start := time.Unix(5000, 0)
	groups := []LinkGroupSpec{{ID: "main"}, {ID: "all", DefaultPathMode: PathModeExhaustive}, {ID: "invalid", Provider: "invalid"}}
	families := []string{FamilyIPv4, FamilyIPv6}
	first := BuildOverlayIntentRecords(groups, families, nil, start)
	if len(first) != 2 || !slices.Equal(first[0].PathKeys, []string{"family:ipv4", "family:ipv6"}) || !slices.Equal(first[1].PathKeys, []string{DefaultPathKey}) {
		t.Fatalf("intents: %+v", first)
	}
	existing := map[string]*zone.Record{}
	for _, intent := range first {
		value, err := json.Marshal(intent)
		if err != nil {
			t.Fatal(err)
		}
		key := OverlayIntentRecordKey(intent.OverlayID)
		existing[key] = &zone.Record{Key: key, Type: RecordTypeOverlayIntent, Value: value}
	}
	before, _ := json.Marshal(existing)
	now := start.Add(time.Hour)
	changed := BuildOverlayIntentRecords(groups, []string{FamilyIPv4}, existing, now)
	if changed[0].UpdatedAt != now.Unix() || changed[1].UpdatedAt != start.Unix() {
		t.Fatalf("change timestamps: %+v", changed)
	}
	after, _ := json.Marshal(existing)
	if string(before) != string(after) || groups[0].Provider != "" {
		t.Fatal("mutated input")
	}
	existing[OverlayIntentRecordKey("main")].Value = []byte("{")
	repaired := BuildOverlayIntentRecords(groups, families, existing, now)
	if repaired[0].UpdatedAt != now.Unix() {
		t.Fatal("malformed old record suppressed publication")
	}
	if got := BuildOverlayIntentRecords(groups[:1], nil, nil, now); len(got) != 0 {
		t.Fatal("family-redundant overlay without families was published")
	}
}
