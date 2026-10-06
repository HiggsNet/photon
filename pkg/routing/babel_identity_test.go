package routing

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestBabelIdentityLeaseAndFullIDs(t *testing.T) {
	now := time.Unix(100000, 0)
	for _, tc := range []struct {
		name  string
		value BabelIdentityRecord
		valid bool
	}{
		{"full", BabelIdentityRecord{1, []string{"1234567890abcdef"}, now.Add(time.Hour).Unix()}, true},
		{"withdraw", BabelIdentityRecord{1, nil, now.Add(time.Hour).Unix()}, true},
		{"low32", BabelIdentityRecord{1, []string{"90abcdef"}, now.Add(time.Hour).Unix()}, false},
		{"upper", BabelIdentityRecord{1, []string{"1234567890ABCDEF"}, now.Add(time.Hour).Unix()}, false},
		{"zero", BabelIdentityRecord{1, []string{"0000000000000000"}, now.Add(time.Hour).Unix()}, false},
		{"duplicate", BabelIdentityRecord{1, []string{"1234567890abcdef", "1234567890abcdef"}, now.Add(time.Hour).Unix()}, false},
		{"expired", BabelIdentityRecord{1, []string{"1234567890abcdef"}, now.Unix()}, false},
		{"unbounded", BabelIdentityRecord{1, []string{"1234567890abcdef"}, now.Add(25 * time.Hour).Unix()}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			value, _ := json.Marshal(tc.value)
			record := &zone.Record{Zone: "leaf.test.", Key: RecordKeyBabelIdentity, Type: RecordTypeBabelIdentity, Timestamp: now.Unix(), Value: value}
			if _, err := ParseBabelIdentityRecord(record, now); (err == nil) != tc.valid {
				t.Fatal("unexpected parser result", err)
			}
		})
	}
}

func TestStableBabelIDDomainSeparation(t *testing.T) {
	root, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	first, err := StableBabelRouterID("leaf.test.", root, "main")
	if err != nil {
		t.Fatal(err)
	}
	same, err := StableBabelRouterID("leaf.test.", root, "main")
	if err != nil || first != same || first == [8]byte{} {
		t.Fatal("unstable identity")
	}
	other, _ := StableBabelRouterID("other.test.", root, "main")
	overlay, _ := StableBabelRouterID("leaf.test.", root, "other")
	if first == other || first == overlay {
		t.Fatal("identity scope collapsed")
	}
	if _, err := StableBabelRouterID("leaf.test.", nil, "main"); err == nil {
		t.Fatal("missing trust pin")
	}
}
