package crypto

import (
	"crypto/ed25519"
	"encoding/hex"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func canonicalPayloadFixture() (*zone.Record, *zone.Delegation, *zone.DelegationRevocation) {
	var seed [ed25519.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	key := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	seed[0] = 99
	other := ed25519.NewKeyFromSeed(seed[:]).Public().(ed25519.PublicKey)
	expires := time.Unix(12345, 987654321)
	authority := zone.ZoneAuthority{
		Zone: "child.", Epoch: 0x0102030405060708, Threshold: 1,
		Keys: []zone.AuthorizedKey{
			{Key: key, NotBefore: -3, NotAfter: 12345, Capabilities: []zone.Capability{
				{KeyPrefix: "data/", Permissions: []zone.Permission{zone.PermWrite, zone.PermAllocateIP}},
				{KeyPrefix: "委托/", Permissions: []zone.Permission{zone.PermDelegate}},
			}},
			{Key: other, Capabilities: []zone.Capability{{}}},
		},
	}
	record := &zone.Record{
		Zone: authority.Zone, Key: "data/测试", Type: "node.identity", Value: []byte("original\x00payload"),
		Version: 0x0102030405060708, Timestamp: -123, SignedBy: key,
	}
	record.ValueHash = Hash(record.Value)
	delegation := &zone.Delegation{
		ZoneName: authority.Zone, Authority: authority, AuthorityEpoch: authority.Epoch,
		AuthorityHash: AuthorityHash(&authority), ExpiresAt: &expires, SignedBy: key,
	}
	revocation := &zone.DelegationRevocation{
		ParentZone: zone.RootZone, ChildZone: authority.Zone, RevokedAuthorityEpoch: authority.Epoch,
		RevokedAuthorityHash: delegation.AuthorityHash, Reason: "旧密钥\x00撤销", RevokedAt: -42,
		TTLSeconds: 86400, GraceSeconds: 600, SignedBy: key,
	}
	return record, delegation, revocation
}

// The wire fixtures were captured before the allocation change. They cover
// length-prefixed UTF-8 and NUL bytes, empty fields, signed negative integers,
// normalized delegation scope, and ordered authority keys/capabilities.
func TestCanonicalPayloadGolden(t *testing.T) {
	r, d, revoke := canonicalPayloadFixture()
	fixtures := []struct {
		name    string
		payload []byte
		golden  string
	}{
		{"record", recordPayload(r), "000000000000001070686f746f6e2e7265636f72642e763100000000000000066368696c642e000000000000000b646174612fe6b58be8af95000000000000000d6e6f64652e6964656e746974790000000000000020ca82c9093732b9e229ae74ecc75250e816fff14f0474240bb8b218137d6f2ac001020304050607080000000000000000ffffffffffffff8500000000000000209d24e2eeaf27c2a088a564a32fc03a882dcd9804dbc0d03a119491e54ba0c933"},
		{"delegation", delegationPayload(d, zone.RootZone), "000000000000001470686f746f6e2e64656c65676174696f6e2e763100000000000000012e00000000000000066368696c642e000000000000000c6469726563742d6368696c64010203040506070800000000000000205c74a23bc035054b3967c2c621e886391465ef50eca56c264c09312c57548e7c000000000000303900000000000000209d24e2eeaf27c2a088a564a32fc03a882dcd9804dbc0d03a119491e54ba0c933"},
		{"revocation", revocationPayload(revoke, zone.RootZone), "000000000000001f70686f746f6e2e64656c65676174696f6e2d7265766f636174696f6e2e763100000000000000012e00000000000000012e00000000000000066368696c642e010203040506070800000000000000205c74a23bc035054b3967c2c621e886391465ef50eca56c264c09312c57548e7c0000000000000010e697a7e5af86e992a500e692a4e99480ffffffffffffffd60000000000015180000000000000025800000000000000209d24e2eeaf27c2a088a564a32fc03a882dcd9804dbc0d03a119491e54ba0c933"},
		{"authority", authorityPayload(&d.Authority), "000000000000001370686f746f6e2e617574686f726974792e763100000000000000066368696c642e010203040506070800000000000000010000000000000002000000000000002003a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8fffffffffffffffd000000000000303900000000000000020000000000000005646174612f000000000000000200000000000000057772697465000000000000000b616c6c6f636174652d69700000000000000007e5a794e689982f0000000000000001000000000000000864656c6567617465000000000000002002ff05298a4af5071f2f6bd2edfd9e6e76e386cad559eecdf413e5f5a6d6736e00000000000000000000000000000000000000000000000100000000000000000000000000000000"},
	}
	for _, tc := range fixtures {
		t.Run(tc.name, func(t *testing.T) {
			if got := hex.EncodeToString(tc.payload); got != tc.golden {
				t.Fatalf("canonical payload changed: got %s, want %s", got, tc.golden)
			}
		})
	}
	if authorityPayload(nil) != nil {
		t.Fatal("nil authority payload changed")
	}

	// Verify signatures over the previous encoder's literal wire bytes, so
	// signing and verification cannot both hide the same encoding regression.
	var seed [ed25519.SeedSize]byte
	for i := range seed {
		seed[i] = byte(i)
	}
	private := ed25519.NewKeyFromSeed(seed[:])
	for i, signature := range []*[]byte{&r.Signature, &d.Signature, &revoke.Signature} {
		wire, err := hex.DecodeString(fixtures[i].golden)
		if err != nil {
			t.Fatal(err)
		}
		*signature = ed25519.Sign(private, wire)
	}
	parent := ConfiguredRootAuthority(r.SignedBy)
	for _, verifier := range []*Verifier{nil, new(Verifier)} {
		now := time.Unix(100, 0)
		if err := verifier.VerifyRecord(r, &d.Authority, now); err != nil {
			t.Fatal(err)
		}
		if err := verifier.VerifyDelegation(d, parent, zone.RootZone, now); err != nil {
			t.Fatal(err)
		}
		if err := verifier.VerifyDelegationRevocation(revoke, parent, zone.RootZone, now); err != nil {
			t.Fatal(err)
		}
	}
}

var canonicalPayloadBenchmarkResult []byte

func BenchmarkCanonicalPayload(b *testing.B) {
	r, d, revoke := canonicalPayloadFixture()
	for _, tc := range []struct {
		name    string
		payload func() []byte
	}{
		{"Record", func() []byte { return recordPayload(r) }},
		{"Delegation", func() []byte { return delegationPayload(d, zone.RootZone) }},
		{"Revocation", func() []byte { return revocationPayload(revoke, zone.RootZone) }},
		{"Authority", func() []byte { return authorityPayload(&d.Authority) }},
	} {
		b.Run(tc.name, func(b *testing.B) {
			b.ReportAllocs()
			for b.Loop() {
				canonicalPayloadBenchmarkResult = tc.payload()
			}
		})
	}
}
