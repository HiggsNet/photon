package ike

import (
	"bytes"
	"crypto/ecdh"
	"encoding/hex"
	"testing"
)

func cryptoHex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

func TestPRFSHA256RFC4231(t *testing.T) {
	// RFC 4231 section 4.2, independently published HMAC-SHA-256 vector.
	want := cryptoHex("b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7")
	if got := PRFSHA256(bytes.Repeat([]byte{0x0b}, 20), []byte("Hi There")); !bytes.Equal(got, want) {
		t.Fatalf("HMAC = %x", got)
	}
}

func TestP256WireKnownPoint(t *testing.T) {
	// The P-256 generator multiplied by two, independently checked with
	// OpenSSL through Node crypto.createECDH('prime256v1').setPrivateKey(2).
	point := cryptoHex("7cf27b188d034f7e8a52380304b51ac3c08969e277f21b35a60b48fc4766997807775510db8ed040293d9ac69f7430dbba7dade63ce982299e04b79d227873d1")
	scalar := make([]byte, 32)
	scalar[31] = 2
	key, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(P256PublicKey(key), point) {
		t.Fatal("group 19 wire encoding mismatch")
	}
	scalar[31] = 1
	one, err := ecdh.P256().NewPrivateKey(scalar)
	if err != nil {
		t.Fatal(err)
	}
	shared, err := P256SharedSecret(one, point)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(shared, point[:32]) {
		t.Fatalf("shared = %x", shared)
	}
	for _, invalid := range [][]byte{nil, point[:63], append([]byte{4}, point...), make([]byte, 64)} {
		if _, err := P256SharedSecret(one, invalid); err == nil {
			t.Fatal("accepted invalid point")
		}
	}
	if _, err := GenerateP256Key(bytes.NewReader(nil)); err == nil {
		t.Fatal("accepted exhausted randomness")
	}
}

func TestInitialIKEKeyMaterialKnownAnswer(t *testing.T) {
	// Independent fixture generated using Node/OpenSSL HMAC, following RFC
	// 7296: HMAC(Ni|Nr, DH), then Tn=HMAC(SKEYSEED,Tprev|Ni|Nr|SPIi|SPIr|n).
	want := cryptoHex("df4ad28668da8188ce5defec720ccf0c251f31cdf3a882fd5f855743dc144686c9ae3d42239d6c8bbf6a6ef5a1caf7cec80ea790d4d352afa83b76ce6f5c3c6c00689060bbd7e4453dc5195c4a1f27d7ac0c4e52418349c6934c39421ea57ca39d64b919ac44bb5b1ebdedbf7e79b38d87ef01ed4d08143494d703625c83cebcade673827ec93a643559b414b4091b801552e64a534781e0a73af40d90e9386412738b2b053adc5a7bf900db34d6f5f82b2efaecd20636b72d5a40971e1f420b")
	shared, ni, nr := bytes.Repeat([]byte{0x33}, 32), bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32)
	keys, err := DeriveIKEKeys(shared, ni, nr, 0x0102030405060708, 0x1112131415161718)
	if err != nil {
		t.Fatal(err)
	}
	var got []byte
	for i, k := range [][]byte{keys.SKD, keys.SKAI, keys.SKAR, keys.SKEI, keys.SKER, keys.SKPI, keys.SKPR} {
		length := 32
		if i == 3 || i == 4 {
			length = 16
		}
		if len(k) != length {
			t.Fatalf("key %d length %d", i, len(k))
		}
		got = append(got, k...)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("keymat = %x", got)
	}
	if _, err := DeriveIKEKeys(shared, ni[:15], nr, 1, 2); err == nil {
		t.Fatal("accepted short nonce")
	}
	if _, err := DeriveIKEKeys(shared, ni, nr, 0, 2); err == nil {
		t.Fatal("accepted zero SPI")
	}
	for _, n := range []int{-1, 8161} {
		if _, err := PRFPlusSHA256(ni, nr, n); err == nil {
			t.Fatal("accepted invalid expansion")
		}
	}
	if b, err := PRFPlusSHA256(ni, nr, 8160); err != nil || len(b) != 8160 {
		t.Fatal("maximum expansion rejected")
	}
}
