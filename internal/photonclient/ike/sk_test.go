package ike

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"strings"
	"testing"
)

func TestSKKnownAnswer(t *testing.T) {
	// AES block one is NIST SP 800-38A F.2.1. The complete IKE packet fixture
	// was independently generated with Node/OpenSSL CBC (autoPadding=false)
	// and HMAC SHA256, truncated to 16 bytes.
	want := cryptoHex("010203040506070811121314151617182e202308000000010000006029000044000102030405060708090a0b0c0d0e0f7649abac8119b246cee98e9b12e9197daf9f3d3ebcea9722032883d3784e9a37f29d2658614d3cfb2ddb5a3214a76a71")
	key := cryptoHex("2b7e151628aed2a6abf7158809cf4f3c")
	macKey := bytes.Repeat([]byte{0x0b}, 32)
	plain := cryptoHex("6bc1bee22e409f96e93d7e117393172a")
	h := Header{InitiatorSPI: 0x0102030405060708, ResponderSPI: 0x1112131415161718, ExchangeType: 35, Flags: FlagInitiator, MessageID: 1}
	got, err := SealSK(h, PayloadNotify, plain, key, macKey, bytes.NewReader(want[32:48]))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("SK packet = %x", got)
	}
	next, decoded, err := OpenSK(want, key, macKey)
	if err != nil || next != PayloadNotify || !bytes.Equal(decoded, plain) {
		t.Fatalf("open = %x, %v", decoded, err)
	}
	for _, index := range []int{0, 8, 18, 19, 20, 28, 29, 32, 48, len(want) - 1} {
		bad := append([]byte(nil), want...)
		bad[index] ^= 1
		if _, _, err := OpenSK(bad, key, macKey); err == nil || !strings.Contains(err.Error(), "integrity") {
			t.Fatalf("tamper %d did not fail authentication: %v", index, err)
		}
	}
	for n := 0; n < len(want); n++ {
		if _, _, err := OpenSK(want[:n], key, macKey); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	if _, err := SealSK(h, PayloadNotify, plain, key, macKey, bytes.NewReader(nil)); err == nil {
		t.Fatal("ignored IV randomness failure")
	}
	if _, err := SealSK(h, PayloadNotify, make([]byte, MaxMessageSize), key, macKey, bytes.NewReader(want)); err == nil {
		t.Fatal("accepted oversized packet")
	}
}

func TestSKPaddingAuthenticatedBeforeInspection(t *testing.T) {
	key, macKey := make([]byte, 16), make([]byte, 32)
	// Construct a peer packet manually: arbitrary nonzero padding is legal;
	// padding need not be PKCS7 and may span more than one CBC block.
	for _, padLength := range []byte{30, 31, 32, 255} {
		h := Header{InitiatorSPI: 1, ResponderSPI: 2, ExchangeType: 35, Flags: FlagResponse, MessageID: 1}
		packet, _ := h.Marshal(PayloadSK, 96)
		packet = append(packet, make([]byte, 68)...)
		packet[28] = PayloadNotify
		binary.BigEndian.PutUint16(packet[30:], 68)
		clear := bytes.Repeat([]byte{0xa7}, 32)
		clear[31] = padLength
		if padLength == 31 {
			packet[28] = 0
		}
		block, _ := aes.NewCipher(key)
		cipher.NewCBCEncrypter(block, packet[32:48]).CryptBlocks(packet[48:80], clear)
		copy(packet[80:], PRFSHA256(macKey, packet[:80])[:16])
		_, plain, err := OpenSK(packet, key, macKey)
		if padLength < 32 {
			if err != nil || len(plain) != 31-int(padLength) {
				t.Fatalf("legal padding rejected: %v", err)
			}
		} else if err == nil {
			t.Fatal("invalid padding accepted")
		}
		packet[95] ^= 1
		if _, _, err := OpenSK(packet, key, macKey); err == nil || !strings.Contains(err.Error(), "integrity") {
			t.Fatalf("padding checked before integrity: %v", err)
		}
	}
}

func FuzzOpenSK(f *testing.F) {
	key, macKey := make([]byte, 16), make([]byte, 32)
	valid, err := SealSK(Header{InitiatorSPI: 1, ResponderSPI: 2, ExchangeType: 35}, PayloadNotify, []byte{0, 0, 0, 4}, key, macKey, bytes.NewReader(make([]byte, 16)))
	if err != nil {
		f.Fatal(err)
	}
	f.Add(valid)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, packet []byte) {
		before := append([]byte(nil), packet...)
		_, _, _ = OpenSK(packet, key, macKey)
		if !bytes.Equal(packet, before) {
			t.Fatal("OpenSK mutated caller packet")
		}
	})
}
