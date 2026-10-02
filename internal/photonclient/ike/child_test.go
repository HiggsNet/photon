package ike

import (
	"bytes"
	"encoding/hex"
	"net/netip"
	"reflect"
	"testing"
)

func TestChildProposal(t *testing.T) {
	b, err := EncodeChildProposal(0x12345678)
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("0000002001030402123456780300000c01000014800e00800000000805000000")
	if !bytes.Equal(b, want) {
		t.Fatalf("proposal: %x", b)
	}
	if spi, err := ValidateChildSelection(b); err != nil || spi != 0x12345678 {
		t.Fatalf("selection: %x %v", spi, err)
	}
	swapped := append([]byte(nil), b[:12]...)
	swapped = append(swapped, b[24:]...)
	swapped[12] = 3
	swapped = append(swapped, b[12:24]...)
	swapped[20] = 0
	if _, err := ValidateChildSelection(swapped); err != nil {
		t.Fatal(err)
	}
	for _, offset := range []int{0, 3, 4, 5, 6, 7, 12, 15, 16, 19, 20, 21, 23, 24, 27, 28, 31} {
		bad := append([]byte(nil), b...)
		bad[offset] ^= 1
		if _, err := ValidateChildSelection(bad); err == nil {
			t.Errorf("accepted mutation at %d", offset)
		}
	}
	for n := 0; n < len(b); n++ {
		if _, err := ValidateChildSelection(b[:n]); err == nil {
			t.Errorf("accepted truncation %d", n)
		}
	}
	if _, err := ValidateChildSelection(append(b, 0)); err == nil {
		t.Fatal("accepted trailing data")
	}
	for _, spi := range []uint32{0, 1, 255} {
		if _, err := EncodeChildProposal(spi); err == nil {
			t.Fatalf("reserved SPI %d", spi)
		}
		bad := append([]byte(nil), b...)
		copy(bad[8:12], []byte{0, 0, 0, byte(spi)})
		if _, err := ValidateChildSelection(bad); err == nil {
			t.Fatal("accepted reserved SPI")
		}
	}
}

func testTS(start, end string, protocol uint8, low, high uint16) TrafficSelector {
	return TrafficSelector{StartAddr: netip.MustParseAddr(start), EndAddr: netip.MustParseAddr(end), Protocol: protocol, StartPort: low, EndPort: high}
}

func TestTrafficSelectorWire(t *testing.T) {
	v4 := testTS("192.0.2.1", "192.0.2.255", 6, 443, 443)
	b, err := EncodeTrafficSelectors([]TrafficSelector{v4})
	if err != nil {
		t.Fatal(err)
	}
	want, _ := hex.DecodeString("010000000706001001bb01bbc0000201c00002ff")
	if !bytes.Equal(b, want) {
		t.Fatalf("wire: %x", b)
	}
	v6 := testTS("2001:db8::", "2001:db8::ffff", 0, 0, 65535)
	for _, selectors := range [][]TrafficSelector{{v4}, {v6}, {v4, v6}} {
		wire, err := EncodeTrafficSelectors(selectors)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeTrafficSelectors(wire)
		if err != nil || !reflect.DeepEqual(selectors, decoded) {
			t.Fatalf("roundtrip: %+v %v", decoded, err)
		}
		for n := 0; n < len(wire); n++ {
			if _, err := DecodeTrafficSelectors(wire[:n]); err == nil {
				t.Fatalf("accepted truncation %d", n)
			}
		}
		if _, err := DecodeTrafficSelectors(append(wire, 0)); err == nil {
			t.Fatal("accepted trailing bytes")
		}
	}
	for _, offset := range []int{0, 4, 7} {
		bad := append([]byte(nil), b...)
		bad[offset]++
		if _, err := DecodeTrafficSelectors(bad); err == nil {
			t.Fatalf("accepted mutation at %d", offset)
		}
	}
	// Reserved bits are ignored on reception as required by IKEv2.
	b[1] = 255
	if _, err := DecodeTrafficSelectors(b); err != nil {
		t.Fatal(err)
	}
}

func TestTrafficSelectorNarrowing(t *testing.T) {
	offer := testTS("192.0.2.0", "192.0.2.255", 0, 0, 65535)
	valid := testTS("192.0.2.1", "192.0.2.20", 6, 443, 443)
	if err := ValidateTrafficSelectorNarrowing([]TrafficSelector{valid}, []TrafficSelector{offer}); err != nil {
		t.Fatal(err)
	}
	for name, bad := range map[string]TrafficSelector{
		"lower address":             testTS("192.0.1.255", "192.0.2.1", 6, 443, 443),
		"upper address":             testTS("192.0.2.1", "192.0.3.0", 6, 443, 443),
		"family":                    testTS("2001:db8::1", "2001:db8::2", 6, 443, 443),
		"reversed addresses":        testTS("192.0.2.20", "192.0.2.1", 6, 443, 443),
		"reversed ports":            testTS("192.0.2.1", "192.0.2.20", 6, 444, 443),
		"wildcard restricted ports": testTS("192.0.2.1", "192.0.2.20", 0, 443, 443),
		"unported restricted ports": testTS("192.0.2.1", "192.0.2.20", 50, 443, 443),
		"mapped":                    testTS("::ffff:192.0.2.1", "::ffff:192.0.2.20", 6, 443, 443),
		"zone":                      testTS("fe80::1%eth0", "fe80::2%eth0", 6, 443, 443),
		"missing":                   {},
	} {
		t.Run(name, func(t *testing.T) {
			if err := ValidateTrafficSelectorNarrowing([]TrafficSelector{bad}, []TrafficSelector{offer}); err == nil {
				t.Fatal("accepted selector")
			}
		})
	}
	for _, bad := range []TrafficSelector{offer, testTS("192.0.2.1", "192.0.2.20", 17, 443, 443), testTS("192.0.2.1", "192.0.2.20", 6, 442, 443), testTS("192.0.2.1", "192.0.2.20", 6, 443, 444)} {
		if err := ValidateTrafficSelectorNarrowing([]TrafficSelector{bad}, []TrafficSelector{valid}); err == nil {
			t.Fatal("accepted widening")
		}
	}
	gapOffer := []TrafficSelector{testTS("192.0.2.1", "192.0.2.4", 0, 0, 65535), testTS("192.0.2.6", "192.0.2.20", 0, 0, 65535)}
	if err := ValidateTrafficSelectorNarrowing([]TrafficSelector{valid}, gapOffer); err == nil {
		t.Fatal("merged across unauthorized gap")
	}
	if err := ValidateTrafficSelectorNarrowing(nil, []TrafficSelector{offer}); err == nil {
		t.Fatal("accepted empty response")
	}
	if err := ValidateTrafficSelectorNarrowing([]TrafficSelector{offer}, nil); err == nil {
		t.Fatal("accepted empty offer")
	}
	if _, err := EncodeTrafficSelectors(make([]TrafficSelector, 65)); err == nil {
		t.Fatal("accepted excessive count")
	}
}

func TestInitialChildKeysVector(t *testing.T) {
	// Independently calculated with Node crypto.createHmac SHA-256, explicitly
	// concatenating Ni|Nr|01 and then T1|Ni|Nr|02 (no Go PRF+ helper).
	want, _ := hex.DecodeString("6271cf5645c423a4be195e1cd0afacdc906182132e3694fb226a28b65fd19b905faea360a82dc4f4")
	skD, ni, nr := bytes.Repeat([]byte{0x11}, 32), bytes.Repeat([]byte{0x22}, 32), bytes.Repeat([]byte{0x33}, 32)
	keys, err := DeriveInitialChildKeys(skD, ni, nr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(keys.InitiatorToResponder, want[:20]) || !bytes.Equal(keys.ResponderToInitiator, want[20:]) {
		t.Fatalf("keys: %x %x", keys.InitiatorToResponder, keys.ResponderToInitiator)
	}
	if cap(keys.InitiatorToResponder) != 20 {
		t.Fatal("direction slices share append capacity")
	}
	for _, args := range [][3][]byte{{skD[:31], ni, nr}, {skD, ni[:15], nr}, {skD, ni, nr[:15]}, {skD, make([]byte, 257), nr}, {skD, ni, make([]byte, 257)}} {
		if _, err := DeriveInitialChildKeys(args[0], args[1], args[2]); err == nil {
			t.Fatal("accepted invalid key input")
		}
	}
}

func FuzzTrafficSelectors(f *testing.F) {
	b, _ := EncodeTrafficSelectors([]TrafficSelector{testTS("192.0.2.1", "192.0.2.20", 0, 0, 65535)})
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) {
		selectors, err := DecodeTrafficSelectors(b)
		if err != nil {
			return
		}
		encoded, err := EncodeTrafficSelectors(selectors)
		if err != nil {
			t.Fatal(err)
		}
		decoded, err := DecodeTrafficSelectors(encoded)
		if err != nil || !reflect.DeepEqual(selectors, decoded) {
			t.Fatal("unstable decoded selectors")
		}
	})
}
