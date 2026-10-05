package babel

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

var testID = [8]byte{1, 2, 3, 4, 5, 6, 7, 8}
var testPeer = netip.MustParseAddr("fe80::2")

func wire(tlvs ...[]byte) []byte {
	b := []byte{Magic, Version, 0, 0}
	for _, tlv := range tlvs {
		b = append(b, tlv...)
	}
	binary.BigEndian.PutUint16(b[2:4], uint16(len(b)-4))
	return b
}
func tlv(typ byte, b ...byte) []byte { return append([]byte{typ, byte(len(b))}, b...) }
func update(ae, flags, plen, omit byte, prefix ...byte) []byte {
	return tlv(TLVUpdate, append([]byte{ae, flags, plen, omit, 0, 100, 0, 7, 0, 96}, prefix...)...)
}
func decode(t *testing.T, b []byte) []Message {
	t.Helper()
	m, err := Decode(b, testPeer)
	if err != nil {
		t.Fatal(err)
	}
	return m
}
func TestControlGolden(t *testing.T) {
	b, err := Encode([]Message{{Type: TLVHello, Unicast: true, Seqno: 0x1234, Interval: 100}, {Type: TLVAck, Opaque: 0xabcd}})
	want := []byte{42, 2, 0, 12, 4, 6, 128, 0, 18, 52, 0, 100, 3, 2, 171, 205}
	if err != nil || !bytes.Equal(b, want) {
		t.Fatalf("%x %v", b, err)
	}
	b[6] |= 0x7f
	b[7] = 255
	m := decode(t, b)
	if !m[0].Unicast || m[0].Seqno != 0x1234 || m[0].Ignore {
		t.Fatal(m)
	}
	for _, typ := range []byte{TLVHello, TLVIHU, TLVAckRequest} {
		m := decode(t, wire(tlv(typ, 0, 0, 0, 0, 0, 0)))[0]
		if m.Ignore != (typ != TLVHello) {
			t.Fatal(m)
		}
	}
}
func TestUpdateRoundTripSourceAndAddressFamilies(t *testing.T) {
	for _, item := range []struct {
		prefix, source, hop string
		ae                  byte
	}{{"10.0.0.0/8", "192.0.2.0/24", "192.0.2.1", AEIPv4}, {"2001:db8::/32", "fd00::/8", "fe80::2", AEIPv6}, {"10.0.0.0/8", "192.0.2.0/24", "fe80::2", AEIPv4ViaIPv6}} {
		for _, typ := range []byte{TLVUpdate, TLVRouteRequest, TLVSeqnoRequest} {
			in := Message{Type: typ, Prefix: netip.MustParsePrefix(item.prefix), SourcePrefix: netip.MustParsePrefix(item.source), NextHop: netip.MustParseAddr(item.hop), RouterID: testID, Metric: 96, Interval: 100, Seqno: 7, HopCount: 16}
			b, err := Encode([]Message{in})
			if err != nil {
				t.Fatal(err)
			}
			out := decode(t, b)
			got := out[len(out)-1]
			if got.Ignore || got.Prefix != in.Prefix || got.SourcePrefix != in.SourcePrefix {
				t.Fatal(got)
			}
			if typ == TLVUpdate && (got.AE != item.ae || got.RouterID != in.RouterID || got.NextHop != in.NextHop) {
				t.Fatal(got)
			}
		}
	}
}
func TestCompressionAndMandatoryStateEffects(t *testing.T) {
	// Mandatory unknown sub-TLV suppresses this route, but P/R state still applies.
	first := update(AEIPv4ViaIPv6, 0xc1, 16, 0, 10, 1, 129, 0)
	second := update(AEIPv4ViaIPv6, 0, 24, 3)
	got := decode(t, wire(first, second))
	if !got[0].Ignore || got[1].Ignore || got[1].Prefix.String() != "10.1.0.0/24" || got[1].RouterID != [8]byte{0, 0, 0, 0, 10, 1, 0, 0} {
		t.Fatal(got)
	}
	if _, err := Decode(wire(second), testPeer); err == nil {
		t.Fatal("prefix state escaped packet")
	}
	otherAE := update(AEIPv4, 0, 24, 3)
	if _, err := Decode(wire(first, otherAE), testPeer); err == nil {
		t.Fatal("AE 1 reused AE 4 state")
	}
	router := tlv(TLVRouterID, append(append([]byte{0, 0}, testID[:]...), 129, 0)...)
	hop := tlv(TLVNextHop, 3, 0, 0, 0, 0, 0, 0, 0, 0, 9, 129, 0)
	got = decode(t, wire(router, hop, update(AEIPv4ViaIPv6, 0, 8, 0, 10)))
	if !got[0].Ignore || !got[1].Ignore || got[2].Ignore || got[2].RouterID != testID || got[2].NextHop.String() != "fe80::9" {
		t.Fatal(got)
	}
}
func TestSourceNeverDowngrades(t *testing.T) {
	for _, sub := range [][]byte{{128, 1, 0}, {128, 2, 24, 10}, {128, 2, 8, 10, 128, 2, 8, 11}, {129, 0}} {
		b := update(AEIPv4ViaIPv6, 0x40, 8, 0, 10)
		b = append(b, sub...)
		b[1] += byte(len(sub))
		got := decode(t, wire(b))
		if !got[0].Ignore {
			t.Fatalf("%x: %+v", sub, got)
		}
	}
}
func TestRetractionOriginAndTrailer(t *testing.T) {
	finite := update(AEIPv4ViaIPv6, 0, 8, 0, 10)
	if !decode(t, wire(finite))[0].Ignore {
		t.Fatal("accepted originless finite route")
	}
	finite[10], finite[11] = 255, 255
	if decode(t, wire(finite))[0].Ignore {
		t.Fatal("retraction requires origin")
	}
	b, err := Encode([]Message{{Type: TLVUpdate, Wildcard: true, Metric: MetricInfinity, Interval: 100}})
	if err != nil || !decode(t, b)[0].Wildcard {
		t.Fatal(err)
	}
	trailer := append(wire(tlv(TLVAck, 0, 1)), finite...)
	if len(decode(t, trailer)) != 1 {
		t.Fatal("trailer introduced route")
	}
}
func TestCodecBounds(t *testing.T) {
	for _, b := range [][]byte{nil, {42, 2, 0, 1}, {42, 3, 0, 0}, wire(tlv(TLVUpdate, 1)), wire(bytes.Repeat([]byte{0}, MaxMessages+1)), make([]byte, MaxPacket+1)} {
		if _, err := Decode(b, testPeer); err == nil {
			t.Fatalf("accepted malformed %x", b[:min(len(b), 16)])
		}
	}
	for _, m := range []Message{{Type: TLVAckRequest}, {Type: TLVIHU}, {Type: TLVUpdate, Prefix: netip.MustParsePrefix("::ffff:192.0.2.0/120"), Metric: MetricInfinity, Interval: 100}, {Type: TLVRouterID}} {
		if _, err := Encode([]Message{m}); err == nil {
			t.Fatal(m)
		}
	}
}
func FuzzDecode(f *testing.F) {
	f.Add(wire(update(AEIPv4ViaIPv6, 0xc0, 8, 0, 10)))
	f.Add([]byte{42, 2, 0, 0})
	f.Fuzz(func(t *testing.T, b []byte) { _, _ = Decode(b, testPeer) })
}

func TestIPv6PrefixFlagsAndLinkLocalAE(t *testing.T) {
	// R uses the low 64 bits; irrelevant prefix bits and reserved flags are ignored.
	raw := netip.MustParseAddr("2001:db8::1234:56ff").As16()
	got := decode(t, wire(update(AEIPv6, 0x7f, 120, 0, raw[:15]...)))[0]
	if got.Ignore || got.RouterID != [8]byte{0, 0, 0, 0, 0x12, 0x34, 0x56, 0} || got.Prefix.String() != "2001:db8::1234:5600/120" {
		t.Fatal(got)
	}
	got = decode(t, wire(update(AEIPv6LinkLocal, 0x40, 128, 0, 0, 0, 0, 0, 0, 0, 0, 2)))[0]
	if got.Ignore || got.Prefix.String() != "fe80::2/128" || got.RouterID != [8]byte{0, 0, 0, 0, 0, 0, 0, 2} {
		t.Fatal(got)
	}
	// Partial final octets must be masked, including inside source-prefix TLVs.
	got = decode(t, wire(update(AEIPv4ViaIPv6, 0x40, 9, 0, 10, 255, 128, 3, 9, 192, 255)))[0]
	if got.Ignore || got.Prefix.String() != "10.128.0.0/9" || got.SourcePrefix.String() != "192.128.0.0/9" {
		t.Fatal(got)
	}
}
