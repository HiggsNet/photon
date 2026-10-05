package babel

import (
	"bytes"
	"net/netip"
	"testing"
)

func TestPacketRoundTripAndChecksum(t *testing.T) {
	local := netip.MustParseAddr("fe80::1")
	for _, dest := range []netip.Addr{local, Multicast} {
		for _, payload := range [][]byte{{42, 2, 0, 0}, {42, 2, 0, 1, 0}, bytes.Repeat([]byte{7}, MaxPacket)} {
			b, err := BuildPacket(testPeer, dest, payload)
			if err != nil {
				t.Fatal(err)
			}
			src, out, err := ParsePacket(b, local)
			if err != nil || src != testPeer || !bytes.Equal(out, payload) {
				t.Fatalf("%v %v", src, err)
			}
			// Independent bytewise pseudo-header sum also verifies odd payload padding.
			pseudo := append(testPeer.AsSlice(), dest.AsSlice()...)
			pseudo = append(pseudo, 0, 0, byte((len(b)-40)>>8), byte(len(b)-40), 0, 0, 0, 17)
			pseudo = append(pseudo, b[40:]...)
			var sum uint32
			for i, v := range pseudo {
				if i%2 == 0 {
					sum += uint32(v) << 8
				} else {
					sum += uint32(v)
				}
			}
			for sum > 65535 {
				sum = (sum & 65535) + (sum >> 16)
			}
			if sum != 65535 {
				t.Fatalf("checksum %x", sum)
			}
			out[0] ^= 1
			if b[48] != payload[0] {
				t.Fatal("aliased payload")
			}
			for _, index := range []int{0, 4, 6, 8, 24, 40, 42, 44, 46, len(b) - 1} {
				corrupt := bytes.Clone(b)
				corrupt[index] ^= 0x10
				if _, _, err := ParsePacket(corrupt, local); err == nil {
					t.Fatalf("accepted corrupted byte %d", index)
				}
			}
		}
	}
	for _, src := range []string{"2001:db8::1", "192.0.2.1", "fe80::1%eth0"} {
		if _, err := BuildPacket(netip.MustParseAddr(src), Multicast, []byte{42, 2, 0, 0}); err == nil {
			t.Fatal(src)
		}
	}
}
func FuzzPacket(f *testing.F) {
	b, _ := BuildPacket(testPeer, Multicast, []byte{42, 2, 0, 0})
	f.Add(b)
	f.Fuzz(func(t *testing.T, b []byte) { _, _, _ = ParsePacket(b, netip.MustParseAddr("fe80::1")) })
}
