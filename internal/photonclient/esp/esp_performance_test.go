package esp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func TestSealOwnsItsPacketBuffer(t *testing.T) {
	// Extra caller capacity must not become plaintext workspace or returned
	// ciphertext storage. Keep the input intact even beyond its logical end.
	backing := bytes.Repeat([]byte{0xa5}, 128)
	copy(backing, testIP)
	before := bytes.Clone(backing)
	sender, _ := NewSender(0x10203040, testKey)
	packet, err := sender.Seal(backing[:len(testIP)])
	if err != nil || !bytes.Equal(packet, testWire) || !bytes.Equal(backing, before) {
		t.Fatal("Seal changed its input or independent wire vector", err)
	}
	clear(packet)
	if !bytes.Equal(backing, before) {
		t.Fatal("ciphertext shares caller backing storage")
	}
}

func BenchmarkSeal1200(b *testing.B) {
	sender, err := NewSender(0x10203040, testKey)
	if err != nil {
		b.Fatal(err)
	}
	packet := make([]byte, 1200)
	copy(packet, testIP)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	b.ResetTimer()
	for b.Loop() {
		if _, err := sender.Seal(packet); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkSealOpen1200 measures a crypto round trip for a complete 1200-byte
// inner IP packet. It performs no network I/O.
func BenchmarkSealOpen1200(b *testing.B) {
	var keySalt [20]byte
	if _, err := rand.Read(keySalt[:]); err != nil {
		b.Fatal(err)
	}
	sender, err := NewSender(0x10203040, keySalt[:])
	if err != nil {
		b.Fatal(err)
	}
	receiver, err := NewReceiver(0x10203040, keySalt[:])
	if err != nil {
		b.Fatal(err)
	}
	packet := bytes.Repeat([]byte{0xa5}, 1200)
	copy(packet, testIP)
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	b.ReportAllocs()
	b.SetBytes(int64(len(packet)))
	for b.Loop() {
		sealed, err := sender.Seal(packet)
		if err != nil {
			b.Fatal(err)
		}
		opened, err := receiver.Open(sealed)
		if err != nil {
			b.Fatal(err)
		}
		if !bytes.Equal(opened, packet) {
			b.Fatal("Seal/Open changed the inner packet")
		}
	}
}

// BenchmarkESP1200ApplicationPair seals and opens an IPv4/UDP packet carrying
// 1200 application bytes (1228 inner bytes, 1264 ESP bytes). Each pair counts the
// application bytes once. No network I/O or selector authorization is measured.
// Both paths keep one fresh directional key and continuous sequence/replay state
// throughout the benchmark, and check the entire returned inner packet.
func BenchmarkESP1200ApplicationPair(b *testing.B) {
	for _, owned := range []bool{false, true} {
		name := "Detached"
		if owned {
			name = "OwnedWorkspace"
		}
		b.Run(name, func(b *testing.B) {
			var keySalt [20]byte
			if _, err := rand.Read(keySalt[:]); err != nil {
				b.Fatal(err)
			}
			sender, err := NewSender(0x10203040, keySalt[:])
			if err != nil {
				b.Fatal(err)
			}
			receiver, err := NewReceiver(0x10203040, keySalt[:])
			if err != nil {
				b.Fatal(err)
			}
			inner := make([]byte, 20+8+1200)
			copy(inner, testIP[:20])
			binary.BigEndian.PutUint16(inner[2:4], uint16(len(inner)))
			// IPv4 permits a zero UDP checksum. Set the ports and UDP length,
			// then fill all application bytes and calculate the IPv4 checksum.
			binary.BigEndian.PutUint16(inner[20:22], 19341)
			binary.BigEndian.PutUint16(inner[22:24], 19342)
			binary.BigEndian.PutUint16(inner[24:26], uint16(8+1200))
			for i := range inner[28:] {
				inner[28+i] = byte(i)
			}
			var checksum uint32
			for i := 0; i < 20; i += 2 {
				checksum += uint32(binary.BigEndian.Uint16(inner[i : i+2]))
			}
			for checksum>>16 != 0 {
				checksum = checksum&0xffff + checksum>>16
			}
			binary.BigEndian.PutUint16(inner[10:12], ^uint16(checksum))
			oracle := bytes.Clone(inner)
			workspace := make([]byte, 0, MaxPacket)
			b.ReportAllocs()
			b.SetBytes(1200)
			for b.Loop() {
				var sealed, opened []byte
				if owned {
					sealed, err = sender.SealInto(workspace, inner)
					if err == nil {
						opened, err = receiver.OpenOwned(sealed)
					}
				} else {
					sealed, err = sender.Seal(inner)
					if err == nil {
						opened, err = receiver.Open(sealed)
					}
				}
				if err != nil || len(sealed) != 1264 || !bytes.Equal(opened, oracle) {
					b.Fatal("ESP pair failed or changed the inner packet", err)
				}
			}
			if !bytes.Equal(inner, oracle) {
				b.Fatal("ESP pair changed the caller's inner packet")
			}
		})
	}
}
