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
