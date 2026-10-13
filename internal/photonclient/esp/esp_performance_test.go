package esp

import (
	"bytes"
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
