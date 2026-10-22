package esp

import (
	"bytes"
	"encoding/binary"
	"errors"
	"math"
	"sync"
	"testing"
)

func TestSealIntoOpenOwnedIndependentVector(t *testing.T) {
	input := bytes.Repeat([]byte{0xa5}, 128)
	copy(input, testIP)
	inputBefore := bytes.Clone(input)
	storage := bytes.Repeat([]byte{0x5a}, len(testWire)+32)
	sender, _ := NewSender(0x10203040, testKey)
	// dst's current length is deliberately unrelated to the packet length.
	packet, err := sender.SealInto(storage[:3], input[:len(testIP)])
	if err != nil || !bytes.Equal(packet, testWire) {
		t.Fatalf("independent wire vector: %x %v", packet, err)
	}
	if &packet[0] != &storage[0] || !bytes.Equal(input, inputBefore) ||
		!bytes.Equal(storage[len(packet):], bytes.Repeat([]byte{0x5a}, 32)) {
		t.Fatal("SealInto lost storage ownership, changed input, or wrote past the packet")
	}

	// The old Open still returns independent storage for a SealInto packet.
	detachedReceiver, _ := NewReceiver(0x10203040, testKey)
	detached, err := detachedReceiver.Open(packet)
	if err != nil || !bytes.Equal(packet, testWire) || !bytes.Equal(detached, testIP) {
		t.Fatal("Open changed its input or plaintext", err)
	}
	receiver, _ := NewReceiver(0x10203040, testKey)
	inner, err := receiver.OpenOwned(packet)
	if err != nil || !bytes.Equal(inner, testIP) || cap(inner) != len(inner) || &inner[0] != &packet[16] {
		t.Fatal("OpenOwned did not return the bounded in-place plaintext", err)
	}
	if !bytes.Equal(packet[:16], testWire[:16]) || !bytes.Equal(input, inputBefore) {
		t.Fatal("OpenOwned changed the header or independent sender input")
	}
	clear(inner)
	if !bytes.Equal(detached, testIP) || !bytes.Equal(packet[16:16+len(testIP)], make([]byte, len(testIP))) {
		t.Fatal("old Open was not detached or OpenOwned was not in place")
	}
}

func TestSealIntoGuardsPreserveSequenceAndStorage(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  int
		dst  int
	}{
		{"same-start", 0, 0},
		{"input-in-output", 16, 0},
		{"output-overlaps-last-input-byte", 0, len(testIP) - 1},
		{"output-last-byte-overlaps-input", len(testWire) - 1, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage := bytes.Repeat([]byte{0xa5}, 192)
			copy(storage[tc.src:], testIP)
			before := bytes.Clone(storage)
			sender, _ := NewSender(0x10203040, testKey)
			got, err := sender.SealInto(storage[tc.dst:tc.dst], storage[tc.src:tc.src+len(testIP)])
			if got != nil || !errors.Is(err, ErrInvalidPacket) || sender.sequence != 0 || !bytes.Equal(storage, before) {
				t.Fatal("overlap changed storage or consumed a sequence", err)
			}
			got, err = sender.SealInto(make([]byte, 0, len(testWire)), testIP)
			if err != nil || !bytes.Equal(got, testWire) {
				t.Fatal("overlap rejection prevented a valid retry", err)
			}
		})
	}
	for _, tc := range []struct {
		name  string
		input []byte
		cap   int
	}{
		{"nil-output", testIP, 0},
		{"one-byte-short", testIP, len(testWire) - 1},
		{"invalid-inner", append(bytes.Clone(testIP), 0), len(testWire) + 4},
	} {
		t.Run(tc.name, func(t *testing.T) {
			storage := bytes.Repeat([]byte{0xa5}, tc.cap)
			before := bytes.Clone(storage)
			sender, _ := NewSender(0x10203040, testKey)
			got, err := sender.SealInto(storage[:0], tc.input)
			if got != nil || !errors.Is(err, ErrInvalidPacket) || sender.sequence != 0 || !bytes.Equal(storage, before) {
				t.Fatal("invalid buffer or input changed storage or consumed a sequence", err)
			}
		})
	}
}

func TestSealIntoDisjointBackingAndExhaustion(t *testing.T) {
	for _, inputFirst := range []bool{true, false} {
		storage := make([]byte, len(testIP)+len(testWire))
		var input, dst []byte
		if inputFirst {
			// The input has spare capacity spanning dst, but its readable bytes
			// do not overlap the output write region.
			input, dst = storage[:len(testIP)], storage[len(testIP):len(testIP)]
		} else {
			input, dst = storage[len(testWire):], storage[:0:len(testWire)]
		}
		copy(input, testIP)
		sender, _ := NewSender(0x10203040, testKey)
		got, err := sender.SealInto(dst, input)
		if err != nil || !bytes.Equal(got, testWire) || !bytes.Equal(input, testIP) {
			t.Fatal("disjoint regions in one backing array must be usable", err)
		}
	}
	sender, _ := NewSender(0x10203040, testKey)
	sender.sequence = math.MaxUint32 - 1
	storage := make([]byte, len(testWire))
	packet, err := sender.SealInto(storage[:0], testIP)
	if err != nil || binary.BigEndian.Uint32(packet[4:8]) != math.MaxUint32 {
		t.Fatal("last sequence was not available", err)
	}
	receiver, _ := NewReceiver(0x10203040, testKey)
	if inner, err := receiver.OpenOwned(packet); err != nil || !bytes.Equal(inner, testIP) {
		t.Fatal("last sequence could not be opened", err)
	}
	before := bytes.Clone(storage)
	for range 2 {
		if got, err := sender.SealInto(storage[:0], testIP); got != nil || !errors.Is(err, ErrSequenceExhausted) || !bytes.Equal(storage, before) {
			t.Fatal("sequence exhaustion changed the output", err)
		}
	}
}

func TestOpenOwnedErrorsDoNotAdvanceReplay(t *testing.T) {
	valid := append(bytes.Clone(testIP), 1, 2, 2, 4)
	for name, mutate := range map[string]func([]byte){
		"padding":     func(p []byte) { p[len(testIP)] = 0 },
		"pad-length":  func(p []byte) { p[len(p)-2] = 255 },
		"next-header": func(p []byte) { p[len(p)-1] = 41 },
		"inner-length": func(p []byte) {
			p[3]--
		},
	} {
		t.Run(name, func(t *testing.T) {
			receiver, _ := NewReceiver(0x10203040, testKey)
			plaintext := bytes.Clone(valid)
			mutate(plaintext)
			// Authenticate a malformed high sequence independently. This is a
			// test-only peer; production does not expose raw plaintext sealing.
			header := bytes.Clone(testWire[:16])
			binary.BigEndian.PutUint32(header[4:8], 32)
			binary.BigEndian.PutUint64(header[8:16], 32)
			var nonce [12]byte
			copy(nonce[:4], receiver.sa.salt[:])
			copy(nonce[4:], header[8:16])
			bad := receiver.sa.aead.Seal(header, nonce[:], plaintext, header[:8])
			if got, err := receiver.OpenOwned(bad); got != nil || !errors.Is(err, ErrInvalidPacket) || receiver.highest != 0 || receiver.seen != 0 {
				t.Fatal("malformed authenticated packet advanced replay or leaked plaintext", err)
			}
			if got, err := receiver.OpenOwned(bytes.Clone(testWire)); err != nil || !bytes.Equal(got, testIP) {
				t.Fatal("malformed high sequence prevented a valid packet", err)
			}
		})
	}
	receiver, _ := NewReceiver(0x10203040, testKey)
	bad := bytes.Clone(testWire)
	binary.BigEndian.PutUint32(bad[4:8], math.MaxUint32)
	if got, err := receiver.OpenOwned(bad); got != nil || !errors.Is(err, ErrAuthentication) || receiver.highest != 0 || receiver.seen != 0 {
		t.Fatal("forged high sequence advanced replay or leaked plaintext", err)
	}
	if got, err := receiver.OpenOwned(bytes.Clone(testWire)); err != nil || !bytes.Equal(got, testIP) {
		t.Fatal("authentication failure prevented a valid packet", err)
	}
}

func TestOwnedPacketBoundsAndIPv6(t *testing.T) {
	for n := 0; n < len(testWire); n++ {
		receiver, _ := NewReceiver(0x10203040, testKey)
		if got, err := receiver.OpenOwned(bytes.Clone(testWire[:n])); got != nil || err == nil || receiver.highest != 0 || receiver.seen != 0 {
			t.Fatalf("truncation %d accepted or advanced replay: %v", n, err)
		}
	}
	for _, bad := range [][]byte{make([]byte, MaxPacket+4), append(bytes.Clone(testWire), 0, 0, 0, 0)} {
		receiver, _ := NewReceiver(0x10203040, testKey)
		if got, err := receiver.OpenOwned(bad); got != nil || err == nil || receiver.highest != 0 || receiver.seen != 0 {
			t.Fatal("wire bounds accepted or advanced replay", err)
		}
	}
	for extra := 0; extra < 8; extra++ {
		inner := make([]byte, 40+extra)
		inner[0] = 0x60
		binary.BigEndian.PutUint16(inner[4:6], uint16(extra))
		sender, _ := NewSender(256, testKey)
		receiver, _ := NewReceiver(256, testKey)
		packet, err := sender.SealInto(make([]byte, 0, 84), inner)
		if err != nil {
			t.Fatalf("IPv6 extra %d: %v", extra, err)
		}
		if got, err := receiver.OpenOwned(packet); err != nil || !bytes.Equal(got, inner) {
			t.Fatal("IPv6 and varying padding did not round trip", err)
		}
	}
	inner := make([]byte, MaxInnerPacket)
	inner[0] = 0x45
	binary.BigEndian.PutUint16(inner[2:4], uint16(len(inner)))
	sender, _ := NewSender(256, testKey)
	receiver, _ := NewReceiver(256, testKey)
	packet, err := sender.SealInto(make([]byte, 0, MaxPacket), inner)
	if err != nil || len(packet) != MaxPacket {
		t.Fatal("maximum packet did not fit the exact output capacity", err)
	}
	if got, err := receiver.OpenOwned(packet); err != nil || !bytes.Equal(got, inner) {
		t.Fatal("maximum packet did not round trip", err)
	}
}

func TestOpenOwnedPeerIVAndNonminimalPadding(t *testing.T) {
	receiver, _ := NewReceiver(0x10203040, testKey)
	header := bytes.Clone(testWire[:16])
	copy(header[8:], unhex("1020304050607080"))
	plaintext := bytes.Clone(testIP)
	for i := 1; i <= 254; i++ {
		plaintext = append(plaintext, byte(i))
	}
	plaintext = append(plaintext, 254, 4)
	var nonce [12]byte
	copy(nonce[:4], receiver.sa.salt[:])
	copy(nonce[4:], header[8:16])
	packet := receiver.sa.aead.Seal(header, nonce[:], plaintext, header[:8])
	if got, err := receiver.OpenOwned(packet); err != nil || !bytes.Equal(got, testIP) || &got[0] != &packet[16] {
		t.Fatal("arbitrary peer IV and nonminimal padding failed in-place decoding", err)
	}
}

func TestConcurrentOwnedSenderAndDuplicateReceiver(t *testing.T) {
	sender, _ := NewSender(256, testKey)
	receiver, _ := NewReceiver(256, testKey)
	packets := make(chan []byte, 32)
	var wg sync.WaitGroup
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Each concurrent caller owns a different output allocation.
			packet, err := sender.SealInto(make([]byte, 0, len(testWire)), testIP)
			if err != nil {
				t.Error(err)
				return
			}
			packets <- packet
		}()
	}
	wg.Wait()
	close(packets)
	seen := make(map[uint32]bool)
	for packet := range packets {
		sequence := binary.BigEndian.Uint32(packet[4:8])
		if sequence == 0 || seen[sequence] || binary.BigEndian.Uint64(packet[8:16]) != uint64(sequence) {
			t.Fatal("concurrent sealing reused a nonce or sequence")
		}
		seen[sequence] = true
		if got, err := receiver.OpenOwned(packet); err != nil || !bytes.Equal(got, testIP) {
			t.Fatal(err)
		}
	}
	if len(seen) != 32 {
		t.Fatal("concurrent sealing lost packets")
	}
	receiver, _ = NewReceiver(0x10203040, testKey)
	accepted := make(chan bool, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Exclusive inputs are required even for duplicate wire packets:
			// the successful caller will overwrite its ciphertext.
			got, err := receiver.OpenOwned(bytes.Clone(testWire))
			if err != nil && !errors.Is(err, ErrReplay) {
				t.Error(err)
			}
			accepted <- err == nil && bytes.Equal(got, testIP)
		}()
	}
	wg.Wait()
	close(accepted)
	n := 0
	for ok := range accepted {
		if ok {
			n++
		}
	}
	if n != 1 {
		t.Fatalf("accepted %d independent copies of one sequence", n)
	}
}
