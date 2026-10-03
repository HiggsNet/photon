package esp

import (
	"bytes"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"math"
	"sync"
	"testing"
)

func unhex(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}

var testKey = unhex("000102030405060708090a0b0c0d0e0fa0a1a2a3")
var testIP = unhex("450000180001000040110000c0000201c633640201020304")
var testWire = unhex("1020304000000001000000000000000103711cea6c857750c77d46171b049667d7c17d8197f783a66cf3891445e963210b9788ec7faf2f3ee7aeff98")

func TestIndependentOpenSSLVector(t *testing.T) {
	// Fixed result produced by testdata/vector.cjs using Node/OpenSSL. This
	// checks salt/IV/AAD/padding/tag placement independently of a Go roundtrip.
	s, _ := NewSender(0x10203040, testKey)
	got, err := s.Seal(testIP)
	if err != nil || !bytes.Equal(got, testWire) {
		t.Fatalf("Seal = %x, %v", got, err)
	}
	r, _ := NewReceiver(0x10203040, testKey)
	got, err = r.Open(testWire)
	if err != nil || !bytes.Equal(got, testIP) {
		t.Fatalf("Open = %x, %v", got, err)
	}
}

func TestConstructorsAndKeyOwnership(t *testing.T) {
	for _, spi := range []uint32{0, 1, 255} {
		if _, err := NewSender(spi, testKey); err == nil {
			t.Fatal("reserved SPI")
		}
		if _, err := NewReceiver(spi, testKey); err == nil {
			t.Fatal("reserved SPI")
		}
	}
	for _, n := range []int{0, 16, 19, 21, 36} {
		if _, err := NewSender(256, make([]byte, n)); err == nil {
			t.Fatal("invalid key")
		}
	}
	key := bytes.Clone(testKey)
	s, _ := NewSender(0x10203040, key)
	r, _ := NewReceiver(0x10203040, key)
	clear(key)
	p, _ := s.Seal(testIP)
	if !bytes.Equal(p, testWire) {
		t.Fatal("retained caller key")
	}
	if _, err := r.Open(p); err != nil {
		t.Fatal(err)
	}
}

func TestReplayWindow(t *testing.T) {
	s, _ := NewSender(256, testKey)
	r, _ := NewReceiver(256, testKey)
	packets := make([][]byte, 130)
	for i := range packets {
		packets[i], _ = s.Seal(testIP)
	}
	for _, i := range []int{63, 0, 62, 1, 129, 66, 128} {
		if _, err := r.Open(packets[i]); err != nil {
			t.Fatalf("seq%d: %v", i+1, err)
		}
		if _, err := r.Open(packets[i]); !errors.Is(err, ErrReplay) {
			t.Fatalf("duplicate seq%d: %v", i+1, err)
		}
	}
	if _, err := r.Open(packets[65]); !errors.Is(err, ErrReplay) {
		t.Fatalf("stale boundary: %v", err)
	}
	if _, err := r.Open(packets[127]); err != nil {
		t.Fatal(err)
	}
}

func TestCorruptionDoesNotAdvanceReplay(t *testing.T) {
	for i := range testWire {
		r, _ := NewReceiver(0x10203040, testKey)
		bad := bytes.Clone(testWire)
		bad[i] ^= 0x80
		if _, err := r.Open(bad); err == nil {
			t.Fatalf("accepted mutation at%d", i)
		}
		if _, err := r.Open(testWire); err != nil {
			t.Fatalf("mutation advanced replay: %v", err)
		}
	}
	r, _ := NewReceiver(0x10203040, testKey)
	bad := bytes.Clone(testWire)
	binary.BigEndian.PutUint32(bad[4:8], math.MaxUint32)
	if _, err := r.Open(bad); !errors.Is(err, ErrAuthentication) {
		t.Fatal(err)
	}
	if _, err := r.Open(testWire); err != nil {
		t.Fatal(err)
	}
}

// Forge authenticated malformed plaintext to verify checks after GCM.Open.
// These deliberately reuse nonces only in tests; production never exposes SealRaw.
func malformedWire(r *Receiver, plaintext []byte) []byte {
	packet := bytes.Clone(testWire[:16])
	var nonce [12]byte
	copy(nonce[:4], r.sa.salt[:])
	copy(nonce[4:], packet[8:16])
	return r.sa.aead.Seal(packet, nonce[:], plaintext, packet[:8])
}

func TestAuthenticatedMalformedDoesNotAdvanceReplay(t *testing.T) {
	valid := append(bytes.Clone(testIP), 1, 2, 2, 4)
	cases := map[string][]byte{}
	for name, change := range map[string]func([]byte){
		"padding":      func(p []byte) { p[24] = 0 },
		"pad-length":   func(p []byte) { p[26] = 255 },
		"next-header":  func(p []byte) { p[27] = 41 },
		"total-length": func(p []byte) { p[3]-- },
		"version":      func(p []byte) { p[0] = 0x70 },
		"ihl":          func(p []byte) { p[0] = 0x4f },
	} {
		p := bytes.Clone(valid)
		change(p)
		cases[name] = p
	}
	cases["empty"] = []byte{1, 2, 2, 4}
	for name, p := range cases {
		t.Run(name, func(t *testing.T) {
			r, _ := NewReceiver(0x10203040, testKey)
			if _, err := r.Open(malformedWire(r, p)); !errors.Is(err, ErrInvalidPacket) {
				t.Fatalf("%v", err)
			}
			if _, err := r.Open(testWire); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestPacketBoundsAndSequenceExhaustion(t *testing.T) {
	s, _ := NewSender(256, testKey)
	for _, p := range [][]byte{nil, make([]byte, 19), append(bytes.Clone(testIP), 0), {0x40}, make([]byte, MaxInnerPacket+1)} {
		if _, err := s.Seal(p); !errors.Is(err, ErrInvalidPacket) {
			t.Fatalf("accepted malformed: %v", err)
		}
	}
	if s.sequence != 0 {
		t.Fatal("invalid packet consumed sequence")
	}
	large := make([]byte, MaxInnerPacket)
	large[0] = 0x45
	binary.BigEndian.PutUint16(large[2:4], uint16(len(large)))
	p, err := s.Seal(large)
	if err != nil || len(p) != MaxPacket {
		t.Fatalf("maximum: len%d %v", len(p), err)
	}
	r, _ := NewReceiver(256, testKey)
	if got, err := r.Open(p); err != nil || !bytes.Equal(got, large) {
		t.Fatal(err)
	}
	s.sequence = math.MaxUint32 - 1
	p, err = s.Seal(testIP)
	if err != nil || binary.BigEndian.Uint32(p[4:8]) != math.MaxUint32 {
		t.Fatal(err)
	}
	for range 2 {
		if _, err = s.Seal(testIP); !errors.Is(err, ErrSequenceExhausted) {
			t.Fatal(err)
		}
	}
}

func TestIPv6AndPaddingLengths(t *testing.T) {
	for extra := 0; extra < 8; extra++ {
		inner := make([]byte, 40+extra)
		inner[0] = 0x60
		binary.BigEndian.PutUint16(inner[4:6], uint16(extra))
		s, _ := NewSender(256, testKey)
		r, _ := NewReceiver(256, testKey)
		packet, err := s.Seal(inner)
		if err != nil {
			t.Fatal(err)
		}
		got, err := r.Open(packet)
		if err != nil || !bytes.Equal(got, inner) {
			t.Fatal(err)
		}
		inner[5]++
		if _, err := s.Seal(inner); err == nil {
			t.Fatal("IPv6 length mismatch")
		}
	}
}

func TestPeerIVAndNonminimalPadding(t *testing.T) {
	r, _ := NewReceiver(0x10203040, testKey)
	// A peer may choose any unique explicit IV, independent of its sequence.
	header := bytes.Clone(testWire[:16])
	copy(header[8:], unhex("1020304050607080"))
	plaintext := bytes.Clone(testIP)
	for i := 1; i <= 254; i++ {
		plaintext = append(plaintext, byte(i))
	}
	plaintext = append(plaintext, 254, 4)
	var nonce [12]byte
	copy(nonce[:4], r.sa.salt[:])
	copy(nonce[4:], header[8:])
	packet := r.sa.aead.Seal(header, nonce[:], plaintext, header[:8])
	got, err := r.Open(packet)
	if err != nil || !bytes.Equal(got, testIP) {
		t.Fatalf("peer IV/padding: %v", err)
	}
	// Neither the encrypted input nor the returned packet aliases the other.
	clear(packet)
	if !bytes.Equal(got, testIP) {
		t.Fatal("Open aliases input")
	}
}

func TestRejectWireBounds(t *testing.T) {
	for n := 0; n < len(testWire); n++ {
		r, _ := NewReceiver(0x10203040, testKey)
		if _, err := r.Open(testWire[:n]); err == nil {
			t.Fatalf("accepted truncation %d", n)
		}
	}
	r, _ := NewReceiver(0x10203040, testKey)
	for _, p := range [][]byte{make([]byte, MaxPacket+4), append(bytes.Clone(testWire), 0, 0, 0, 0)} {
		if _, err := r.Open(p); err == nil {
			t.Fatal("accepted oversized or trailing packet")
		}
	}
}

func TestConcurrentSenderAndDuplicateReceiver(t *testing.T) {
	s, _ := NewSender(256, testKey)
	r, _ := NewReceiver(256, testKey)
	var wg sync.WaitGroup
	packets := make(chan []byte, 32)
	for range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := s.Seal(testIP)
			if err != nil {
				t.Error(err)
			}
			packets <- p
		}()
	}
	wg.Wait()
	close(packets)
	seen := map[uint32]bool{}
	for p := range packets {
		seq := binary.BigEndian.Uint32(p[4:8])
		if seen[seq] {
			t.Fatal("nonce reuse")
		}
		seen[seq] = true
		if _, err := r.Open(p); err != nil {
			t.Fatal(err)
		}
	}
	r, _ = NewReceiver(0x10203040, testKey)
	accepted := make(chan bool, 32)
	for range 32 {
		wg.Add(1)
		go func() { defer wg.Done(); _, err := r.Open(testWire); accepted <- err == nil }()
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
		t.Fatalf("accepted%d", n)
	}
}

func FuzzOpen(f *testing.F) {
	f.Add(testWire)
	f.Add([]byte{})
	f.Add(make([]byte, 36))
	f.Fuzz(func(t *testing.T, p []byte) {
		r, _ := NewReceiver(0x10203040, testKey)
		got, err := r.Open(p)
		if err != nil {
			if r.highest != 0 || r.seen != 0 {
				t.Fatal("failed packet advanced replay")
			}
			return
		}
		if _, err := innerProtocol(got); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Open(p); !errors.Is(err, ErrReplay) {
			t.Fatal("accepted replay")
		}
	})
}

func FuzzAuthenticatedTrailer(f *testing.F) {
	f.Add(append(bytes.Clone(testIP), 1, 2, 2, 4))
	f.Add([]byte{1, 2, 2, 4})
	f.Fuzz(func(t *testing.T, plaintext []byte) {
		if len(plaintext) < 4 || len(plaintext) > MaxPacket-32 || len(plaintext)%4 != 0 {
			return
		}
		r, _ := NewReceiver(0x10203040, testKey)
		packet := malformedWire(r, plaintext)
		inner, err := r.Open(packet)
		if err != nil {
			if r.highest != 0 || r.seen != 0 {
				t.Fatal("malformed plaintext advanced replay")
			}
			return
		}
		if _, err := innerProtocol(inner); err != nil {
			t.Fatal(err)
		}
		if _, err := r.Open(packet); !errors.Is(err, ErrReplay) {
			t.Fatal("accepted replay")
		}
	})
}
