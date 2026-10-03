// Package esp implements the AES-128-GCM-16, no-ESN tunnel packet format in
// RFC 4106 and RFC 4303. It owns one directional SA's sequence/replay state,
// not sockets, traffic-selector authorization, routing, or SA lifetimes.
package esp

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"errors"
	"math"
	"sync"
)

const (
	// MaxPacket is four-byte aligned and fits a maximum IPv4 UDP payload.
	// Actual path MTU limits will normally be substantially smaller.
	MaxPacket      = 65504
	MaxInnerPacket = MaxPacket - 32 - 2
)

var (
	ErrInvalidPacket     = errors.New("esp: invalid packet")
	ErrAuthentication    = errors.New("esp: authentication failed")
	ErrReplay            = errors.New("esp: replay or stale sequence")
	ErrSequenceExhausted = errors.New("esp: sequence exhausted; replace SA")
)

type securityAssociation struct {
	spi  uint32
	aead cipher.AEAD
	salt [4]byte
}

func newSA(spi uint32, keySalt []byte) (securityAssociation, error) {
	if spi < 256 || len(keySalt) != 20 {
		return securityAssociation{}, errors.New("esp: require SPI >= 256 and 20-byte AES-128 key plus salt")
	}
	block, err := aes.NewCipher(keySalt[:16])
	if err != nil {
		return securityAssociation{}, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return securityAssociation{}, err
	}
	sa := securityAssociation{spi: spi, aead: aead}
	copy(sa.salt[:], keySalt[16:])
	return sa, nil
}

// Sender is safe for concurrent use and must not be copied. Create exactly one
// Sender for each fresh directional SA key. Never reconstruct it with previously
// used key material: restarting the sequence would repeat a GCM nonce. A restart
// requires a newly negotiated SA, even when its SPI differs.
type Sender struct {
	mu       sync.Mutex
	sa       securityAssociation
	sequence uint32
}

func NewSender(spi uint32, keySalt []byte) (*Sender, error) {
	sa, err := newSA(spi, keySalt)
	if err != nil {
		return nil, err
	}
	return &Sender{sa: sa}, nil
}

// Seal returns an ESP packet without outer IP or UDP headers. The caller must
// first enforce the SA's outbound traffic selectors and its effective MTU.
func (s *Sender) Seal(ipPacket []byte) ([]byte, error) {
	next, err := innerProtocol(ipPacket)
	if err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sequence == math.MaxUint32 {
		return nil, ErrSequenceExhausted
	}
	s.sequence++
	padding := (4 - (len(ipPacket)+2)%4) % 4
	plaintext := make([]byte, len(ipPacket)+padding+2)
	copy(plaintext, ipPacket)
	for i := 0; i < padding; i++ {
		plaintext[len(ipPacket)+i] = byte(i + 1)
	}
	plaintext[len(plaintext)-2] = byte(padding)
	plaintext[len(plaintext)-1] = next
	packet := make([]byte, 16, 16+len(plaintext)+16)
	binary.BigEndian.PutUint32(packet[:4], s.sa.spi)
	binary.BigEndian.PutUint32(packet[4:8], s.sequence)
	binary.BigEndian.PutUint64(packet[8:16], uint64(s.sequence))
	var nonce [12]byte
	copy(nonce[:4], s.sa.salt[:])
	copy(nonce[4:], packet[8:16])
	return s.sa.aead.Seal(packet, nonce[:], plaintext, packet[:8]), nil
}

// Receiver is safe for concurrent use and must not be copied. Its 64-packet
// replay window advances only after authentication and complete packet checks.
// Keep this receiver for the entire directional SA lifetime; replacing it
// with the same keys would forget already accepted packets.
type Receiver struct {
	mu      sync.Mutex
	sa      securityAssociation
	highest uint32
	seen    uint64
}

func NewReceiver(spi uint32, keySalt []byte) (*Receiver, error) {
	sa, err := newSA(spi, keySalt)
	if err != nil {
		return nil, err
	}
	return &Receiver{sa: sa}, nil
}

// Open authenticates and unwraps an ESP packet. It returns a detached inner IP
// packet. Before delivery, the caller must enforce inbound traffic selectors.
// TFC padding, dummy packets, and IPv6 jumbograms are not supported.
func (r *Receiver) Open(packet []byte) ([]byte, error) {
	if len(packet) < 36 || len(packet) > MaxPacket || len(packet)%4 != 0 {
		return nil, ErrInvalidPacket
	}
	if binary.BigEndian.Uint32(packet[:4]) != r.sa.spi {
		return nil, ErrInvalidPacket
	}
	sequence := binary.BigEndian.Uint32(packet[4:8])
	if sequence == 0 {
		return nil, ErrInvalidPacket
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if sequence <= r.highest {
		distance := r.highest - sequence
		if distance >= 64 || r.seen&(uint64(1)<<distance) != 0 {
			return nil, ErrReplay
		}
	}
	var nonce [12]byte
	copy(nonce[:4], r.sa.salt[:])
	copy(nonce[4:], packet[8:16])
	plaintext, err := r.sa.aead.Open(nil, nonce[:], packet[16:], packet[:8])
	if err != nil {
		return nil, ErrAuthentication
	}
	padding := int(plaintext[len(plaintext)-2])
	end := len(plaintext) - 2 - padding
	if end < 0 {
		return nil, ErrInvalidPacket
	}
	for i := 0; i < padding; i++ {
		if plaintext[end+i] != byte(i+1) {
			return nil, ErrInvalidPacket
		}
	}
	inner := plaintext[:end:end]
	next, err := innerProtocol(inner)
	if err != nil || next != plaintext[len(plaintext)-1] {
		return nil, ErrInvalidPacket
	}
	if sequence > r.highest {
		r.seen = r.seen<<(sequence-r.highest) | 1
		r.highest = sequence
	} else {
		r.seen |= uint64(1) << (r.highest - sequence)
	}
	return inner, nil
}

func innerProtocol(packet []byte) (byte, error) {
	if len(packet) < 20 || len(packet) > MaxInnerPacket {
		return 0, ErrInvalidPacket
	}
	switch packet[0] >> 4 {
	case 4:
		header := int(packet[0]&15) * 4
		if header < 20 || header > len(packet) || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
			return 0, ErrInvalidPacket
		}
		return 4, nil
	case 6:
		if len(packet) < 40 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) {
			return 0, ErrInvalidPacket
		}
		return 41, nil
	default:
		return 0, ErrInvalidPacket
	}
}
