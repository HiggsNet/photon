package ike

// RFC 7383 SKF support for the existing AES-CBC-128/HMAC-SHA256-128 profile.
// Plaintext payloads preceding SKF and active PMTU probing are not supported.
import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

const (
	PayloadSKF                   uint8  = 53
	NotifyFragmentationSupported uint16 = 16430
	maxFragments                        = 64
	fragmentTimeout                     = 30 * time.Second
)

// SealSKF splits an encrypted payload's plaintext regardless of inner payload
// boundaries. maxPacket is the IKE datagram budget, excluding IP/UDP and NAT-T
// marker overhead. The session must negotiate fragmentation before calling it,
// and retain the resulting packets unchanged for retransmission.
func SealSKF(h Header, first uint8, plain, encryptionKey, integrityKey []byte, maxPacket int, random io.Reader) ([][]byte, error) {
	if len(encryptionKey) != 16 || len(integrityKey) != 32 || random == nil || first == 0 || len(plain) == 0 || len(plain) > MaxMessageSize || h.ExchangeType == ExchangeSAInit || maxPacket > MaxMessageSize {
		return nil, fmt.Errorf("ike: invalid SKF input")
	}
	// CBC ciphertext includes at least the trailing pad-length byte.
	overhead := HeaderLen + 8 + aes.BlockSize + skICVLen
	if maxPacket < overhead+aes.BlockSize {
		return nil, fmt.Errorf("ike: SKF datagram budget too small")
	}
	chunkSize := (maxPacket-overhead)/aes.BlockSize*aes.BlockSize - 1
	total := (len(plain) + chunkSize - 1) / chunkSize
	if total > maxFragments {
		return nil, fmt.Errorf("ike: too many SKF fragments")
	}
	packets := make([][]byte, 0, total)
	for number := 1; number <= total; number++ {
		end := min(len(plain), chunkSize)
		chunk := plain[:end]
		plain = plain[end:]
		cipherLength := (len(chunk)/aes.BlockSize + 1) * aes.BlockSize
		packet, err := h.Marshal(PayloadSKF, overhead+cipherLength)
		if err != nil {
			return nil, err
		}
		packet = append(packet, make([]byte, overhead+cipherLength-HeaderLen)...)
		if number == 1 {
			packet[HeaderLen] = first
		}
		binary.BigEndian.PutUint16(packet[HeaderLen+2:], uint16(len(packet)-HeaderLen))
		binary.BigEndian.PutUint16(packet[HeaderLen+4:], uint16(number))
		binary.BigEndian.PutUint16(packet[HeaderLen+6:], uint16(total))
		iv := packet[HeaderLen+8 : HeaderLen+8+aes.BlockSize]
		if _, err := io.ReadFull(random, iv); err != nil {
			return nil, err
		}
		encrypted := packet[HeaderLen+8+aes.BlockSize : len(packet)-skICVLen]
		copy(encrypted, chunk)
		encrypted[len(encrypted)-1] = byte(len(encrypted) - len(chunk) - 1)
		block, _ := aes.NewCipher(encryptionKey)
		cipher.NewCBCEncrypter(block, iv).CryptBlocks(encrypted, encrypted)
		copy(packet[len(packet)-skICVLen:], PRFSHA256(integrityKey, packet[:len(packet)-skICVLen])[:skICVLen])
		packets = append(packets, packet)
	}
	return packets, nil
}

// skfReassembly belongs to one pending session exchange. Its caller serializes
// access, supplies the expected SA/direction/message ID, and calls Reset when
// the exchange is cancelled or its timer expires. Add also expires stale data.
// Completion clears retained plaintext; the session alone advances message IDs.
type skfReassembly struct {
	header                Header
	parts                 [maxFragments][]byte
	total, received, size int
	first                 uint8
	started               time.Time
}

func (r *skfReassembly) Reset() {
	for _, part := range r.parts {
		clear(part)
	}
	*r = skfReassembly{}
}

func (r *skfReassembly) Add(packet []byte, expected Header, encryptionKey, integrityKey []byte, now time.Time) (uint8, []byte, bool, error) {
	if !r.started.IsZero() && !now.Before(r.started.Add(fragmentTimeout)) {
		r.Reset()
	}
	h, next, err := DecodeHeader(packet)
	if err != nil {
		return 0, nil, false, err
	}
	// Match direction/response semantics without rejecting reserved or higher-
	// version flags. Integrity below still covers their original wire values.
	h.Flags &= FlagInitiator | FlagResponse
	expected.Flags &= FlagInitiator | FlagResponse
	if h != expected || next != PayloadSKF || h.ExchangeType == ExchangeSAInit || len(encryptionKey) != 16 || len(integrityKey) != 32 {
		return 0, nil, false, fmt.Errorf("ike: SKF does not match pending exchange")
	}
	const overhead = HeaderLen + 8 + aes.BlockSize + skICVLen
	if len(packet) < overhead+aes.BlockSize || int(binary.BigEndian.Uint16(packet[HeaderLen+2:])) != len(packet)-HeaderLen || (len(packet)-overhead)%aes.BlockSize != 0 {
		return 0, nil, false, fmt.Errorf("ike: invalid SKF framing")
	}
	number := int(binary.BigEndian.Uint16(packet[HeaderLen+4:]))
	total := int(binary.BigEndian.Uint16(packet[HeaderLen+6:]))
	first := packet[HeaderLen]
	if number < 1 || total < 1 || number > total || total > maxFragments || (number == 1 && first == 0) || (number > 1 && first != 0) {
		return 0, nil, false, fmt.Errorf("ike: invalid SKF fragment numbers or next payload")
	}
	mac := PRFSHA256(integrityKey, packet[:len(packet)-skICVLen])[:skICVLen]
	if !hmac.Equal(mac, packet[len(packet)-skICVLen:]) {
		return 0, nil, false, fmt.Errorf("ike: SKF integrity check failed")
	}
	// No attacker-controlled allocation or cache mutation occurs before integrity.
	encrypted := packet[HeaderLen+8+aes.BlockSize : len(packet)-skICVLen]
	plain := make([]byte, len(encrypted))
	defer clear(plain)
	block, _ := aes.NewCipher(encryptionKey)
	cipher.NewCBCDecrypter(block, packet[HeaderLen+8:HeaderLen+8+aes.BlockSize]).CryptBlocks(plain, encrypted)
	padding := int(plain[len(plain)-1]) + 1
	if padding > len(plain) {
		return 0, nil, false, fmt.Errorf("ike: invalid SKF padding")
	}
	chunk := plain[:len(plain)-padding]
	if len(chunk) == 0 {
		return 0, nil, false, fmt.Errorf("ike: empty SKF chunk unsupported")
	}
	if r.total != 0 && r.header != h {
		return 0, nil, false, fmt.Errorf("ike: another SKF exchange pending")
	}
	if total < r.total {
		return 0, nil, false, fmt.Errorf("ike: stale SKF fragment set")
	}
	if total == r.total && r.parts[number-1] != nil {
		if !bytes.Equal(r.parts[number-1], chunk) || number == 1 && r.first != first {
			return 0, nil, false, fmt.Errorf("ike: conflicting SKF duplicate")
		}
		return 0, nil, false, nil
	}
	oldSize := r.size
	if total > r.total {
		oldSize = 0
	}
	if len(chunk) > MaxMessageSize-oldSize {
		return 0, nil, false, fmt.Errorf("ike: SKF reassembly size exceeded")
	}
	if total > r.total {
		// A valid newer PMTU fragment set replaces the old set (RFC 7383 §2.6).
		r.Reset()
		r.header = h
		r.total = total
		r.started = now
	}
	r.parts[number-1] = bytes.Clone(chunk)
	r.size += len(chunk)
	r.received++
	if number == 1 {
		r.first = first
	}
	if r.received != r.total {
		return 0, nil, false, nil
	}
	merged := make([]byte, 0, r.size)
	for _, part := range r.parts[:r.total] {
		merged = append(merged, part...)
	}
	first = r.first
	r.Reset()
	return first, merged, true, nil
}

// AuthRequestFragments fragments the already-created IKE_AUTH request after
// bilateral negotiation. The first call fixes the datagram size; later calls
// return detached, byte-identical retransmissions. Create a fresh SA to change
// the authenticated exchange's policy. No IP/UDP/NAT-T overhead is included.
func (i *Initiator) AuthRequestFragments(maxPacket int) ([][]byte, error) {
	if i.auth == nil || i.authDone || !i.peerFragmentation {
		return nil, fmt.Errorf("ike: fragmentation not negotiated or no pending IKE_AUTH")
	}
	if i.auth.fragments == nil {
		first, plain, err := OpenSK(i.auth.request, i.init.Keys.SKEI, i.init.Keys.SKAI)
		if err != nil {
			return nil, err
		}
		defer clear(plain)
		h, _, err := DecodeHeader(i.auth.request)
		if err != nil {
			return nil, err
		}
		packets, err := SealSKF(h, first, plain, i.init.Keys.SKEI, i.init.Keys.SKAI, maxPacket, rand.Reader)
		if err != nil {
			return nil, err
		}
		i.auth.fragments = packets
	}
	packets := make([][]byte, len(i.auth.fragments))
	for n, p := range i.auth.fragments {
		packets[n] = bytes.Clone(p)
	}
	return packets, nil
}

// HandleAuthFragment accepts negotiated SKF responses. (nil, nil) means an
// authenticated fragment was buffered or duplicated; only a non-nil result
// completes IKE_AUTH. Fragment integrity is not peer identity authentication:
// the complete payload still passes the same pinned AUTH and CHILD validation.
func (i *Initiator) HandleAuthFragment(packet []byte, now time.Time) (*AuthResult, error) {
	if i.auth == nil || i.authDone || !i.peerFragmentation {
		return nil, fmt.Errorf("ike: fragmentation not negotiated or no pending IKE_AUTH")
	}
	expected := Header{InitiatorSPI: i.spi, ResponderSPI: i.init.ResponderSPI, ExchangeType: ExchangeIKEAuth, Flags: FlagResponse, MessageID: 1}
	first, plain, complete, err := i.auth.reassembly.Add(packet, expected, i.init.Keys.SKER, i.init.Keys.SKAR, now)
	if err != nil || !complete {
		return nil, err
	}
	defer clear(plain)
	return i.handleAuthPlain(first, plain)
}

// ResetAuthFragments releases an incomplete response when its transport timer
// expires. It retains the original request fragments for retransmission and
// never marks the pending IKE_AUTH exchange as authenticated.
func (i *Initiator) ResetAuthFragments() {
	if i.auth != nil {
		i.auth.reassembly.Reset()
	}
}
