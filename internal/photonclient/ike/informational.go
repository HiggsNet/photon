package ike

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
)

const ExchangeInformational uint8 = 37

// Request counters belong to the original sender and are independent in each
// direction. A wider counter represents exhaustion without wrapping to zero.
type informationalState struct {
	nextLocal, nextRemote  uint64
	pending                []byte
	lastRequest, lastReply []byte
}

// InformationalRequest begins one authenticated empty liveness exchange after
// IKE_AUTH. The caller owns scheduling, deadlines and endpoint validation, and
// must serialize all Initiator calls. A timeout requires abandoning this SA;
// it must not free the pending slot or skip the unanswered message ID.
func (i *Initiator) InformationalRequest() ([]byte, error) {
	if !i.authDone || i.init == nil {
		return nil, fmt.Errorf("ike: INFORMATIONAL requires completed IKE_AUTH")
	}
	if i.info.pending != nil {
		return nil, fmt.Errorf("ike: INFORMATIONAL already pending")
	}
	if i.info.nextLocal > math.MaxUint32 {
		return nil, fmt.Errorf("ike: local message ID exhausted; replace IKE SA")
	}
	packet, err := SealSK(Header{InitiatorSPI: i.spi, ResponderSPI: i.init.ResponderSPI,
		ExchangeType: ExchangeInformational, Flags: FlagInitiator, MessageID: uint32(i.info.nextLocal)},
		0, nil, i.init.Keys.SKEI, i.init.Keys.SKAI, rand.Reader)
	if err != nil {
		return nil, err
	}
	i.info.pending = packet
	return bytes.Clone(packet), nil
}

// PendingInformationalRequest returns a detached copy of the original encrypted
// request for byte-identical retransmission, or nil when no exchange is pending.
func (i *Initiator) PendingInformationalRequest() []byte {
	return bytes.Clone(i.info.pending)
}

// HandleInformational accepts only authenticated empty INFORMATIONAL messages.
// A non-nil result is a reply to send (including a cached reply to a duplicate
// request); nil with no error completes the pending local liveness exchange.
// Delete, rekey, notifications and peer window changes are unsupported. Invalid
// messages never consume an ID, complete a pending exchange or replace a cache.
func (i *Initiator) HandleInformational(packet []byte) ([]byte, error) {
	if !i.authDone || i.init == nil {
		return nil, fmt.Errorf("ike: INFORMATIONAL requires completed IKE_AUTH")
	}
	h, _, err := DecodeHeader(packet)
	if err != nil {
		return nil, err
	}
	if h.InitiatorSPI != i.spi || h.ResponderSPI != i.init.ResponderSPI || h.ExchangeType != ExchangeInformational || h.Flags&FlagInitiator != 0 {
		return nil, fmt.Errorf("ike: INFORMATIONAL does not match IKE SA")
	}
	first, plain, err := OpenSK(packet, i.init.Keys.SKER, i.init.Keys.SKAR)
	if err != nil {
		return nil, err
	}
	if first != 0 || len(plain) != 0 {
		return nil, fmt.Errorf("ike: nonempty INFORMATIONAL unsupported")
	}
	if h.Flags&FlagResponse != 0 {
		if i.info.pending == nil || uint64(h.MessageID) != i.info.nextLocal {
			return nil, fmt.Errorf("ike: no matching INFORMATIONAL request")
		}
		i.info.pending = nil
		i.info.nextLocal++
		return nil, nil
	}
	// Authentication precedes duplicate handling. Only the last exact request
	// can reuse its encrypted response; the cache is bounded to one exchange.
	if i.info.lastRequest != nil && bytes.Equal(packet, i.info.lastRequest) {
		return bytes.Clone(i.info.lastReply), nil
	}
	if i.info.nextRemote > math.MaxUint32 || uint64(h.MessageID) != i.info.nextRemote {
		return nil, fmt.Errorf("ike: unexpected responder INFORMATIONAL message ID")
	}
	// I is the original IKE initiator bit, including in replies to requests
	// that the original responder originated (RFC 7296 section 3.1).
	reply, err := SealSK(Header{InitiatorSPI: i.spi, ResponderSPI: i.init.ResponderSPI,
		ExchangeType: ExchangeInformational, Flags: FlagInitiator | FlagResponse, MessageID: h.MessageID},
		0, nil, i.init.Keys.SKEI, i.init.Keys.SKAI, rand.Reader)
	if err != nil {
		return nil, err
	}
	i.info.lastRequest, i.info.lastReply = bytes.Clone(packet), reply
	i.info.nextRemote++
	return bytes.Clone(reply), nil
}
