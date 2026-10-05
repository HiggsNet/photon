package ike

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
)

// The session has one outbound window and one inbound replay cache, shared by
// every exchange type. Counters are wider than the wire so exhaustion cannot
// wrap. Transport, deadlines and serialization remain the caller's responsibility.
type exchangeState struct {
	nextLocal, nextRemote  uint64
	pending                []byte
	pendingKind            uint8
	lastRequest, lastReply []byte
}

const (
	exchangeLiveness uint8 = iota + 1
	exchangeChild
	exchangeDelete
	exchangeIKERekey
)

func (i *Initiator) beginExchange(exchange, kind uint8, ps []Payload) ([]byte, error) {
	if !i.authDone || i.init == nil {
		return nil, fmt.Errorf("ike: exchange requires completed IKE_AUTH")
	}
	if i.exchanges.pending != nil {
		return nil, fmt.Errorf("ike: exchange already pending")
	}
	if i.exchanges.nextLocal > math.MaxUint32 {
		return nil, fmt.Errorf("ike: local message ID exhausted; replace IKE SA")
	}
	packet, err := i.sealExchange(exchange, FlagInitiator, uint32(i.exchanges.nextLocal), ps)
	if err != nil {
		return nil, err
	}
	i.exchanges.pending, i.exchanges.pendingKind = packet, kind
	return bytes.Clone(packet), nil
}

func (i *Initiator) sealExchange(exchange, flags uint8, id uint32, ps []Payload) ([]byte, error) {
	first, plain, err := EncodePayloads(ps)
	if err != nil {
		return nil, err
	}
	return SealSK(Header{InitiatorSPI: i.spi, ResponderSPI: i.init.ResponderSPI, ExchangeType: exchange, Flags: flags, MessageID: id}, first, plain, i.init.Keys.SKEI, i.init.Keys.SKAI, rand.Reader)
}

// PendingRequest is the original encrypted request, suitable for exact
// retransmission for any post-AUTH exchange; returned storage is detached.
func (i *Initiator) PendingRequest() []byte { return bytes.Clone(i.exchanges.pending) }

// openExchange authenticates before examining inner content or replay state.
// cached is non-nil only for a byte-identical retransmitted peer request.
func (i *Initiator) openExchange(packet []byte, exchange uint8) (h Header, ps []Payload, cached []byte, err error) {
	if !i.authDone || i.init == nil {
		err = fmt.Errorf("ike: exchange requires completed IKE_AUTH")
		return
	}
	h, _, err = DecodeHeader(packet)
	if err != nil {
		return
	}
	if h.InitiatorSPI != i.spi || h.ResponderSPI != i.init.ResponderSPI || h.ExchangeType != exchange || h.Flags&FlagInitiator != 0 {
		err = fmt.Errorf("ike: exchange does not match IKE SA")
		return
	}
	var first uint8
	var plain []byte
	first, plain, err = OpenSK(packet, i.init.Keys.SKER, i.init.Keys.SKAR)
	if err != nil {
		return
	}
	ps, err = DecodePayloads(first, plain)
	if err != nil {
		return
	}
	if h.Flags&FlagResponse != 0 {
		if i.exchanges.pending == nil || uint64(h.MessageID) != i.exchanges.nextLocal || i.exchanges.pending[18] != exchange {
			err = fmt.Errorf("ike: no matching pending exchange")
		}
		return
	}
	if i.exchanges.lastRequest != nil && bytes.Equal(packet, i.exchanges.lastRequest) {
		cached = bytes.Clone(i.exchanges.lastReply)
		return
	}
	if i.exchanges.nextRemote > math.MaxUint32 || uint64(h.MessageID) != i.exchanges.nextRemote {
		err = fmt.Errorf("ike: unexpected peer message ID")
	}
	return
}

func (i *Initiator) completeExchange() {
	i.exchanges.pending = nil
	i.exchanges.pendingKind = 0
	i.exchanges.nextLocal++
}

func (i *Initiator) replyExchange(packet []byte, h Header, ps []Payload) ([]byte, error) {
	reply, err := i.sealExchange(h.ExchangeType, FlagInitiator|FlagResponse, h.MessageID, ps)
	if err != nil {
		return nil, err
	}
	i.exchanges.lastRequest, i.exchanges.lastReply = bytes.Clone(packet), reply
	i.exchanges.nextRemote++
	return bytes.Clone(reply), nil
}
