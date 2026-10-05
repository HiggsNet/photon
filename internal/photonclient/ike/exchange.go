package ike

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"math"
	"time"
)

// The session has one outbound window and one inbound replay cache, shared by
// every exchange type. Counters are wider than the wire so exhaustion cannot
// wrap. Transport, deadlines and serialization remain the caller's responsibility.
type exchangeState struct {
	nextLocal, nextRemote             uint64
	pending                           []byte
	pendingKind                       uint8
	lastRequest, lastReply            []byte
	requestFragments, replyFragments  [][]byte
	fragmentRequest, fragmentResponse skfReassembly
}

const (
	exchangeLiveness uint8 = iota + 1
	exchangeChild
	exchangeDelete
	exchangeIKERekey
	exchangeIKEDelete
)

func (i *Initiator) beginExchange(exchange, kind uint8, ps []Payload) ([]byte, error) {
	if !i.authDone || i.init == nil || i.closing || i.closed {
		return nil, fmt.Errorf("ike: exchange requires completed IKE_AUTH")
	}
	if (i.dormant || i.rekeyed) && kind != exchangeIKEDelete {
		return nil, fmt.Errorf("ike: IKE SA not active after rekey")
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
	i.exchanges.requestFragments = nil
	return bytes.Clone(packet), nil
}

func (i *Initiator) sealExchange(exchange, flags uint8, id uint32, ps []Payload) ([]byte, error) {
	first, plain, err := EncodePayloads(ps)
	if err != nil {
		return nil, err
	}
	encryption, integrity := i.sendKeys()
	flags = flags&^FlagInitiator | i.localInitiatorFlag()
	return SealSK(Header{InitiatorSPI: i.spi, ResponderSPI: i.init.ResponderSPI, ExchangeType: exchange, Flags: flags, MessageID: id}, first, plain, encryption, integrity, rand.Reader)
}

// PendingRequest is the original encrypted request, suitable for exact
// retransmission for any post-AUTH exchange; returned storage is detached.
func (i *Initiator) PendingRequest() []byte { return bytes.Clone(i.exchanges.pending) }

func (i *Initiator) decodeSKExchange(packet []byte) (*ExchangeMessage, error) {
	if !i.authDone || i.init == nil {
		return nil, fmt.Errorf("ike: exchange requires completed IKE_AUTH")
	}
	h, _, err := DecodeHeader(packet)
	if err != nil {
		return nil, err
	}
	if h.InitiatorSPI != i.spi || h.ResponderSPI != i.init.ResponderSPI || h.Flags&FlagInitiator == i.localInitiatorFlag() {
		return nil, fmt.Errorf("ike: exchange does not match IKE SA")
	}
	encryption, integrity := i.receiveKeys()
	first, plain, err := OpenSK(packet, encryption, integrity)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	ps, err := DecodePayloads(first, plain)
	if err != nil {
		return nil, err
	}
	return &ExchangeMessage{owner: i, header: h, payloads: ps, identity: bytes.Clone(packet)}, nil
}

func (i *Initiator) openAuthenticated(m *ExchangeMessage, exchange uint8) (h Header, ps []Payload, cached []byte, err error) {
	if m == nil || m.owner != i || !i.authDone || m.header.ExchangeType != exchange {
		err = fmt.Errorf("ike: message does not belong to this exchange")
		return
	}
	h, ps = m.header, m.payloads
	if i.closed {
		if h.Flags&FlagResponse == 0 && bytes.Equal(m.identity, i.exchanges.lastRequest) {
			cached = bytes.Clone(i.exchanges.lastReply)
			return
		}
		err = fmt.Errorf("ike: IKE SA closed")
		return
	}
	if h.Flags&FlagResponse != 0 {
		if i.exchanges.pending == nil || uint64(h.MessageID) != i.exchanges.nextLocal || i.exchanges.pending[18] != exchange {
			err = fmt.Errorf("ike: no matching pending exchange")
		}
		return
	}
	if i.exchanges.lastRequest != nil && bytes.Equal(m.identity, i.exchanges.lastRequest) {
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
	i.exchanges.requestFragments = nil
	i.exchanges.fragmentResponse.Reset()
	i.exchanges.nextLocal++
}

func (i *Initiator) replyExchange(packet []byte, h Header, ps []Payload) ([]byte, error) {
	reply, err := i.sealExchange(h.ExchangeType, FlagInitiator|FlagResponse, h.MessageID, ps)
	if err != nil {
		return nil, err
	}
	i.exchanges.lastRequest, i.exchanges.lastReply = bytes.Clone(packet), reply
	i.exchanges.replyFragments = nil
	i.exchanges.nextRemote++
	return bytes.Clone(reply), nil
}

// ExchangeMessage is an authenticated complete message tied to one session.
// Its payload storage is opaque so inspection cannot modify what is accepted.
type ExchangeMessage struct {
	owner    *Initiator
	header   Header
	payloads []Payload
	identity []byte
}

func (m *ExchangeMessage) Header() Header { return m.header }

// DecodeExchange accepts SK or negotiated SKF after AUTH. nil,nil buffers a
// partial or repeated fragment. Completion does not consume a message ID;
// InspectChildExchange and HandleExchange revalidate the window when used.
func (i *Initiator) DecodeExchange(packet []byte, now time.Time) (*ExchangeMessage, error) {
	h, next, err := DecodeHeader(packet)
	if err != nil {
		return nil, err
	}
	if next != PayloadSKF {
		return i.decodeSKExchange(packet)
	}
	h.Flags &= FlagInitiator | FlagResponse
	if !i.authDone || i.init == nil || !i.peerFragmentation {
		return nil, fmt.Errorf("ike: post-AUTH fragmentation not negotiated")
	}
	if h.InitiatorSPI != i.spi || h.ResponderSPI != i.init.ResponderSPI || h.Flags&FlagInitiator == i.localInitiatorFlag() || (h.ExchangeType != ExchangeInformational && h.ExchangeType != ExchangeCreateChild) {
		return nil, fmt.Errorf("ike: SKF does not match IKE SA")
	}
	cache := &i.exchanges.fragmentRequest
	if h.Flags&FlagResponse != 0 {
		if i.exchanges.pending == nil || uint64(h.MessageID) != i.exchanges.nextLocal || i.exchanges.pending[18] != h.ExchangeType {
			return nil, fmt.Errorf("ike: SKF has no pending exchange")
		}
		cache = &i.exchanges.fragmentResponse
	} else if uint64(h.MessageID) != i.exchanges.nextRemote && !(i.exchanges.lastRequest != nil && uint64(h.MessageID)+1 == i.exchanges.nextRemote) {
		return nil, fmt.Errorf("ike: SKF outside inbound window")
	}
	// A newer expected request can displace an incomplete replay of the last
	// request, but only after its first fragment passes integrity validation.
	target := cache
	var replacement skfReassembly
	if cache.total != 0 && cache.header != h {
		if h.Flags&FlagResponse != 0 || uint64(h.MessageID) != i.exchanges.nextRemote {
			return nil, fmt.Errorf("ike: another SKF request is pending")
		}
		target = &replacement
	}
	encryption, integrity := i.receiveKeys()
	first, plain, complete, err := target.Add(packet, h, encryption, integrity, now)
	if err == nil && target != cache {
		cache.Reset()
		*cache = replacement
	}
	if err != nil || !complete {
		return nil, err
	}
	defer clear(plain)
	ps, err := DecodePayloads(first, plain)
	if err != nil {
		return nil, err
	}
	// A completed SKF retransmission may use a newer fragmentation boundary.
	// Canonical authenticated content, not newly generated ciphertext, identifies
	// it. SK packets retain their stricter original-wire equality behavior.
	identity, err := h.Marshal(PayloadSKF, HeaderLen)
	if err != nil {
		return nil, err
	}
	identity = append(identity, first)
	identity = append(identity, plain...)
	return &ExchangeMessage{owner: i, header: h, payloads: ps, identity: identity}, nil
}

// ExchangeResult reports one completed authenticated exchange. Reply is sent
// through ReplyPackets when a datagram budget requires negotiated fragmentation.
type ExchangeResult struct {
	Reply    []byte
	Child    *ChildExchangeResult
	Deleted  *DeleteResult
	Liveness bool
	IKE      *IKERekeyResult
}

// HandleExchange consumes an opaque message after any required policy check.
// childConfig is used only for peer CHILD requests; nil never authorizes one.
func (i *Initiator) HandleExchange(m *ExchangeMessage, childConfig *ChildExchangeConfig) (*ExchangeResult, error) {
	if m == nil || m.owner != i {
		return nil, fmt.Errorf("ike: message belongs to another session")
	}
	result := &ExchangeResult{}
	var err error
	switch m.header.ExchangeType {
	case ExchangeCreateChild:
		if m.IsIKERekey() || m.header.Flags&FlagResponse != 0 && i.exchanges.pendingKind == exchangeIKERekey {
			if m.header.Flags&FlagResponse != 0 {
				result.IKE, err = i.handleIKERekeyResponse(m)
			} else {
				result.Reply, result.IKE, err = i.handleIKERekeyRequest(m)
			}
		} else if m.header.Flags&FlagResponse != 0 {
			result.Child, err = i.handleChildResponse(m)
		} else {
			if childConfig == nil {
				return nil, fmt.Errorf("ike: CHILD request requires current caller authorization")
			}
			result.Reply, result.Child, err = i.handleChildRequest(m, *childConfig)
		}
	case ExchangeInformational:
		if isIKEDelete(m.payloads) || m.header.Flags&FlagResponse != 0 && i.exchanges.pendingKind == exchangeIKEDelete {
			result.Reply, result.Deleted, err = i.handleIKEDelete(m)
		} else if len(m.payloads) == 0 && !(m.header.Flags&FlagResponse != 0 && i.exchanges.pendingKind == exchangeDelete) {
			result.Reply, err = i.handleInformational(m)
			result.Liveness = err == nil
		} else {
			result.Reply, result.Deleted, err = i.handleChildDelete(m)
		}
	default:
		err = fmt.Errorf("ike: unsupported authenticated exchange")
	}
	if err != nil {
		return nil, err
	}
	return result, nil
}

func clonePackets(packets [][]byte) [][]byte {
	result := make([][]byte, len(packets))
	for n, p := range packets {
		result[n] = bytes.Clone(p)
	}
	return result
}

func (i *Initiator) exchangePackets(packet []byte, maxPacket int, cache *[][]byte) ([][]byte, error) {
	if len(packet) == 0 || maxPacket < HeaderLen || maxPacket > MaxMessageSize {
		return nil, fmt.Errorf("ike: invalid exchange datagram budget")
	}
	if *cache != nil {
		return clonePackets(*cache), nil
	}
	if len(packet) <= maxPacket {
		*cache = [][]byte{bytes.Clone(packet)}
		return clonePackets(*cache), nil
	}
	if !i.peerFragmentation {
		return nil, fmt.Errorf("ike: fragmentation not negotiated")
	}
	h, _, err := DecodeHeader(packet)
	if err != nil {
		return nil, err
	}
	encryption, integrity := i.sendKeys()
	first, plain, err := OpenSK(packet, encryption, integrity)
	if err != nil {
		return nil, err
	}
	defer clear(plain)
	packets, err := SealSKF(h, first, plain, encryption, integrity, maxPacket, rand.Reader)
	if err != nil {
		return nil, err
	}
	*cache = packets
	return clonePackets(packets), nil
}

// PendingRequestPackets returns the single SK or original SKF packet sequence.
// The first successful call fixes its datagram budget for all retransmissions.
func (i *Initiator) PendingRequestPackets(maxPacket int) ([][]byte, error) {
	return i.exchangePackets(i.exchanges.pending, maxPacket, &i.exchanges.requestFragments)
}

// ReplyPackets returns the current reply's cached SK/SKF sequence. A detached
// reply from HandleExchange or another handler must match the current cache.
func (i *Initiator) ReplyPackets(reply []byte, maxPacket int) ([][]byte, error) {
	if len(reply) == 0 || !bytes.Equal(reply, i.exchanges.lastReply) {
		return nil, fmt.Errorf("ike: reply no longer matches cache")
	}
	return i.exchangePackets(reply, maxPacket, &i.exchanges.replyFragments)
}

// ResetExchangeFragments discards incomplete inbound plaintext when the caller's
// transport timer expires. It does not change request IDs or retransmission data.
func (i *Initiator) ResetExchangeFragments() {
	i.exchanges.fragmentRequest.Reset()
	i.exchanges.fragmentResponse.Reset()
}

func (i *Initiator) localInitiatorFlag() uint8 {
	if i.originalResponder {
		return 0
	}
	return FlagInitiator
}
func (i *Initiator) sendKeys() ([]byte, []byte) {
	if i.originalResponder {
		return i.init.Keys.SKER, i.init.Keys.SKAR
	}
	return i.init.Keys.SKEI, i.init.Keys.SKAI
}
func (i *Initiator) receiveKeys() ([]byte, []byte) {
	if i.originalResponder {
		return i.init.Keys.SKEI, i.init.Keys.SKAI
	}
	return i.init.Keys.SKER, i.init.Keys.SKAR
}

// SPIs identifies the on-wire IKE SA independent of which endpoint initiated
// its rekey. A transport can dispatch old/new overlap without accessing keys.
func (i *Initiator) SPIs() (uint64, uint64) {
	if i.init == nil {
		return i.spi, 0
	}
	return i.spi, i.init.ResponderSPI
}

// IsIKERekey distinguishes an authenticated IKE proposal from a CHILD proposal.
// It does not validate that proposal or consume the exchange.
func (m *ExchangeMessage) IsIKERekey() bool {
	if m == nil || m.header.ExchangeType != ExchangeCreateChild {
		return false
	}
	for _, p := range m.payloads {
		if p.Type == PayloadSA && len(p.Data) >= 6 {
			return p.Data[5] == 1
		}
	}
	return false
}
