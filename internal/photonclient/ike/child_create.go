package ike

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

const ExchangeCreateChild uint8 = 36
const NotifyRekeySA uint16 = 16393
const maxChildSAs = 8

// ChildExchangeConfig uses local orientation even when the peer originates the
// exchange. RekeySPI names an existing local inbound ESP SPI (zero creates a new
// CHILD). DHGroup is zero or GroupP256. The caller authorizes these selectors.
type ChildExchangeConfig struct {
	Child    ChildConfig
	RekeySPI uint32
	DHGroup  uint16
}

type ChildExchangeResult struct {
	Child    ChildResult
	RekeySPI uint32
}

type childPending struct {
	config  ChildExchangeConfig
	nonce   []byte
	private *ecdh.PrivateKey
}

type childSA struct {
	result       ChildResult
	predecessor  uint32
	minimumNonce []byte
}

func cloneChild(c ChildResult) ChildResult {
	c.LocalSelectors = append([]TrafficSelector(nil), c.LocalSelectors...)
	c.RemoteSelectors = append([]TrafficSelector(nil), c.RemoteSelectors...)
	c.Keys.InitiatorToResponder = bytes.Clone(c.Keys.InitiatorToResponder)
	c.Keys.ResponderToInitiator = bytes.Clone(c.Keys.ResponderToInitiator)
	return c
}

func (i *Initiator) rememberChild(c ChildResult, predecessor uint32, minimumNonce []byte) {
	if i.children == nil {
		i.children = make(map[uint32]*childSA)
	}
	i.children[c.InitiatorSPI] = &childSA{result: cloneChild(c), predecessor: predecessor, minimumNonce: bytes.Clone(minimumNonce)}
}

// EncodeChildExchangeProposal adds the optional P-256 transform to the fixed
// ESP AES-GCM-16-128, no-ESN suite. The SA_INIT IKE proposal is independent.
func EncodeChildExchangeProposal(spi uint32, group uint16) ([]byte, error) {
	b, err := EncodeChildProposal(spi)
	if err != nil {
		return nil, err
	}
	if group == 0 {
		return b, nil
	}
	if group != GroupP256 {
		return nil, fmt.Errorf("ike: unsupported CHILD DH group")
	}
	b[24] = 3
	b = append(b, 0, 0, 0, 8, 4, 0, 0, byte(group))
	b[7] = 3
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b, nil
}

func decodeChildExchangeProposal(b []byte) (spi uint32, group uint16, err error) {
	fail := func() (uint32, uint16, error) { return 0, 0, fmt.Errorf("ike: unsupported CHILD exchange proposal") }
	if len(b) < 12 || b[0] != 0 || int(binary.BigEndian.Uint16(b[2:])) != len(b) || b[4] != 1 || b[5] != 3 || b[6] != 4 || b[7] < 2 || b[7] > 3 {
		return fail()
	}
	spi = binary.BigEndian.Uint32(b[8:])
	if spi < 256 {
		return fail()
	}
	rest := b[12:]
	var encryption, esn, dh bool
	for n := 0; n < int(b[7]); n++ {
		if len(rest) < 8 {
			return fail()
		}
		size := int(binary.BigEndian.Uint16(rest[2:]))
		more := byte(3)
		if n == int(b[7])-1 {
			more = 0
		}
		if rest[0] != more || size < 8 || size > len(rest) {
			return fail()
		}
		switch rest[4] {
		case 1:
			if encryption || size != 12 || binary.BigEndian.Uint16(rest[6:]) != 20 || binary.BigEndian.Uint16(rest[8:]) != 0x800e || binary.BigEndian.Uint16(rest[10:]) != 128 {
				return fail()
			}
			encryption = true
		case 5:
			if esn || size != 8 || binary.BigEndian.Uint16(rest[6:]) != 0 {
				return fail()
			}
			esn = true
		case 4:
			if dh || size != 8 {
				return fail()
			}
			group = binary.BigEndian.Uint16(rest[6:])
			if group != 0 && group != GroupP256 {
				return fail()
			}
			dh = true
		default:
			return fail()
		}
		rest = rest[size:]
	}
	if !encryption || !esn || len(rest) != 0 {
		return fail()
	}
	return spi, group, nil
}

// DeriveChildExchangeKeys follows RFC 7296 section 2.17. Directions are relative
// to the CREATE_CHILD_SA initiator; the session normalizes peer-initiated results
// back to local-to-remote and remote-to-local in ChildResult.
func DeriveChildExchangeKeys(skD, shared, ni, nr []byte) (ChildKeys, error) {
	if len(skD) != 32 || (len(shared) != 0 && len(shared) != 32) || len(ni) < 16 || len(ni) > 256 || len(nr) < 16 || len(nr) > 256 {
		return ChildKeys{}, fmt.Errorf("ike: invalid CHILD exchange key input")
	}
	seed := append(bytes.Clone(shared), ni...)
	seed = append(seed, nr...)
	material, err := PRFPlusSHA256(skD, seed, 40)
	clear(seed)
	if err != nil {
		return ChildKeys{}, err
	}
	return ChildKeys{InitiatorToResponder: material[:20:20], ResponderToInitiator: material[20:40:40]}, nil
}

func (i *Initiator) validateChildConfig(c ChildExchangeConfig) error {
	if !i.authDone || i.init == nil {
		return fmt.Errorf("ike: CHILD exchange requires IKE_AUTH")
	}
	if c.DHGroup != 0 && c.DHGroup != GroupP256 {
		return fmt.Errorf("ike: unsupported CHILD DH group")
	}
	if c.Child.InitiatorSPI < 256 || i.children[c.Child.InitiatorSPI] != nil {
		return fmt.Errorf("ike: reserved or reused inbound CHILD SPI")
	}
	reserved := 0
	if i.childPending != nil {
		reserved = 1
		if i.childPending.config.Child.InitiatorSPI == c.Child.InitiatorSPI {
			return fmt.Errorf("ike: inbound CHILD SPI reserved by pending exchange")
		}
	}
	if len(i.children)+reserved >= maxChildSAs {
		return fmt.Errorf("ike: CHILD overlap limit reached")
	}
	if _, err := EncodeTrafficSelectors(c.Child.LocalSelectors); err != nil {
		return err
	}
	if _, err := EncodeTrafficSelectors(c.Child.RemoteSelectors); err != nil {
		return err
	}
	if c.RekeySPI != 0 {
		old := i.children[c.RekeySPI]
		if old == nil {
			return fmt.Errorf("ike: unknown CHILD to rekey")
		}
		// A rekey may narrow but never expand the old SA's authorized traffic.
		if err := ValidateTrafficSelectorNarrowing(c.Child.LocalSelectors, old.result.LocalSelectors); err != nil {
			return err
		}
		if err := ValidateTrafficSelectorNarrowing(c.Child.RemoteSelectors, old.result.RemoteSelectors); err != nil {
			return err
		}
	}
	return nil
}

func childPayloads(c ChildExchangeConfig, nonce []byte, private *ecdh.PrivateKey, peerInitiated bool) ([]Payload, error) {
	sa, err := EncodeChildExchangeProposal(c.Child.InitiatorSPI, c.DHGroup)
	if err != nil {
		return nil, err
	}
	local, remote := c.Child.LocalSelectors, c.Child.RemoteSelectors
	if peerInitiated {
		local, remote = remote, local
	}
	tsi, err := EncodeTrafficSelectors(local)
	if err != nil {
		return nil, err
	}
	tsr, err := EncodeTrafficSelectors(remote)
	if err != nil {
		return nil, err
	}
	ps := []Payload{{Type: PayloadSA, Data: sa}, {Type: PayloadNonce, Data: nonce}}
	if private != nil {
		ps = append(ps, Payload{Type: PayloadKE, Data: EncodeKE(GroupP256, P256PublicKey(private))})
	}
	ps = append(ps, Payload{Type: PayloadTSi, Data: tsi}, Payload{Type: PayloadTSr, Data: tsr})
	return ps, nil
}

func newChildPending(c ChildExchangeConfig) (*childPending, error) {
	c.Child.LocalSelectors = append([]TrafficSelector(nil), c.Child.LocalSelectors...)
	c.Child.RemoteSelectors = append([]TrafficSelector(nil), c.Child.RemoteSelectors...)
	p := &childPending{config: c, nonce: make([]byte, 32)}
	if _, err := rand.Read(p.nonce); err != nil {
		return nil, err
	}
	if c.DHGroup == GroupP256 {
		var err error
		p.private, err = GenerateP256Key(rand.Reader)
		if err != nil {
			return nil, err
		}
	}
	return p, nil
}

// ChildRequest starts a fresh CHILD exchange, optionally replacing RekeySPI.
// The old SA remains usable until an explicit Delete exchange completes. Keep
// its inbound SA installed during overlap; the session never installs routes.
func (i *Initiator) ChildRequest(c ChildExchangeConfig) ([]byte, error) {
	if err := i.validateChildConfig(c); err != nil {
		return nil, err
	}
	p, err := newChildPending(c)
	if err != nil {
		return nil, err
	}
	ps, err := childPayloads(c, p.nonce, p.private, false)
	if err != nil {
		return nil, err
	}
	if c.RekeySPI != 0 {
		spi := binary.BigEndian.AppendUint32(nil, c.RekeySPI)
		n, _ := EncodeNotify(Notify{Protocol: 3, Type: NotifyRekeySA, SPI: spi})
		ps = append([]Payload{{Type: PayloadNotify, Data: n}}, ps...)
	}
	packet, err := i.beginExchange(ExchangeCreateChild, exchangeChild, ps)
	if err != nil {
		return nil, err
	}
	i.childPending = p
	return packet, nil
}

type childOffer struct {
	spi, rekeySPI uint32
	group         uint16
	nonce, ke     []byte
	tsi, tsr      []TrafficSelector
}

func parseChildOffer(ps []Payload) (childOffer, error) {
	var o childOffer
	var sa, nonce, tsi, tsr bool
	var err error
	for _, p := range ps {
		switch p.Type {
		case PayloadSA:
			o.spi, o.group, err = decodeChildExchangeProposal(p.Data)
			sa = true
		case PayloadNonce:
			o.nonce, err = DecodeNonce(p.Data)
			nonce = true
		case PayloadKE:
			_, o.ke, err = DecodeKE(p.Data)
		case PayloadTSi:
			o.tsi, err = DecodeTrafficSelectors(p.Data)
			tsi = true
		case PayloadTSr:
			o.tsr, err = DecodeTrafficSelectors(p.Data)
			tsr = true
		case PayloadNotify:
			var n Notify
			n, err = DecodeNotify(p.Data)
			if err == nil {
				switch n.Type {
				case NotifyRekeySA:
					if n.Protocol != 3 || len(n.SPI) != 4 || len(n.Data) != 0 || o.rekeySPI != 0 {
						err = fmt.Errorf("ike: invalid REKEY_SA notification")
					} else {
						o.rekeySPI = binary.BigEndian.Uint32(n.SPI)
						if o.rekeySPI < 256 {
							err = fmt.Errorf("ike: reserved REKEY_SA SPI")
						}
					}
				case 16394:
					if n.Protocol != 0 || len(n.SPI) != 0 || len(n.Data) != 0 {
						err = fmt.Errorf("ike: invalid ESP_TFC_PADDING_NOT_SUPPORTED")
					}
				default:
					err = fmt.Errorf("ike: unsupported CHILD notification %d", n.Type)
				}
			}
		default:
			err = fmt.Errorf("ike: unsupported CHILD payload %d", p.Type)
		}
		if err != nil {
			return childOffer{}, err
		}
	}
	if !sa || !nonce || !tsi || !tsr || (o.group == 0) != (len(o.ke) == 0) {
		return childOffer{}, fmt.Errorf("ike: incomplete CHILD offer or mismatched KE")
	}
	return o, nil
}

func (i *Initiator) checkPeerChildSPI(spi uint32) error {
	for _, c := range i.children {
		if c.result.ResponderSPI == spi {
			return fmt.Errorf("ike: reused peer inbound CHILD SPI")
		}
	}
	return nil
}

func finishChild(p *childPending, o childOffer, peerInitiated bool, skD []byte) (ChildResult, []byte, error) {
	local, remote := o.tsi, o.tsr
	if peerInitiated {
		local, remote = remote, local
	}
	if o.group != p.config.DHGroup {
		return ChildResult{}, nil, fmt.Errorf("ike: unoffered CHILD DH group")
	}
	if err := ValidateTrafficSelectorNarrowing(local, p.config.Child.LocalSelectors); err != nil {
		return ChildResult{}, nil, err
	}
	if err := ValidateTrafficSelectorNarrowing(remote, p.config.Child.RemoteSelectors); err != nil {
		return ChildResult{}, nil, err
	}
	var shared []byte
	var err error
	if p.private != nil {
		shared, err = P256SharedSecret(p.private, o.ke)
		if err != nil {
			return ChildResult{}, nil, err
		}
		defer clear(shared)
	}
	ni, nr := p.nonce, o.nonce
	if peerInitiated {
		ni, nr = nr, ni
	}
	keys, err := DeriveChildExchangeKeys(skD, shared, ni, nr)
	if err != nil {
		return ChildResult{}, nil, err
	}
	if peerInitiated {
		keys.InitiatorToResponder, keys.ResponderToInitiator = keys.ResponderToInitiator, keys.InitiatorToResponder
	}
	minimum := ni
	if bytes.Compare(nr, minimum) < 0 {
		minimum = nr
	}
	return ChildResult{InitiatorSPI: p.config.Child.InitiatorSPI, ResponderSPI: o.spi, LocalSelectors: local, RemoteSelectors: remote, Keys: keys}, minimum, nil
}

func (i *Initiator) HandleChildResponse(packet []byte) (*ChildExchangeResult, error) {
	h, ps, _, err := i.openExchange(packet, ExchangeCreateChild)
	if err != nil {
		return nil, err
	}
	if h.Flags&FlagResponse == 0 || i.exchanges.pendingKind != exchangeChild || i.childPending == nil {
		return nil, fmt.Errorf("ike: no matching pending CHILD exchange")
	}
	o, err := parseChildOffer(ps)
	if err != nil {
		return nil, err
	}
	if o.rekeySPI != 0 {
		return nil, fmt.Errorf("ike: unexpected REKEY_SA in response")
	}
	if err := i.checkPeerChildSPI(o.spi); err != nil {
		return nil, err
	}
	p := i.childPending
	result, minimum, err := finishChild(p, o, false, i.init.Keys.SKD)
	if err != nil {
		return nil, err
	}
	i.rememberChild(result, p.config.RekeySPI, minimum)
	i.childPending = nil
	i.completeExchange()
	return &ChildExchangeResult{Child: result, RekeySPI: p.config.RekeySPI}, nil
}

// HandleChildRequest answers a peer-initiated CHILD exchange using an explicit
// caller-authorized configuration. Duplicate requests return the original
// encrypted response with nil result so the caller must not install twice.
func (i *Initiator) HandleChildRequest(packet []byte, c ChildExchangeConfig) ([]byte, *ChildExchangeResult, error) {
	h, ps, cached, err := i.openExchange(packet, ExchangeCreateChild)
	if err != nil {
		return nil, nil, err
	}
	if h.Flags&FlagResponse != 0 {
		return nil, nil, fmt.Errorf("ike: expected CHILD request")
	}
	if cached != nil {
		return cached, nil, nil
	}
	if err := i.validateChildConfig(c); err != nil {
		return nil, nil, err
	}
	o, err := parseChildOffer(ps)
	if err != nil {
		return nil, nil, err
	}
	if err := i.checkPeerChildSPI(o.spi); err != nil {
		return nil, nil, err
	}
	if c.RekeySPI == 0 && o.rekeySPI != 0 || c.RekeySPI != 0 && i.children[c.RekeySPI].result.ResponderSPI != o.rekeySPI {
		return nil, nil, fmt.Errorf("ike: REKEY_SA does not identify authorized CHILD")
	}
	// Policy must fit the peer offer; responding never echoes a wider proposal.
	if err := ValidateTrafficSelectorNarrowing(c.Child.LocalSelectors, o.tsr); err != nil {
		return nil, nil, err
	}
	if err := ValidateTrafficSelectorNarrowing(c.Child.RemoteSelectors, o.tsi); err != nil {
		return nil, nil, err
	}
	p, err := newChildPending(c)
	if err != nil {
		return nil, nil, err
	}
	// Derivation validates the peer KE; selectors in the result are our selection.
	o.tsr, o.tsi = c.Child.LocalSelectors, c.Child.RemoteSelectors
	result, minimum, err := finishChild(p, o, true, i.init.Keys.SKD)
	if err != nil {
		return nil, nil, err
	}
	responsePS, err := childPayloads(c, p.nonce, p.private, true)
	if err != nil {
		return nil, nil, err
	}
	reply, err := i.replyExchange(packet, h, responsePS)
	if err != nil {
		return nil, nil, err
	}
	i.rememberChild(result, c.RekeySPI, minimum)
	return reply, &ChildExchangeResult{Child: result, RekeySPI: c.RekeySPI}, nil
}
