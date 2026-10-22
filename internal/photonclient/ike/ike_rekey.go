package ike

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
)

type ikeRekeyPending struct {
	spi     uint64
	nonce   []byte
	private *ecdh.PrivateKey
}
type ikeRekeyCandidate struct {
	session        *Initiator
	minimumNonce   []byte
	localInitiated bool
}

// IKERekeyResult exposes the newly keyed session without transferring CHILDs.
// The old owner must resolve collisions and call AdoptIKERekey before using it.
type IKERekeyResult struct{ Session *Initiator }

type IKERekeyResolution struct {
	Surviving, Redundant                *Initiator
	Pending, DeleteOld, DeleteRedundant bool
}

func EncodeIKERekeyProposal(spi uint64) ([]byte, error) {
	if spi == 0 {
		return nil, fmt.Errorf("ike: zero IKE rekey SPI")
	}
	original := DefaultIKEProposal()
	b := append(bytes.Clone(original[:8]), binary.BigEndian.AppendUint64(nil, spi)...)
	b = append(b, original[8:]...)
	b[6] = 8
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b, nil
}

func decodeIKERekeyProposal(b []byte) (uint64, error) {
	if len(b) < 16 || b[6] != 8 || int(binary.BigEndian.Uint16(b[2:])) != len(b) {
		return 0, fmt.Errorf("ike: invalid IKE rekey proposal")
	}
	spi := binary.BigEndian.Uint64(b[8:])
	if spi == 0 {
		return 0, fmt.Errorf("ike: zero IKE rekey SPI")
	}
	initial := append(bytes.Clone(b[:8]), b[16:]...)
	initial[6] = 0
	binary.BigEndian.PutUint16(initial[2:], uint16(len(initial)))
	if err := ValidateIKESelection(initial); err != nil {
		return 0, err
	}
	return spi, nil
}

// DeriveRekeyIKEKeys uses the old SK_d PRF and fresh mandatory P-256 secret;
// unlike SA_INIT, its SKEYSEED is prf(old SK_d, shared | Ni | Nr).
func DeriveRekeyIKEKeys(oldSKD, shared, ni, nr []byte, si, sr uint64) (IKEKeys, error) {
	if len(oldSKD) != 32 || len(shared) != 32 || len(ni) < 16 || len(ni) > 256 || len(nr) < 16 || len(nr) > 256 || si == 0 || sr == 0 {
		return IKEKeys{}, fmt.Errorf("ike: invalid IKE rekey key input")
	}
	nonces := append(bytes.Clone(ni), nr...)
	input := append(bytes.Clone(shared), nonces...)
	skeyseed := PRFSHA256(oldSKD, input)
	defer clear(input)
	defer clear(skeyseed)
	seed := binary.BigEndian.AppendUint64(nonces, si)
	seed = binary.BigEndian.AppendUint64(seed, sr)
	material, err := PRFPlusSHA256(skeyseed, seed, 192)
	if err != nil {
		return IKEKeys{}, err
	}
	return IKEKeys{SKD: material[:32:32], SKAI: material[32:64:64], SKAR: material[64:96:96], SKEI: material[96:112:112], SKER: material[112:128:128], SKPI: material[128:160:160], SKPR: material[160:192:192]}, nil
}

func (i *Initiator) newIKERekeyPending() (*ikeRekeyPending, error) {
	p := &ikeRekeyPending{nonce: make([]byte, 32)}
	var spi [8]byte
	for p.spi == 0 || i.ikeSPIInUse(p.spi) {
		if _, err := rand.Read(spi[:]); err != nil {
			return nil, err
		}
		p.spi = binary.BigEndian.Uint64(spi[:])
	}
	if _, err := rand.Read(p.nonce); err != nil {
		return nil, err
	}
	var err error
	p.private, err = GenerateP256Key(rand.Reader)
	return p, err
}

func ikeRekeyPayloads(p *ikeRekeyPending) []Payload {
	sa, _ := EncodeIKERekeyProposal(p.spi)
	return []Payload{{Type: PayloadSA, Data: sa}, {Type: PayloadNonce, Data: p.nonce}, {Type: PayloadKE, Data: EncodeKE(GroupP256, P256PublicKey(p.private))}}
}

func (i *Initiator) IKERekeyRequest() ([]byte, error) {
	if !i.authDone || i.init == nil || i.localRekey != nil || i.peerRekey != nil || i.closed || i.closing {
		return nil, fmt.Errorf("ike: IKE rekey cannot start in current state")
	}
	p, err := i.newIKERekeyPending()
	if err != nil {
		return nil, err
	}
	packet, err := i.beginExchange(ExchangeCreateChild, exchangeIKERekey, ikeRekeyPayloads(p))
	if err != nil {
		return nil, err
	}
	i.ikePending = p
	return packet, nil
}

type ikeRekeyOffer struct {
	spi            uint64
	nonce, ke      []byte
	proposalNumber uint8
	keGroup        uint16
}

func parseIKERekeyOffer(ps []Payload) (ikeRekeyOffer, error) {
	return parseIKERekeyPayloads(ps, false)
}

func parseIKERekeyPayloads(ps []Payload, request bool) (ikeRekeyOffer, error) {
	var o ikeRekeyOffer
	var sa []byte
	var err error
	for _, p := range ps {
		switch p.Type {
		case PayloadSA:
			sa = p.Data
		case PayloadNonce:
			o.nonce, err = DecodeNonce(p.Data)
		case PayloadKE:
			if request {
				o.keGroup, o.ke, err = rawRequestKE(p.Data)
			} else {
				o.keGroup, o.ke, err = DecodeKE(p.Data)
			}
		default:
			err = fmt.Errorf("ike: unsupported IKE rekey payload %d", p.Type)
		}
		if err != nil {
			return o, err
		}
	}
	if len(sa) == 0 || len(o.nonce) == 0 || len(o.ke) == 0 {
		return o, fmt.Errorf("ike: incomplete IKE rekey")
	}
	if request {
		o.spi, o.proposalNumber, err = selectIKERekeyOffer(sa)
	} else {
		o.spi, err = decodeIKERekeyProposal(sa)
		o.proposalNumber = 1
	}
	if err != nil {
		return o, err
	}
	return o, nil
}

func (i *Initiator) finishIKERekey(p *ikeRekeyPending, o ikeRekeyOffer, peerInitiated bool) (*ikeRekeyCandidate, error) {
	if o.spi == p.spi || i.ikeSPIInUse(o.spi) {
		return nil, fmt.Errorf("ike: reused IKE rekey SPI")
	}
	shared, err := P256SharedSecret(p.private, o.ke)
	if err != nil {
		return nil, err
	}
	defer clear(shared)
	si, sr, ni, nr := p.spi, o.spi, p.nonce, o.nonce
	if peerInitiated {
		si, sr, ni, nr = o.spi, p.spi, o.nonce, p.nonce
	}
	keys, err := DeriveRekeyIKEKeys(i.init.Keys.SKD, shared, ni, nr, si, sr)
	if err != nil {
		return nil, err
	}
	session := &Initiator{spi: si, init: &InitResult{ResponderSPI: sr, Keys: keys, NAT: i.init.NAT}, authDone: true, peerFragmentation: i.peerFragmentation, originalResponder: peerInitiated, dormant: true, local: i.local, remote: i.remote}
	minimum := ni
	if bytes.Compare(nr, minimum) < 0 {
		minimum = nr
	}
	return &ikeRekeyCandidate{session: session, minimumNonce: bytes.Clone(minimum), localInitiated: !peerInitiated}, nil
}

func (i *Initiator) HandleIKERekeyResponse(packet []byte) (*IKERekeyResult, error) {
	m, err := i.decodeSKExchange(packet)
	if err != nil {
		return nil, err
	}
	return i.handleIKERekeyResponse(m)
}
func (i *Initiator) handleIKERekeyResponse(m *ExchangeMessage) (*IKERekeyResult, error) {
	h, ps, _, err := i.openAuthenticated(m, ExchangeCreateChild)
	if err != nil {
		return nil, err
	}
	if h.Flags&FlagResponse == 0 || i.exchanges.pendingKind != exchangeIKERekey || i.ikePending == nil {
		return nil, fmt.Errorf("ike: no pending IKE rekey")
	}
	if refusal, err := childRefusal(ps, 0); err != nil {
		return nil, err
	} else if refusal != nil {
		refusal.IKERekey = true
		i.ikePending = nil
		i.completeExchange()
		return nil, refusal
	}
	o, err := parseIKERekeyOffer(ps)
	if err != nil {
		return nil, err
	}
	candidate, err := i.finishIKERekey(i.ikePending, o, false)
	if err != nil {
		return nil, err
	}
	i.localRekey = candidate
	i.ikePending = nil
	i.completeExchange()
	return &IKERekeyResult{Session: candidate.session}, nil
}

func (i *Initiator) HandleIKERekeyRequest(packet []byte) ([]byte, *IKERekeyResult, error) {
	m, err := i.decodeSKExchange(packet)
	if err != nil {
		return nil, nil, err
	}
	return i.handleIKERekeyRequest(m)
}
func (i *Initiator) handleIKERekeyRequest(m *ExchangeMessage) ([]byte, *IKERekeyResult, error) {
	h, ps, cached, err := i.openAuthenticated(m, ExchangeCreateChild)
	if err != nil {
		return nil, nil, err
	}
	if h.Flags&FlagResponse != 0 {
		return nil, nil, fmt.Errorf("ike: expected IKE rekey request")
	}
	if cached != nil {
		return cached, nil, nil
	}
	o, err := parseIKERekeyPayloads(ps, true)
	if err != nil {
		return nil, nil, err
	}
	// Simultaneous IKE rekeys are supported. CHILD exchanges and an already
	// completed rekey must finish/close before another IKE rekey can proceed.
	if i.closing || i.rekeyed || i.dormant || i.localRekey != nil || i.peerRekey != nil || i.exchanges.pending != nil && i.exchanges.pendingKind != exchangeIKERekey {
		notice, _ := EncodeNotify(Notify{Type: NotifyTemporaryFailure})
		reply, err := i.replyExchange(m.identity, h, []Payload{{Type: PayloadNotify, Data: notice}})
		return reply, nil, err
	}
	if o.keGroup != GroupP256 {
		reply, err := i.replyInvalidKE(m, h, GroupP256)
		return reply, nil, err
	}
	p, err := i.newIKERekeyPending()
	if err != nil {
		return nil, nil, err
	}
	candidate, err := i.finishIKERekey(p, o, true)
	if err != nil {
		return nil, nil, err
	}
	responsePS := ikeRekeyPayloads(p)
	responsePS[0].Data[4] = o.proposalNumber
	reply, err := i.replyExchange(m.identity, h, responsePS)
	if err != nil {
		return nil, nil, err
	}
	i.peerRekey = candidate
	return reply, &IKERekeyResult{Session: candidate.session}, nil
}

func (i *Initiator) ResolveIKERekey() (*IKERekeyResolution, error) {
	result := &IKERekeyResolution{}
	if i.ikePending != nil {
		result.Pending = true
		return result, nil
	}
	survivor, other := i.localRekey, i.peerRekey
	if survivor == nil {
		survivor, other = other, nil
	}
	if survivor == nil {
		return nil, fmt.Errorf("ike: no completed IKE rekey")
	}
	if other != nil {
		comparison := compareRekeyNonce(survivor.minimumNonce, other.minimumNonce)
		if comparison == 0 {
			return nil, fmt.Errorf("ike: equal IKE rekey nonces; reauthenticate")
		}
		if comparison < 0 {
			survivor, other = other, survivor
		}
		result.Redundant = other.session
		result.DeleteRedundant = other.localInitiated
	}
	result.Surviving = survivor.session
	result.DeleteOld = survivor.localInitiated
	return result, nil
}

// AdoptIKERekey transfers sole CHILD ownership to the resolved surviving SA.
// The old and redundant sessions remain solely for closing/retransmission.
// The transport must retain their SPI dispatch until their closing timeout.
func (i *Initiator) AdoptIKERekey() (*IKERekeyResolution, error) {
	result, err := i.ResolveIKERekey()
	if err != nil {
		return nil, err
	}
	if result.Pending {
		return nil, fmt.Errorf("ike: simultaneous rekey still pending")
	}
	if i.rekeyed {
		return result, nil
	}
	if i.exchanges.pending != nil {
		return nil, fmt.Errorf("ike: old SA still has a pending exchange")
	}
	if len(result.Surviving.children) != 0 {
		return nil, fmt.Errorf("ike: successor already owns CHILDs")
	}
	result.Surviving.children = i.children
	i.children = nil
	result.Surviving.dormant = false
	i.rekeyed = true
	return result, nil
}

func (i *Initiator) ikeSPIInUse(spi uint64) bool {
	if spi == i.spi || spi == i.init.ResponderSPI {
		return true
	}
	if i.ikePending != nil && spi == i.ikePending.spi {
		return true
	}
	for _, candidate := range []*ikeRekeyCandidate{i.localRekey, i.peerRekey} {
		if candidate != nil {
			si, sr := candidate.session.SPIs()
			if spi == si || spi == sr {
				return true
			}
		}
	}
	return false
}
