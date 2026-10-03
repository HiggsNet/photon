package ike

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"net/netip"
)

// Initiator owns one SA_INIT followed by IKE_AUTH. Its caller owns transport,
// deadlines and serialization. SA_INIT remains unauthenticated; no traffic or
// route may be authorized until IKE_AUTH and the caller's current policy pass.
type Initiator struct {
	spi            uint64
	nonce, request []byte
	private        *ecdh.PrivateKey
	init           *InitResult
	peerEd25519    bool
	auth           *authPending
	authDone       bool
	local, remote  netip.AddrPort
}

type InitResult struct {
	ResponderSPI uint64
	Nonce        []byte
	Keys         IKEKeys
	Response     []byte
	NAT          NATStatus
}

func NewInitiator() (*Initiator, error) {
	return newInitiator(netip.AddrPort{}, netip.AddrPort{})
}

// NewInitiatorWithEndpoints enables NAT detection using the actual UDP endpoints
// of SA_INIT. The transport owner must enforce the response's source endpoint.
func NewInitiatorWithEndpoints(local, remote netip.AddrPort) (*Initiator, error) {
	if !validNATEndpoint(local) || !validNATEndpoint(remote) || local.Addr().Unmap().Is4() != remote.Addr().Unmap().Is4() {
		return nil, fmt.Errorf("ike: invalid or mixed-family NAT detection endpoints")
	}
	return newInitiator(local, remote)
}

func newInitiator(local, remote netip.AddrPort) (*Initiator, error) {
	key, err := GenerateP256Key(rand.Reader)
	if err != nil {
		return nil, err
	}
	i := &Initiator{private: key, nonce: make([]byte, 32), local: local, remote: remote}
	var spi [8]byte
	for i.spi == 0 {
		if _, err := rand.Read(spi[:]); err != nil {
			return nil, err
		}
		i.spi = binary.BigEndian.Uint64(spi[:])
	}
	if _, err := rand.Read(i.nonce); err != nil {
		return nil, err
	}
	ps := []Payload{
		{Type: PayloadSA, Data: DefaultIKEProposal()},
		{Type: PayloadKE, Data: EncodeKE(GroupP256, P256PublicKey(key))},
		{Type: PayloadNonce, Data: i.nonce},
	}
	if local.IsValid() {
		ps = append(ps, natPayload(NotifyNATDetectionSource, i.spi, 0, local), natPayload(NotifyNATDetectionDestination, i.spi, 0, remote))
	}
	ps = append(ps, Payload{Type: PayloadNotify, Data: []byte{0, 0, 0x40, 0x2f, 0, 5}})
	i.request, err = EncodeMessage(Header{InitiatorSPI: i.spi, ExchangeType: ExchangeSAInit, Flags: FlagInitiator}, ps)
	if err != nil {
		return nil, err
	}
	return i, nil
}

// Request returns a detached transcript, also suitable for retransmission.
func (i *Initiator) Request() []byte { return append([]byte(nil), i.request...) }

func (i *Initiator) HandleInitResponse(packet []byte) (*InitResult, error) {
	if i.private == nil {
		return nil, fmt.Errorf("ike: SA_INIT already completed")
	}
	h, ps, err := DecodeMessage(packet)
	if err != nil {
		return nil, err
	}
	if h.InitiatorSPI != i.spi || h.ResponderSPI == 0 || h.ExchangeType != ExchangeSAInit || h.MessageID != 0 || h.Flags&FlagResponse == 0 || h.Flags&FlagInitiator != 0 {
		return nil, fmt.Errorf("ike: response does not match pending SA_INIT")
	}
	var sa, ke, nonce []byte
	var peerEd25519, seenHashes bool
	for _, p := range ps {
		switch p.Type {
		case PayloadSA:
			sa = p.Data
		case PayloadKE:
			_, ke, err = DecodeKE(p.Data)
		case PayloadNonce:
			nonce, err = DecodeNonce(p.Data)
		case PayloadNotify:
			var n Notify
			n, err = DecodeNotify(p.Data)
			if err == nil && (len(n.SPI) != 0 || n.Type < 16384 || n.Type == 16390) {
				err = fmt.Errorf("ike: unsupported SA_INIT notification %d", n.Type)
			}
			if err == nil && n.Type == 16431 {
				if seenHashes || len(n.Data) == 0 || len(n.Data)%2 != 0 {
					err = fmt.Errorf("ike: invalid signature hash algorithms notification")
				} else {
					seenHashes = true
					for j := 0; j < len(n.Data); j += 2 {
						peerEd25519 = peerEd25519 || binary.BigEndian.Uint16(n.Data[j:]) == 5
					}
				}
			}
		case PayloadVendor:
		default:
			if p.Critical || (p.Type >= 33 && p.Type <= 48) {
				err = fmt.Errorf("ike: unexpected SA_INIT payload %d", p.Type)
			}
		}
		if err != nil {
			return nil, err
		}
	}
	if err := ValidateIKESelection(sa); err != nil {
		return nil, err
	}
	if len(ke) == 0 || len(nonce) == 0 {
		return nil, fmt.Errorf("ike: incomplete SA_INIT response")
	}
	nat, err := checkNAT(ps, h, i.local, i.remote)
	if err != nil {
		return nil, err
	}
	shared, err := P256SharedSecret(i.private, ke)
	if err != nil {
		return nil, err
	}
	keys, err := DeriveIKEKeys(shared, i.nonce, nonce, i.spi, h.ResponderSPI)
	clear(shared)
	if err != nil {
		return nil, err
	}
	i.private = nil
	i.peerEd25519 = peerEd25519
	i.init = &InitResult{ResponderSPI: h.ResponderSPI, Nonce: nonce, Keys: keys, Response: append([]byte(nil), packet...), NAT: nat}
	return cloneInitResult(i.init), nil
}
