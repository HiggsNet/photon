package ike

// Independently implemented from RFC 7296 sections 2.15 and 3.5, RFC 7427,
// and RFC 8420. Trust and route policy are supplied by the caller, not learned
// from the unauthenticated exchange or certificates sent by the peer.
import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
)

const (
	PayloadIDi      uint8 = 35
	PayloadIDr      uint8 = 36
	PayloadAUTH     uint8 = 39
	PayloadTSi      uint8 = 44
	PayloadTSr      uint8 = 45
	ExchangeIKEAuth uint8 = 35
)

type ChildConfig struct {
	InitiatorSPI                    uint32
	LocalSelectors, RemoteSelectors []TrafficSelector
}

// AuthConfig is a snapshot of caller-authorized identity and traffic policy.
// A successful exchange does not establish that this snapshot is still current.
type AuthConfig struct {
	LocalID, RemoteID string
	PrivateKey        ed25519.PrivateKey
	RemotePublicKey   ed25519.PublicKey
	Child             ChildConfig
}

type ChildResult struct {
	InitiatorSPI, ResponderSPI      uint32
	LocalSelectors, RemoteSelectors []TrafficSelector
	Keys                            ChildKeys
}

type AuthResult struct {
	RemoteID string
	Child    ChildResult
}

type authPending struct {
	remoteID  string
	remoteKey ed25519.PublicKey
	child     ChildConfig
}

func cloneInitResult(r *InitResult) *InitResult {
	k := r.Keys
	return &InitResult{ResponderSPI: r.ResponderSPI, Nonce: bytes.Clone(r.Nonce), Response: bytes.Clone(r.Response), Keys: IKEKeys{
		SKD: bytes.Clone(k.SKD), SKAI: bytes.Clone(k.SKAI), SKAR: bytes.Clone(k.SKAR), SKEI: bytes.Clone(k.SKEI), SKER: bytes.Clone(k.SKER), SKPI: bytes.Clone(k.SKPI), SKPR: bytes.Clone(k.SKPR),
	}}
}

func encodeFQDN(id string) ([]byte, error) {
	if len(id) == 0 || len(id) > 253 {
		return nil, fmt.Errorf("ike: invalid FQDN identity length")
	}
	for _, c := range []byte(id) {
		if c < 0x21 || c > 0x7e {
			return nil, fmt.Errorf("ike: FQDN identity must be printable ASCII")
		}
	}
	return append([]byte{2, 0, 0, 0}, []byte(id)...), nil
}

func signedOctets(transcript, nonce, skP, id []byte) []byte {
	b := append(bytes.Clone(transcript), nonce...)
	return append(b, PRFSHA256(skP, id)...)
}

var ed25519Algorithm = []byte{0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70}

func signAuth(private ed25519.PrivateKey, octets []byte) []byte {
	b := append([]byte{14, 0, 0, 0, 7}, ed25519Algorithm...)
	return append(b, ed25519.Sign(private, octets)...)
}

func verifyAuth(public ed25519.PublicKey, octets, auth []byte) error {
	if len(public) != ed25519.PublicKeySize {
		return fmt.Errorf("ike: invalid pinned public key length")
	}
	if len(auth) != 4+1+len(ed25519Algorithm)+ed25519.SignatureSize || auth[0] != 14 || auth[4] != 7 || !bytes.Equal(auth[5:12], ed25519Algorithm) {
		return fmt.Errorf("ike: expected Ed25519 digital signature AUTH")
	}
	if !ed25519.Verify(public, octets, auth[12:]) {
		return fmt.Errorf("ike: responder AUTH signature invalid")
	}
	return nil
}

// AuthRequest starts the sole IKE_AUTH exchange. Keep the returned packet for
// retransmission; subsequent calls cannot silently change its trust policy.
func (i *Initiator) AuthRequest(c AuthConfig) ([]byte, error) {
	if i.init == nil || i.auth != nil || i.authDone {
		return nil, fmt.Errorf("ike: IKE_AUTH cannot start in current state")
	}
	if !i.peerEd25519 {
		return nil, fmt.Errorf("ike: peer did not advertise identity signature hash for Ed25519")
	}
	if len(c.PrivateKey) != ed25519.PrivateKeySize || len(c.RemotePublicKey) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("ike: invalid Ed25519 key length")
	}
	if !bytes.Equal(ed25519.NewKeyFromSeed(c.PrivateKey[:32]), c.PrivateKey) {
		return nil, fmt.Errorf("ike: inconsistent Ed25519 private key")
	}
	idi, err := encodeFQDN(c.LocalID)
	if err != nil {
		return nil, err
	}
	idr, err := encodeFQDN(c.RemoteID)
	if err != nil {
		return nil, err
	}
	sa, err := EncodeChildProposal(c.Child.InitiatorSPI)
	if err != nil {
		return nil, err
	}
	tsi, err := EncodeTrafficSelectors(c.Child.LocalSelectors)
	if err != nil {
		return nil, err
	}
	tsr, err := EncodeTrafficSelectors(c.Child.RemoteSelectors)
	if err != nil {
		return nil, err
	}
	auth := signAuth(c.PrivateKey, signedOctets(i.request, i.init.Nonce, i.init.Keys.SKPI, idi))
	first, body, err := EncodePayloads([]Payload{{Type: PayloadIDi, Data: idi}, {Type: PayloadIDr, Data: idr}, {Type: PayloadAUTH, Data: auth}, {Type: PayloadSA, Data: sa}, {Type: PayloadTSi, Data: tsi}, {Type: PayloadTSr, Data: tsr}})
	if err != nil {
		return nil, err
	}
	request, err := SealSK(Header{InitiatorSPI: i.spi, ResponderSPI: i.init.ResponderSPI, ExchangeType: ExchangeIKEAuth, Flags: FlagInitiator, MessageID: 1}, first, body, i.init.Keys.SKEI, i.init.Keys.SKAI, rand.Reader)
	if err != nil {
		return nil, err
	}
	child := c.Child
	child.LocalSelectors = append([]TrafficSelector(nil), child.LocalSelectors...)
	child.RemoteSelectors = append([]TrafficSelector(nil), child.RemoteSelectors...)
	i.auth = &authPending{remoteID: c.RemoteID, remoteKey: bytes.Clone(c.RemotePublicKey), child: child}
	return bytes.Clone(request), nil
}

// HandleAuthResponse returns CHILD material only after pinned identity,
// signature, ESP proposal and both traffic selector sets pass validation.
// Invalid packets leave the pending exchange intact for transport-level retry.
func (i *Initiator) HandleAuthResponse(packet []byte) (*AuthResult, error) {
	if i.auth == nil || i.authDone {
		return nil, fmt.Errorf("ike: no pending IKE_AUTH")
	}
	h, _, err := DecodeHeader(packet)
	if err != nil {
		return nil, err
	}
	if h.InitiatorSPI != i.spi || h.ResponderSPI != i.init.ResponderSPI || h.ExchangeType != ExchangeIKEAuth || h.MessageID != 1 || h.Flags&FlagResponse == 0 || h.Flags&FlagInitiator != 0 {
		return nil, fmt.Errorf("ike: response does not match pending IKE_AUTH")
	}
	first, plain, err := OpenSK(packet, i.init.Keys.SKER, i.init.Keys.SKAR)
	if err != nil {
		return nil, err
	}
	ps, err := DecodePayloads(first, plain)
	if err != nil {
		return nil, err
	}
	var id, auth, sa, tsi, tsr []byte
	for _, p := range ps {
		switch p.Type {
		case PayloadIDr:
			id = p.Data
		case PayloadAUTH:
			auth = p.Data
		case PayloadSA:
			sa = p.Data
		case PayloadTSi:
			tsi = p.Data
		case PayloadTSr:
			tsr = p.Data
		case PayloadNotify:
			n, e := DecodeNotify(p.Data)
			if e != nil {
				return nil, e
			}
			if n.Type < 16384 {
				return nil, fmt.Errorf("ike: IKE_AUTH error notification %d", n.Type)
			}
			// Transport mode changes the CHILD semantics and was not requested.
			if n.Type == 16391 || n.Type == 16387 {
				return nil, fmt.Errorf("ike: unrequested CHILD mode or compression")
			}
		case 37, PayloadVendor: // Certificates cannot replace the pinned public key.
		default:
			if p.Critical || (p.Type >= 33 && p.Type <= 48) {
				return nil, fmt.Errorf("ike: unexpected IKE_AUTH payload %d", p.Type)
			}
		}
	}
	if len(id) < 4 || id[0] != 2 || string(id[4:]) != i.auth.remoteID {
		return nil, fmt.Errorf("ike: responder identity does not match pinned FQDN")
	}
	if err := verifyAuth(i.auth.remoteKey, signedOctets(i.init.Response, i.nonce, i.init.Keys.SKPR, id), auth); err != nil {
		return nil, err
	}
	spi, err := ValidateChildSelection(sa)
	if err != nil {
		return nil, err
	}
	local, err := DecodeTrafficSelectors(tsi)
	if err != nil {
		return nil, err
	}
	remote, err := DecodeTrafficSelectors(tsr)
	if err != nil {
		return nil, err
	}
	if err := ValidateTrafficSelectorNarrowing(local, i.auth.child.LocalSelectors); err != nil {
		return nil, err
	}
	if err := ValidateTrafficSelectorNarrowing(remote, i.auth.child.RemoteSelectors); err != nil {
		return nil, err
	}
	keys, err := DeriveInitialChildKeys(i.init.Keys.SKD, i.nonce, i.init.Nonce)
	if err != nil {
		return nil, err
	}
	i.authDone = true
	return &AuthResult{RemoteID: i.auth.remoteID, Child: ChildResult{InitiatorSPI: i.auth.child.InitiatorSPI, ResponderSPI: spi, LocalSelectors: local, RemoteSelectors: remote, Keys: keys}}, nil
}
