package ike

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"testing"
)

func TestSignedOctetsVector(t *testing.T) {
	// Expected HMAC generated independently using OpenSSL dgst -sha256 -mac
	// HMAC -macopt hexkey:01020304 over 020000006c6561662e74657374.
	id := []byte{2, 0, 0, 0, 'l', 'e', 'a', 'f', '.', 't', 'e', 's', 't'}
	want, _ := hex.DecodeString("696e69742d72657175657374726573706f6e6465722d6e6f6e6365753de3c2f99dfa83b2d497b190a16c6a4fa391bd4d4b378c471ef27765db939a")
	got := signedOctets([]byte("init-request"), []byte("responder-nonce"), []byte{1, 2, 3, 4}, id)
	if !bytes.Equal(got, want) {
		t.Fatalf("signed octets = %x", got)
	}
}

func authFixture(t *testing.T) (*Initiator, AuthConfig, responderFixture, []byte, []Payload) {
	t.Helper()
	i, err := NewInitiator()
	if err != nil {
		t.Fatal(err)
	}
	r := newResponderFixture(t, i)
	r.payloads = append(r.payloads, Payload{Type: PayloadNotify, Data: []byte{0, 0, 0x40, 0x2f, 0, 5}})
	response := encodeFixture(t, r)
	init, err := i.HandleInitResponse(response)
	if err != nil {
		t.Fatal(err)
	}
	serverPublic, serverPrivate, _ := ed25519.GenerateKey(rand.Reader)
	_, clientPrivate, _ := ed25519.GenerateKey(rand.Reader)
	local := TrafficSelector{StartAddr: netip.MustParseAddr("10.0.0.1"), EndAddr: netip.MustParseAddr("10.0.0.1"), EndPort: 65535}
	remote := TrafficSelector{StartAddr: netip.MustParseAddr("10.1.0.1"), EndAddr: netip.MustParseAddr("10.1.0.1"), EndPort: 65535}
	c := AuthConfig{LocalID: "leaf.test", RemoteID: "gateway.test", PrivateKey: clientPrivate, RemotePublicKey: serverPublic, Child: ChildConfig{InitiatorSPI: 0x10203040, LocalSelectors: []TrafficSelector{local}, RemoteSelectors: []TrafficSelector{remote}}}
	// None of these returned buffers may alter the session's private copy.
	clear(init.Keys.SKD)
	clear(init.Keys.SKEI)
	clear(init.Keys.SKPI)
	clear(init.Response)
	clear(init.Nonce)
	request, err := i.AuthRequest(c)
	if err != nil {
		t.Fatal(err)
	}
	first, plain, err := OpenSK(request, r.keys.SKEI, r.keys.SKAI)
	if err != nil {
		t.Fatal("exported keys changed session", err)
	}
	ps, err := DecodePayloads(first, plain)
	if err != nil {
		t.Fatal(err)
	}
	var idi, auth []byte
	for _, p := range ps {
		if p.Type == PayloadIDi {
			idi = p.Data
		}
		if p.Type == PayloadAUTH {
			auth = p.Data
		}
	}
	// Independently assemble signed bytes, using the actual INIT transcript.
	octets := append(i.Request(), r.payloads[2].Data...)
	octets = append(octets, PRFSHA256(r.keys.SKPI, idi)...)
	if len(auth) < 12 || !ed25519.Verify(clientPrivate.Public().(ed25519.PublicKey), octets, auth[12:]) {
		t.Fatal("initiator signature invalid")
	}
	id, _ := encodeFQDN(c.RemoteID)
	// Nonzero reserved ID bytes must be authenticated as received.
	id[1] = 0x80
	serverOctets := append(bytes.Clone(response), i.nonce...)
	serverOctets = append(serverOctets, PRFSHA256(r.keys.SKPR, id)...)
	serverAuth := append([]byte{14, 0, 0, 0, 7, 0x30, 5, 6, 3, 0x2b, 0x65, 0x70}, ed25519.Sign(serverPrivate, serverOctets)...)
	sa, _ := EncodeChildProposal(0x50607080)
	tsi, _ := EncodeTrafficSelectors([]TrafficSelector{local})
	tsr, _ := EncodeTrafficSelectors([]TrafficSelector{remote})
	return i, c, r, request, []Payload{{Type: PayloadIDr, Data: id}, {Type: PayloadAUTH, Data: serverAuth}, {Type: PayloadSA, Data: sa}, {Type: PayloadTSi, Data: tsi}, {Type: PayloadTSr, Data: tsr}}
}

func authResponse(t *testing.T, i *Initiator, r responderFixture, ps []Payload, change func(*Header)) []byte {
	t.Helper()
	first, plain, err := EncodePayloads(ps)
	if err != nil {
		t.Fatal(err)
	}
	h := Header{InitiatorSPI: i.spi, ResponderSPI: r.header.ResponderSPI, ExchangeType: ExchangeIKEAuth, Flags: FlagResponse, MessageID: 1}
	if change != nil {
		change(&h)
	}
	b, err := SealSK(h, first, plain, r.keys.SKER, r.keys.SKAR, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestIKEAuthPinnedIdentityAndChild(t *testing.T) {
	i, c, r, request, ps := authFixture(t)
	clear(c.RemotePublicKey)
	c.Child.LocalSelectors[0].EndAddr = netip.MustParseAddr("10.9.9.9")
	clear(request)
	result, err := i.HandleAuthResponse(authResponse(t, i, r, ps, nil))
	if err != nil {
		t.Fatal(err)
	}
	if result.RemoteID != "gateway.test" || result.Child.ResponderSPI != 0x50607080 || result.Child.InitiatorSPI != 0x10203040 || len(result.Child.Keys.InitiatorToResponder) != 20 {
		t.Fatalf("unexpected result %+v", result)
	}
	if _, err := i.HandleAuthResponse(authResponse(t, i, r, ps, nil)); err == nil {
		t.Fatal("accepted duplicate response")
	}
}

func TestIKEAuthRejectsWithoutAdvancing(t *testing.T) {
	mutations := map[string]func(*Initiator, []Payload){
		"wrong_identity":     func(_ *Initiator, ps []Payload) { ps[0].Data[4] ^= 1 },
		"wrong_key":          func(i *Initiator, _ []Payload) { i.auth.remoteKey[0] ^= 1 },
		"signature":          func(_ *Initiator, ps []Payload) { ps[1].Data[len(ps[1].Data)-1] ^= 1 },
		"algorithm":          func(_ *Initiator, ps []Payload) { ps[1].Data[11] ^= 1 },
		"legacy_auth":        func(_ *Initiator, ps []Payload) { ps[1].Data[0] = 1 },
		"identity_reserved":  func(_ *Initiator, ps []Payload) { ps[0].Data[1] ^= 1 },
		"proposal":           func(_ *Initiator, ps []Payload) { ps[2].Data[4] = 2 },
		"expanded_local_ts":  func(_ *Initiator, ps []Payload) { ps[3].Data[len(ps[3].Data)-1]++ },
		"expanded_remote_ts": func(_ *Initiator, ps []Payload) { ps[4].Data[len(ps[4].Data)-1]++ },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			i, _, r, _, ps := authFixture(t)
			good := authResponse(t, i, r, ps, nil)
			pin := bytes.Clone(i.auth.remoteKey)
			mutate(i, ps)
			if result, err := i.HandleAuthResponse(authResponse(t, i, r, ps, nil)); err == nil || result != nil {
				t.Fatal("accepted invalid AUTH")
			}
			i.auth.remoteKey = pin
			if _, err := i.HandleAuthResponse(good); err != nil {
				t.Fatal("bad packet advanced session", err)
			}
		})
	}
	for name, change := range map[string]func(*Header){"initiator_spi": func(h *Header) { h.InitiatorSPI++ }, "responder_spi": func(h *Header) { h.ResponderSPI++ }, "message_id": func(h *Header) { h.MessageID++ }, "exchange": func(h *Header) { h.ExchangeType++ }, "flags": func(h *Header) { h.Flags |= FlagInitiator }} {
		t.Run(name, func(t *testing.T) {
			i, _, r, _, ps := authFixture(t)
			if _, err := i.HandleAuthResponse(authResponse(t, i, r, ps, change)); err == nil {
				t.Fatal("accepted mismatching header")
			}
			if _, err := i.HandleAuthResponse(authResponse(t, i, r, ps, nil)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIKEAuthRequiresNegotiatedSignatureHash(t *testing.T) {
	i, _ := NewInitiator()
	r := newResponderFixture(t, i)
	if _, err := i.HandleInitResponse(encodeFixture(t, r)); err != nil {
		t.Fatal(err)
	}
	if _, err := i.AuthRequest(AuthConfig{}); err == nil {
		t.Fatal("accepted peer without identity hash")
	}
}

func TestIKEAuthMissingPayloadAndNotifications(t *testing.T) {
	for removed := 0; removed < 5; removed++ {
		t.Run(string(rune('0'+removed)), func(t *testing.T) {
			i, _, r, _, ps := authFixture(t)
			good := authResponse(t, i, r, ps, nil)
			ps = append(ps[:removed], ps[removed+1:]...)
			if _, err := i.HandleAuthResponse(authResponse(t, i, r, ps, nil)); err == nil {
				t.Fatal("accepted missing payload")
			}
			if _, err := i.HandleAuthResponse(good); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, kind := range []uint16{24, 16387, 16391} {
		t.Run(fmt.Sprint(kind), func(t *testing.T) {
			i, _, r, _, ps := authFixture(t)
			good := authResponse(t, i, r, ps, nil)
			n, _ := EncodeNotify(Notify{Type: kind})
			ps = append(ps, Payload{Type: PayloadNotify, Data: n})
			if _, err := i.HandleAuthResponse(authResponse(t, i, r, ps, nil)); err == nil {
				t.Fatal("accepted error or changed CHILD semantics")
			}
			if _, err := i.HandleAuthResponse(good); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestIKEAuthRejectsDuplicatePayloadAndReverseKeys(t *testing.T) {
	for _, typ := range []uint8{PayloadIDr, PayloadAUTH, PayloadSA, PayloadTSi, PayloadTSr} {
		i, _, r, _, ps := authFixture(t)
		first, plain, err := EncodePayloads(ps)
		if err != nil {
			t.Fatal(err)
		}
		// Bypass the encoder's duplicate validation to model a malicious peer.
		last := 0
		for offset := 0; offset < len(plain); {
			last = offset
			offset += int(plain[offset+2])<<8 | int(plain[offset+3])
		}
		plain[last] = typ
		plain = append(plain, 0, 0, 0, 4)
		h := Header{InitiatorSPI: i.spi, ResponderSPI: r.header.ResponderSPI, ExchangeType: ExchangeIKEAuth, Flags: FlagResponse, MessageID: 1}
		packet, err := SealSK(h, first, plain, r.keys.SKER, r.keys.SKAR, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := i.HandleAuthResponse(packet); err == nil {
			t.Fatalf("duplicate payload %d accepted", typ)
		}
		_, plain, err = EncodePayloads(ps)
		if err != nil {
			t.Fatal(err)
		}
		packet, err = SealSK(h, first, plain, r.keys.SKEI, r.keys.SKAI, rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := i.HandleAuthResponse(packet); err == nil {
			t.Fatal("initiator keys accepted for responder")
		}
		if _, err := i.HandleAuthResponse(authResponse(t, i, r, ps, nil)); err != nil {
			t.Fatal(err)
		}
	}
}

func TestIKEAuthCannotChangePendingPolicy(t *testing.T) {
	i, c, _, _, _ := authFixture(t)
	if _, err := i.AuthRequest(c); err == nil {
		t.Fatal("started second AUTH")
	}
	c.RemoteID = "different.test"
	if _, err := i.AuthRequest(c); err == nil {
		t.Fatal("changed pending identity")
	}
}

func TestSignatureHashNotificationMalformed(t *testing.T) {
	for _, data := range [][]byte{nil, {0}, {0, 5, 0}} {
		i, _ := NewInitiator()
		r := newResponderFixture(t, i)
		good := encodeFixture(t, r)
		n, _ := EncodeNotify(Notify{Type: 16431, Data: data})
		r.payloads = append(r.payloads, Payload{Type: PayloadNotify, Data: n})
		if _, err := i.HandleInitResponse(encodeFixture(t, r)); err == nil {
			t.Fatal("accepted malformed signature hashes")
		}
		if _, err := i.HandleInitResponse(good); err != nil {
			t.Fatal("bad hash notification advanced state", err)
		}
	}
	i, _ := NewInitiator()
	r := newResponderFixture(t, i)
	n := Payload{Type: PayloadNotify, Data: []byte{0, 0, 0x40, 0x2f, 0, 5}}
	r.payloads = append(r.payloads, n, n)
	if _, err := i.HandleInitResponse(encodeFixture(t, r)); err == nil {
		t.Fatal("accepted duplicate signature hashes")
	}
}
