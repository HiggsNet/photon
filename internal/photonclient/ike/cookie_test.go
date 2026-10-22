package ike

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"net/netip"
	"testing"
)

func cookieResponse(t *testing.T, i *Initiator, cookie []byte, change func(*Header, *[]Payload)) []byte {
	t.Helper()
	h := Header{InitiatorSPI: i.spi, ExchangeType: ExchangeSAInit, Flags: FlagResponse}
	ps := []Payload{{Type: PayloadNotify, Data: append([]byte{0, 0, 0x40, 0x06}, cookie...)}}
	if change != nil {
		change(&h, &ps)
	}
	p, err := EncodeMessage(h, ps)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCookieRetryPreservesInitAndBounds(t *testing.T) {
	i, err := NewInitiator()
	if err != nil {
		t.Fatal(err)
	}
	original := i.Request()
	private := i.private
	nonce := bytes.Clone(i.nonce)
	for n := 0; n < 3; n++ {
		data := bytes.Repeat([]byte{byte(n + 1)}, 64)
		packet := cookieResponse(t, i, data, func(h *Header, _ *[]Payload) { h.ResponderSPI = 1234 })
		retry, err := i.HandleInitCookie(packet)
		if err != nil {
			t.Fatal(err)
		}
		h, ps, err := DecodeMessage(retry)
		if err != nil {
			t.Fatal(err)
		}
		if h.ResponderSPI != 0 || h.MessageID != 0 || h.Flags != FlagInitiator || i.private != private || !bytes.Equal(i.nonce, nonce) {
			t.Fatal("COOKIE changed initial state")
		}
		nfy, err := DecodeNotify(ps[0].Data)
		if err != nil || nfy.Type != NotifyCookie || !bytes.Equal(nfy.Data, data) {
			t.Fatal("COOKIE not first", err)
		}
		_, tail, err := EncodePayloads(ps[1:])
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(tail, original[HeaderLen:]) {
			t.Fatal("COOKIE changed original payloads")
		}
		clear(retry)
		if bytes.Equal(i.Request(), retry) {
			t.Fatal("retry aliases transcript")
		}
	}
	before := i.Request()
	if _, err := i.HandleInitCookie(cookieResponse(t, i, []byte{9}, nil)); err == nil || !bytes.Equal(before, i.Request()) {
		t.Fatal("retry cap failed")
	}
}

func TestInvalidCookiePreservesPendingRequest(t *testing.T) {
	cases := []struct {
		name   string
		data   []byte
		change func(*Header, *[]Payload)
	}{
		{"empty", nil, nil}, {"oversize", make([]byte, 65), nil},
		{"SPI", []byte{1}, func(h *Header, _ *[]Payload) { h.InitiatorSPI++ }},
		{"request flag", []byte{1}, func(h *Header, _ *[]Payload) { h.Flags = 0 }},
		{"ID", []byte{1}, func(h *Header, _ *[]Payload) { h.MessageID = 1 }},
		{"protocol", []byte{1}, func(_ *Header, p *[]Payload) { (*p)[0].Data[0] = 1 }},
		{"duplicate", []byte{1}, func(_ *Header, p *[]Payload) { *p = append(*p, (*p)[0]) }},
		{"SA", []byte{1}, func(_ *Header, p *[]Payload) { *p = append(*p, Payload{Type: PayloadSA, Data: DefaultIKEProposal()}) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			i, err := NewInitiator()
			if err != nil {
				t.Fatal(err)
			}
			before := i.Request()
			if _, err := i.HandleInitCookie(cookieResponse(t, i, tc.data, tc.change)); err == nil {
				t.Fatal("invalid COOKIE accepted")
			}
			if i.cookieRetries != 0 || !bytes.Equal(before, i.Request()) || i.init != nil {
				t.Fatal("invalid COOKIE changed state")
			}
		})
	}
}

func TestCookieAuthBindsRetryTranscript(t *testing.T) {
	i, err := NewInitiator()
	if err != nil {
		t.Fatal(err)
	}
	original := i.Request()
	challenge := cookieResponse(t, i, []byte("stateless-cookie"), nil)
	firstRetry, err := i.HandleInitCookie(challenge)
	if err != nil {
		t.Fatal(err)
	}
	secondRetry, err := i.HandleInitCookie(challenge)
	if err != nil || !bytes.Equal(firstRetry, secondRetry) {
		t.Fatal("duplicate COOKIE retry changed", err)
	}
	r := newResponderFixture(t, i)
	r.payloads = append(r.payloads, Payload{Type: PayloadNotify, Data: []byte{0, 0, 0x40, 0x2f, 0, 5}})
	if _, err := i.HandleInitResponse(encodeFixture(t, r)); err != nil {
		t.Fatal(err)
	}
	if _, err := i.HandleInitCookie(challenge); err == nil {
		t.Fatal("COOKIE accepted after INIT")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	selector := TrafficSelector{StartAddr: netip.MustParseAddr("10.0.0.1"), EndAddr: netip.MustParseAddr("10.0.0.1"), EndPort: 65535}
	request, err := i.AuthRequest(AuthConfig{LocalID: "leaf.test", RemoteID: "gateway.test", PrivateKey: priv, RemotePublicKey: pub, Child: ChildConfig{InitiatorSPI: 4242, LocalSelectors: []TrafficSelector{selector}, RemoteSelectors: []TrafficSelector{selector}}})
	if err != nil {
		t.Fatal(err)
	}
	first, plain, err := OpenSK(request, r.keys.SKEI, r.keys.SKAI)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := DecodePayloads(first, plain)
	if err != nil {
		t.Fatal(err)
	}
	var id, auth []byte
	for _, p := range ps {
		if p.Type == PayloadIDi {
			id = p.Data
		}
		if p.Type == PayloadAUTH {
			auth = p.Data
		}
	}
	if err := verifyAuth(pub, signedOctets(firstRetry, r.payloads[2].Data, r.keys.SKPI, id), auth); err != nil {
		t.Fatal("AUTH does not bind cookie retry", err)
	}
	if err := verifyAuth(pub, signedOctets(original, r.payloads[2].Data, r.keys.SKPI, id), auth); err == nil {
		t.Fatal("AUTH still binds pre-cookie INIT")
	}
}
