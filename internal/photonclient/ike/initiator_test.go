package ike

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"reflect"
	"testing"
)

type responderFixture struct {
	header   Header
	payloads []Payload
	keys     IKEKeys
}

func newResponderFixture(t *testing.T, i *Initiator) responderFixture {
	t.Helper()
	h, ps, err := DecodeMessage(i.Request())
	if err != nil {
		t.Fatal(err)
	}
	if h.InitiatorSPI == 0 || h.ResponderSPI != 0 || h.MessageID != 0 || h.Flags != FlagInitiator || h.ExchangeType != ExchangeSAInit {
		t.Fatalf("bad request header %+v", h)
	}
	var public, nonce []byte
	for _, p := range ps {
		switch p.Type {
		case PayloadSA:
			if err := ValidateIKESelection(p.Data); err != nil {
				t.Fatal(err)
			}
		case PayloadKE:
			_, public, err = DecodeKE(p.Data)
		case PayloadNonce:
			nonce, err = DecodeNonce(p.Data)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	// Independently use the standard-library responder's private/public keys and
	// peer decoding, instead of the initiator's internal private key or state.
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peer, err := ecdh.P256().NewPublicKey(append([]byte{4}, public...))
	if err != nil {
		t.Fatal(err)
	}
	shared, err := key.ECDH(peer)
	if err != nil {
		t.Fatal(err)
	}
	nr := bytes.Repeat([]byte{0x71}, 32)
	keys, err := DeriveIKEKeys(shared, nonce, nr, h.InitiatorSPI, 0x11223344)
	if err != nil {
		t.Fatal(err)
	}
	return responderFixture{Header{InitiatorSPI: h.InitiatorSPI, ResponderSPI: 0x11223344, ExchangeType: ExchangeSAInit, Flags: FlagResponse}, []Payload{{Type: PayloadSA, Data: DefaultIKEProposal()}, {Type: PayloadKE, Data: EncodeKE(GroupP256, key.PublicKey().Bytes()[1:])}, {Type: PayloadNonce, Data: nr}}, keys}
}
func encodeFixture(t *testing.T, r responderFixture) []byte {
	t.Helper()
	b, err := EncodeMessage(r.header, r.payloads)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInitiatorExchange(t *testing.T) {
	i, err := NewInitiator()
	if err != nil {
		t.Fatal(err)
	}
	request := i.Request()
	baseline := bytes.Clone(request)
	clear(request)
	if !bytes.Equal(i.Request(), baseline) {
		t.Fatal("Request aliases internal transcript")
	}
	r := newResponderFixture(t, i)
	packet := encodeFixture(t, r)
	result, err := i.HandleInitResponse(packet)
	if err != nil {
		t.Fatal(err)
	}
	if result.ResponderSPI != r.header.ResponderSPI || !reflect.DeepEqual(result.Keys, r.keys) || !bytes.Equal(result.Nonce, r.payloads[2].Data) || !bytes.Equal(result.Response, packet) {
		t.Fatal("responder/initiator result mismatch")
	}
	snapshot := bytes.Clone(result.Response)
	clear(packet)
	if !bytes.Equal(result.Response, snapshot) {
		t.Fatal("response transcript aliases caller")
	}
	if _, err := i.HandleInitResponse(snapshot); err == nil {
		t.Fatal("completed exchange accepted twice")
	}
	if !bytes.Equal(i.Request(), baseline) {
		t.Fatal("completed exchange changed request transcript")
	}
}

func TestInitiatorRejectsWithoutAdvancing(t *testing.T) {
	mutations := map[string]func(*responderFixture){
		"initiator_spi":      func(r *responderFixture) { r.header.InitiatorSPI++ },
		"zero_responder_spi": func(r *responderFixture) { r.header.ResponderSPI = 0 },
		"message_id":         func(r *responderFixture) { r.header.MessageID = 1 },
		"exchange":           func(r *responderFixture) { r.header.ExchangeType++ },
		"request_flag":       func(r *responderFixture) { r.header.Flags = 0 },
		"initiator_flag":     func(r *responderFixture) { r.header.Flags |= FlagInitiator },
		"unoffered_proposal": func(r *responderFixture) { r.payloads[0].Data[15]++ },
		"missing_sa":         func(r *responderFixture) { r.payloads = r.payloads[1:] },
		"missing_nonce":      func(r *responderFixture) { r.payloads = r.payloads[:2] },
		"missing_ke":         func(r *responderFixture) { r.payloads = append(r.payloads[:1], r.payloads[2:]...) },
		"ke_group":           func(r *responderFixture) { r.payloads[1].Data[1]++ },
		"ke_point":           func(r *responderFixture) { clear(r.payloads[1].Data[4:]) },
		"nonce_short":        func(r *responderFixture) { r.payloads[2].Data = make([]byte, 15) },
		"known_id_payload": func(r *responderFixture) {
			r.payloads = append(r.payloads, Payload{Type: 35, Data: []byte{1, 0, 0, 0}})
		},
		"notify_error": func(r *responderFixture) {
			r.payloads = append(r.payloads, Payload{Type: PayloadNotify, Data: []byte{0, 0, 0, 14}})
		},
		"notify_unknown_error": func(r *responderFixture) {
			r.payloads = append(r.payloads, Payload{Type: PayloadNotify, Data: []byte{0, 0, 0x3f, 0xff}})
		},
		"cookie": func(r *responderFixture) {
			r.payloads = append(r.payloads, Payload{Type: PayloadNotify, Data: []byte{0, 0, 0x40, 6, 1}})
		},
		"notify_spi": func(r *responderFixture) {
			r.payloads = append(r.payloads, Payload{Type: PayloadNotify, Data: []byte{0, 1, 0x40, 0, 1}})
		},
		"notify_truncated": func(r *responderFixture) {
			r.payloads = append(r.payloads, Payload{Type: PayloadNotify, Data: []byte{0}})
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			i, err := NewInitiator()
			if err != nil {
				t.Fatal(err)
			}
			r := newResponderFixture(t, i)
			good := encodeFixture(t, r)
			mutate(&r)
			if _, err := i.HandleInitResponse(encodeFixture(t, r)); err == nil {
				t.Fatal("accepted invalid response")
			}
			if _, err := i.HandleInitResponse(good); err != nil {
				t.Fatal("invalid response advanced exchange", err)
			}
		})
	}
	t.Run("unknown_critical", func(t *testing.T) {
		i, _ := NewInitiator()
		r := newResponderFixture(t, i)
		good := encodeFixture(t, r)
		bad := bytes.Clone(good)
		bad[16] = 250
		bad[29] |= 0x80
		if _, err := i.HandleInitResponse(bad); err == nil {
			t.Fatal("unknown critical accepted")
		}
		if _, err := i.HandleInitResponse(good); err != nil {
			t.Fatal(err)
		}
	})
}

func TestInitiatorIgnoresPermittedExtensions(t *testing.T) {
	i, err := NewInitiator()
	if err != nil {
		t.Fatal(err)
	}
	r := newResponderFixture(t, i)
	r.payloads = append(r.payloads, Payload{Type: 250, Data: []byte{1}}, Payload{Type: PayloadVendor, Data: []byte("vendor")}, Payload{Type: PayloadNotify, Data: []byte{99, 0, 0xff, 0xff}})
	r.header.Flags |= 0xc7 // Reserved header flags are ignored.
	b := encodeFixture(t, r)
	b[17] = 0x2f
	if _, err := i.HandleInitResponse(b); err != nil {
		t.Fatal("permitted extension rejected", err)
	}
}
