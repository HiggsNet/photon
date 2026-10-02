package ike

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func TestCodecRoundTrip(t *testing.T) {
	h := Header{InitiatorSPI: 42, ResponderSPI: 9, ExchangeType: ExchangeSAInit, Flags: FlagResponse, MessageID: 3}
	ps := []Payload{{Type: PayloadSA, Data: DefaultIKEProposal()}, {Type: PayloadKE, Data: EncodeKE(GroupP256, make([]byte, 64))}, {Type: PayloadNonce, Data: make([]byte, 32)}, {Type: 250, Data: []byte{1}}, {Type: PayloadNotify}, {Type: PayloadNotify}}
	b, err := EncodeMessage(h, ps)
	if err != nil {
		t.Fatal(err)
	}
	got, out, err := DecodeMessage(b)
	if err != nil || got != h || len(out) != len(ps) {
		t.Fatalf("round trip: %+v %d %v", got, len(out), err)
	}
	b2, err := EncodeMessage(got, out)
	if err != nil || !bytes.Equal(b, b2) {
		t.Fatal("not stable", err)
	}
	b[HeaderLen+4] ^= 1
	if !bytes.Equal(out[0].Data, DefaultIKEProposal()) {
		t.Fatal("aliased packet")
	}
}

func TestCodecRejectsMalformed(t *testing.T) {
	valid, _ := EncodeMessage(Header{}, []Payload{{Type: PayloadNonce, Data: make([]byte, 16)}})
	cases := map[string]func([]byte) []byte{
		"short":            func(b []byte) []byte { return b[:27] },
		"major":            func(b []byte) []byte { b[17] = 0x10; return b },
		"length":           func(b []byte) []byte { b[27]++; return b },
		"payload_short":    func(b []byte) []byte { b[31] = 3; return b },
		"payload_overflow": func(b []byte) []byte { b[30] = 0xff; return b },
		"chain_tail":       func(b []byte) []byte { b[16] = 0; return b },
		"unknown_critical": func(b []byte) []byte { b[16] = 250; b[29] = 0x80; return b },
		"nested_sk":        func(b []byte) []byte { b[16] = PayloadSK; return b },
		"truncated_next":   func(b []byte) []byte { b[28] = PayloadNonce; return b },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if _, _, err := DecodeMessage(mutate(bytes.Clone(valid))); err == nil {
				t.Fatal("accepted malformed message")
			}
		})
	}
	for _, typ := range []uint8{PayloadSA, PayloadKE, PayloadNonce} {
		if _, _, err := EncodePayloads([]Payload{{Type: typ}, {Type: typ}}); err == nil {
			t.Fatalf("accepted duplicate %d", typ)
		}
	}
	ps := make([]Payload, MaxPayloads+1)
	for i := range ps {
		ps[i].Type = PayloadNotify
	}
	if _, _, err := EncodePayloads(ps); err == nil {
		t.Fatal("accepted payload count overflow")
	}
	if _, _, err := EncodePayloads([]Payload{{Type: PayloadNonce, Data: make([]byte, MaxMessageSize)}}); err == nil {
		t.Fatal("accepted giant payload")
	}
	if _, _, err := DecodeMessage(make([]byte, MaxMessageSize+1)); err == nil {
		t.Fatal("accepted giant message")
	}
	// Reserved bits and the minor version must be ignored, not rejected.
	valid[17] = 0x2f
	valid[19] = 0xff
	valid[29] = 0x7f
	if _, _, err := DecodeMessage(valid); err != nil {
		t.Fatal("rejected reserved bits", err)
	}
}

func TestIKESelection(t *testing.T) {
	valid := DefaultIKEProposal()
	if err := ValidateIKESelection(valid); err != nil {
		t.Fatal(err)
	}
	// Reordered transforms are a valid selection.
	reorder := append(bytes.Clone(valid[:8]), valid[20:36]...)
	reorder = append(reorder, valid[8:20]...)
	reorder = append(reorder, valid[36:]...)
	if err := ValidateIKESelection(reorder); err != nil {
		t.Fatal("reordered selection", err)
	}
	cases := map[string]func([]byte) []byte{
		"extra_proposal":   func(b []byte) []byte { b[0] = 2; return append(b, b...) },
		"number":           func(b []byte) []byte { b[4] = 2; return b },
		"protocol":         func(b []byte) []byte { b[5] = 3; return b },
		"spi":              func(b []byte) []byte { b[6] = 8; return b },
		"count":            func(b []byte) []byte { b[7] = 3; return b },
		"early_end":        func(b []byte) []byte { b[8] = 0; return b },
		"more":             func(b []byte) []byte { b[36] = 3; return b },
		"transform_length": func(b []byte) []byte { b[11] = 255; return b },
		"duplicate":        func(b []byte) []byte { b[32] = 2; b[35] = 5; return b },
		"unknown":          func(b []byte) []byte { b[32] = 9; return b },
		"algorithm":        func(b []byte) []byte { b[15] = 20; return b },
		"key_size":         func(b []byte) []byte { b[19] = 192; return b },
		"attribute":        func(b []byte) []byte { b[17] = 15; return b },
		"extra_attribute": func(b []byte) []byte {
			b = append(b[:20], append([]byte{0x80, 14, 0, 128}, b[20:]...)...)
			b[11] = 16
			binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
			return b
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			if err := ValidateIKESelection(mutate(bytes.Clone(valid))); err == nil {
				t.Fatal("accepted invalid selection")
			}
		})
	}
}

func TestInitPayloadBounds(t *testing.T) {
	for _, n := range []int{0, 15, 257} {
		if _, err := DecodeNonce(make([]byte, n)); err == nil {
			t.Fatal("nonce", n)
		}
	}
	for _, n := range []int{16, 256} {
		if _, err := DecodeNonce(make([]byte, n)); err != nil {
			t.Fatal(err)
		}
	}
	ke := EncodeKE(GroupP256, make([]byte, 64))
	if _, _, err := DecodeKE(ke); err != nil {
		t.Fatal(err)
	}
	if _, _, err := DecodeKE(ke[:67]); err == nil {
		t.Fatal("short KE")
	}
	ke[1]++
	if _, _, err := DecodeKE(ke); err == nil {
		t.Fatal("wrong KE group")
	}
	if _, err := DecodeNotify([]byte{0, 9, 0, 0}); err == nil {
		t.Fatal("short notify SPI")
	}
	n := Notify{Type: 16390, Data: make([]byte, 32)}
	b, err := EncodeNotify(n)
	if err != nil {
		t.Fatal(err)
	}
	out, err := DecodeNotify(b)
	if err != nil || out.Type != n.Type || !bytes.Equal(out.Data, n.Data) {
		t.Fatal("notify", err)
	}
}

func FuzzDecodeMessage(f *testing.F) {
	b, _ := EncodeMessage(Header{ExchangeType: ExchangeSAInit}, []Payload{{Type: PayloadSA, Data: DefaultIKEProposal()}})
	f.Add(b)
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		h, ps, err := DecodeMessage(b)
		if err != nil {
			return
		}
		encoded, err := EncodeMessage(h, ps)
		if err != nil {
			t.Fatal(err)
		}
		if _, _, err := DecodeMessage(encoded); err != nil {
			t.Fatal(err)
		}
	})
}
func FuzzInitPayloads(f *testing.F) {
	f.Add(DefaultIKEProposal())
	f.Add([]byte{})
	f.Fuzz(func(t *testing.T, b []byte) {
		_ = ValidateIKESelection(b)
		_, _, _ = DecodeKE(b)
		_, _ = DecodeNonce(b)
		_, _ = DecodeNotify(b)
	})
}
