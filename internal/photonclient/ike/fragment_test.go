package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
	"time"
)

func fragmentFixture(t *testing.T, plain []byte, budget int) (Header, []byte, []byte, [][]byte) {
	t.Helper()
	h := Header{InitiatorSPI: 1, ResponderSPI: 2, ExchangeType: ExchangeIKEAuth, Flags: FlagResponse, MessageID: 1}
	ek, ak := bytes.Repeat([]byte{3}, 16), bytes.Repeat([]byte{4}, 32)
	packets, err := SealSKF(h, PayloadIDr, plain, ek, ak, budget, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return h, ek, ak, packets
}

func TestSKFOutOfOrderAndOwnership(t *testing.T) {
	plain := bytes.Repeat([]byte("fragment data"), 100)
	h, ek, ak, packets := fragmentFixture(t, plain, 300)
	var r skfReassembly
	now := time.Unix(10, 0)
	for n := len(packets) - 1; n >= 0; n-- {
		if len(packets[n]) > 300 {
			t.Fatal("datagram budget exceeded")
		}
		first, out, complete, err := r.Add(packets[n], h, ek, ak, now)
		if err != nil {
			t.Fatal(err)
		}
		if n != 0 {
			if complete || out != nil {
				t.Fatal("completed without first fragment")
			}
			if _, _, done, err := r.Add(packets[n], h, ek, ak, now); err != nil || done {
				t.Fatal("duplicate changed state", err)
			}
		} else if !complete || first != PayloadIDr || !bytes.Equal(out, plain) {
			t.Fatal("reassembly mismatch")
		}
		clear(packets[n])
	}
	if r.total != 0 || r.size != 0 || r.parts[0] != nil {
		t.Fatal("complete reassembly retained state")
	}
}

func TestSKFIntegrityAndConflictsPreserveState(t *testing.T) {
	plain := bytes.Repeat([]byte{0x55}, 700)
	h, ek, ak, packets := fragmentFixture(t, plain, 300)
	now := time.Unix(10, 0)
	var r skfReassembly
	if _, _, _, err := r.Add(packets[0], h, ek, ak, now); err != nil {
		t.Fatal(err)
	}
	saved := bytes.Clone(r.parts[0])
	forged := bytes.Clone(packets[1])
	forged[len(forged)-1] ^= 1
	wrong := h
	wrong.MessageID++
	for _, tc := range []struct {
		p []byte
		h Header
	}{{forged, h}, {packets[1], wrong}} {
		if _, _, _, err := r.Add(tc.p, tc.h, ek, ak, now); err == nil {
			t.Fatal("invalid packet accepted")
		}
		if r.received != 1 || !bytes.Equal(r.parts[0], saved) {
			t.Fatal("invalid packet changed reassembly")
		}
	}
	_, _, _, conflict := fragmentFixture(t, bytes.Repeat([]byte{0x66}, 700), 300)
	if _, _, _, err := r.Add(conflict[0], h, ek, ak, now); err == nil {
		t.Fatal("conflicting duplicate accepted")
	}
	if !bytes.Equal(r.parts[0], saved) {
		t.Fatal("conflict overwrote original")
	}
	// A valid PMTU restart uses a greater total. A forged one must not flush state.
	_, _, _, smaller := fragmentFixture(t, plain, 180)
	forged = bytes.Clone(smaller[0])
	forged[len(forged)-1] ^= 1
	if _, _, _, err := r.Add(forged, h, ek, ak, now); err == nil || r.total != len(packets) {
		t.Fatal("forged restart")
	}
	if _, _, _, err := r.Add(smaller[1], h, ek, ak, now); err != nil || r.total != len(smaller) || r.received != 1 {
		t.Fatal("valid restart failed", err)
	}
	if _, _, _, err := r.Add(packets[1], h, ek, ak, now); err == nil || r.received != 1 {
		t.Fatal("old set accepted")
	}
	for n, p := range smaller {
		if n == 1 {
			continue
		}
		_, out, done, err := r.Add(p, h, ek, ak, now)
		if err != nil {
			t.Fatal(err)
		}
		if n == len(smaller)-1 && (!done || !bytes.Equal(out, plain)) {
			t.Fatal("restart did not complete")
		}
	}
}

func TestSKFBoundsAndCleanup(t *testing.T) {
	h, ek, ak, packets := fragmentFixture(t, bytes.Repeat([]byte{1}, 700), 300)
	now := time.Unix(10, 0)
	var r skfReassembly
	if _, _, _, err := r.Add(packets[0], h, ek, ak, now); err != nil {
		t.Fatal(err)
	}
	retained := r.parts[0]
	if _, _, _, err := r.Add(packets[1], h, ek, ak, now.Add(fragmentTimeout)); err != nil {
		t.Fatal(err)
	}
	if r.parts[0] != nil || r.received != 1 || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("expiration did not clear original fragments")
	}
	retained = r.parts[1]
	r.Reset()
	if r.total != 0 || !bytes.Equal(retained, make([]byte, len(retained))) {
		t.Fatal("reset did not clear")
	}
	for _, offset := range []int{HeaderLen, HeaderLen + 4, HeaderLen + 6} {
		packet := bytes.Clone(packets[0])
		if offset == HeaderLen {
			packet[offset] = 0
		} else {
			binary.BigEndian.PutUint16(packet[offset:], 65535)
		}
		// Invalid framing must not reserve a remotely supplied fragment array.
		if _, _, _, err := r.Add(packet, h, ek, ak, now); err == nil || r.total != 0 {
			t.Fatal("invalid bounds accepted")
		}
	}
	if _, err := SealSKF(h, PayloadIDr, make([]byte, MaxMessageSize+1), ek, ak, 1000, rand.Reader); err == nil {
		t.Fatal("oversized plaintext")
	}
	if _, err := SealSKF(h, PayloadIDr, make([]byte, 5000), ek, ak, 84, rand.Reader); err == nil {
		t.Fatal("excessive fragment count")
	}
	if _, err := SealSKF(h, PayloadIDr, []byte{1}, ek, ak, 83, rand.Reader); err == nil {
		t.Fatal("undersized budget")
	}
	// Individually valid fragments cannot exceed the cumulative plaintext limit.
	big := bytes.Repeat([]byte{9}, 40000)
	_, _, _, bigPackets := fragmentFixture(t, big, MaxMessageSize)
	first := bytes.Clone(bigPackets[0])
	binary.BigEndian.PutUint16(first[HeaderLen+6:], 2)
	copy(first[len(first)-skICVLen:], PRFSHA256(ak, first[:len(first)-skICVLen])[:skICVLen])
	second := bytes.Clone(first)
	second[HeaderLen] = 0
	binary.BigEndian.PutUint16(second[HeaderLen+4:], 2)
	copy(second[len(second)-skICVLen:], PRFSHA256(ak, second[:len(second)-skICVLen])[:skICVLen])
	if _, _, _, err := r.Add(first, h, ek, ak, now); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := r.Add(second, h, ek, ak, now); err == nil || r.received != 1 || r.size != len(big) {
		t.Fatal("aggregate limit not enforced")
	}
}

func TestFragmentationNegotiation(t *testing.T) {
	for _, tc := range []struct {
		name  string
		data  []byte
		valid bool
	}{
		{"valid", []byte{0, 0, 0x40, 0x2e}, true},
		{"protocol", []byte{1, 0, 0x40, 0x2e}, false},
		{"data", []byte{0, 0, 0x40, 0x2e, 1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			i, err := NewInitiator()
			if err != nil {
				t.Fatal(err)
			}
			_, ps, err := DecodeMessage(i.Request())
			if err != nil {
				t.Fatal(err)
			}
			advertised := false
			for _, p := range ps {
				if p.Type == PayloadNotify && bytes.Equal(p.Data, []byte{0, 0, 0x40, 0x2e}) {
					advertised = true
				}
			}
			if !advertised {
				t.Fatal("support not advertised")
			}
			r := newResponderFixture(t, i)
			r.payloads = append(r.payloads, Payload{Type: PayloadNotify, Data: tc.data})
			_, err = i.HandleInitResponse(encodeFixture(t, r))
			if (err == nil) != tc.valid || i.peerFragmentation != tc.valid {
				t.Fatal("negotiation result", err)
			}
		})
	}
}

func TestFragmentedAuthRetainsAuthenticationAndRetransmission(t *testing.T) {
	i, _, responder, _, ps := authFixture(t)
	if _, err := i.AuthRequestFragments(180); err == nil {
		t.Fatal("fragmented without negotiation")
	}
	i.peerFragmentation = true // Wire negotiation is tested separately above.
	requests, err := i.AuthRequestFragments(180)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(requests[0])
	clear(requests[0])
	retry, err := i.AuthRequestFragments(180)
	if err != nil || !bytes.Equal(retry[0], original) {
		t.Fatal("retransmission not detached", err)
	}
	response := authResponse(t, i, responder, ps, nil)
	h, _, _ := DecodeHeader(response)
	first, plain, err := OpenSK(response, responder.keys.SKER, responder.keys.SKAR)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := SealSKF(h, first, plain, responder.keys.SKER, responder.keys.SKAR, 180, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(10, 0)
	for n := len(packets) - 1; n >= 0; n-- {
		result, err := i.HandleAuthFragment(packets[n], now)
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 && (result != nil || i.authDone) {
			t.Fatal("partial fragment authenticated peer")
		}
		if n == 0 && (result == nil || !i.authDone || result.RemoteID != "gateway.test") {
			t.Fatal("complete AUTH failed")
		}
	}
	if _, err := i.HandleAuthFragment(packets[0], now); err == nil {
		t.Fatal("AUTH replay accepted")
	}
}

func TestFragmentIntegrityDoesNotReplacePinnedAuth(t *testing.T) {
	i, _, responder, _, ps := authFixture(t)
	i.peerFragmentation = true
	// The exchange's SK integrity key does not prove possession of the pinned
	// identity key; a valid HMAC must not bypass the AUTH signature check.
	for n := range ps {
		if ps[n].Type == PayloadAUTH {
			ps[n].Data = bytes.Clone(ps[n].Data)
			ps[n].Data[len(ps[n].Data)-1] ^= 1
		}
	}
	packet := authResponse(t, i, responder, ps, nil)
	h, _, _ := DecodeHeader(packet)
	first, plain, err := OpenSK(packet, responder.keys.SKER, responder.keys.SKAR)
	if err != nil {
		t.Fatal(err)
	}
	fragments, err := SealSKF(h, first, plain, responder.keys.SKER, responder.keys.SKAR, 180, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for n, fragment := range fragments {
		result, err := i.HandleAuthFragment(fragment, time.Unix(10, 0))
		if result != nil || i.authDone {
			t.Fatal("invalid identity accepted")
		}
		if n == len(fragments)-1 && err == nil {
			t.Fatal("invalid signature not rejected")
		}
		if n < len(fragments)-1 && err != nil {
			t.Fatal(err)
		}
	}
	if i.auth.reassembly.total != 0 {
		t.Fatal("rejected message retained decrypted fragments")
	}
}
