package ike

import (
	"bytes"
	"crypto/rand"
	"math"
	"testing"
)

func informationalFixture(t *testing.T) *Initiator {
	t.Helper()
	i, _, r, _, ps := authFixture(t)
	if _, err := i.HandleAuthResponse(authResponse(t, i, r, ps, nil)); err != nil {
		t.Fatal(err)
	}
	return i
}

func peerInformation(t *testing.T, i *Initiator, id uint32, response bool, ps []Payload, change func(*Header)) []byte {
	t.Helper()
	h := Header{InitiatorSPI: i.spi, ResponderSPI: i.init.ResponderSPI, ExchangeType: ExchangeInformational, MessageID: id}
	if response {
		h.Flags = FlagResponse
	}
	if change != nil {
		change(&h)
	}
	first, plain, err := EncodePayloads(ps)
	if err != nil {
		t.Fatal(err)
	}
	packet, err := SealSK(h, first, plain, i.init.Keys.SKER, i.init.Keys.SKAR, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestInformationalLivenessAndIndependentCounters(t *testing.T) {
	i := informationalFixture(t)
	for id := uint32(2); id <= 3; id++ {
		request, err := i.InformationalRequest()
		if err != nil {
			t.Fatal(err)
		}
		original := bytes.Clone(request)
		h, _, err := DecodeHeader(request)
		if err != nil || h.MessageID != id || h.Flags != FlagInitiator {
			t.Fatalf("request header: %+v, %v", h, err)
		}
		if first, plain, err := OpenSK(request, i.init.Keys.SKEI, i.init.Keys.SKAI); err != nil || first != 0 || len(plain) != 0 {
			t.Fatalf("request not authenticated empty: %v", err)
		}
		clear(request)
		retry := i.PendingInformationalRequest()
		if !bytes.Equal(retry, original) {
			t.Fatal("request not detached")
		}
		clear(retry)
		if !bytes.Equal(i.PendingInformationalRequest(), original) {
			t.Fatal("retry not detached")
		}
		if _, err := i.InformationalRequest(); err == nil {
			t.Fatal("parallel exchange accepted")
		}
		// The responder starts at zero and can initiate while our request is pending.
		peer := peerInformation(t, i, id-2, false, nil, nil)
		reply, err := i.HandleInformational(peer)
		if err != nil {
			t.Fatal(err)
		}
		rh, _, err := DecodeHeader(reply)
		if err != nil || rh.MessageID != id-2 || rh.Flags != FlagInitiator|FlagResponse {
			t.Fatalf("reply header: %+v, %v", rh, err)
		}
		if first, plain, err := OpenSK(reply, i.init.Keys.SKEI, i.init.Keys.SKAI); err != nil || first != 0 || len(plain) != 0 {
			t.Fatalf("reply not authenticated empty: %v", err)
		}
		originalReply := bytes.Clone(reply)
		clear(reply)
		duplicate, err := i.HandleInformational(peer)
		if err != nil || !bytes.Equal(duplicate, originalReply) {
			t.Fatalf("duplicate not cached: %v", err)
		}
		clear(duplicate)
		duplicate, err = i.HandleInformational(peer)
		if err != nil || !bytes.Equal(duplicate, originalReply) {
			t.Fatal("cached reply escaped")
		}
		if !bytes.Equal(i.PendingInformationalRequest(), original) {
			t.Fatal("peer request changed local pending")
		}
		response := peerInformation(t, i, id, true, nil, nil)
		if reply, err := i.HandleInformational(response); err != nil || reply != nil {
			t.Fatalf("response: %x, %v", reply, err)
		}
		if i.PendingInformationalRequest() != nil {
			t.Fatal("pending not cleared")
		}
		if _, err := i.HandleInformational(response); err == nil {
			t.Fatal("replayed response accepted")
		}
	}
}

func TestInformationalRejectsBeforeAuthentication(t *testing.T) {
	i, _, _, _, _ := authFixture(t)
	if _, err := i.InformationalRequest(); err == nil {
		t.Fatal("request before AUTH")
	}
	if _, err := i.HandleInformational(peerInformation(t, i, 0, false, nil, nil)); err == nil {
		t.Fatal("request accepted before AUTH")
	}
	if i.exchanges.nextRemote != 0 || i.exchanges.nextLocal != 2 || i.exchanges.lastRequest != nil {
		t.Fatal("unauthenticated session advanced")
	}
	var zero Initiator
	if _, err := zero.HandleInformational(nil); err == nil {
		t.Fatal("zero session accepted")
	}
}

func TestInformationalInvalidMessagesPreserveState(t *testing.T) {
	cases := []struct {
		name     string
		mutate   func(*Header)
		payloads []Payload
		corrupt  bool
	}{
		{name: "initiator SPI", mutate: func(h *Header) { h.InitiatorSPI++ }},
		{name: "responder SPI", mutate: func(h *Header) { h.ResponderSPI++ }},
		{name: "exchange", mutate: func(h *Header) { h.ExchangeType = ExchangeIKEAuth }},
		{name: "initiator flag", mutate: func(h *Header) { h.Flags |= FlagInitiator }},
		{name: "future ID", mutate: func(h *Header) { h.MessageID++ }},
		{name: "integrity", corrupt: true},
		{name: "delete", payloads: []Payload{{Type: 42, Data: []byte{1, 0, 0, 0}}}},
		{name: "notification", payloads: []Payload{{Type: PayloadNotify, Data: []byte{0, 0, 0x40, 0x01}}}},
		{name: "unknown optional", payloads: []Payload{{Type: 250}}},
	}
	for _, response := range []bool{false, true} {
		for _, tc := range cases {
			name := "request/"
			if response {
				name = "response/"
			}
			t.Run(name+tc.name, func(t *testing.T) {
				i := informationalFixture(t)
				pending, err := i.InformationalRequest()
				if err != nil {
					t.Fatal(err)
				}
				id := uint32(0)
				if response {
					id = 2
				}
				packet := peerInformation(t, i, id, response, tc.payloads, tc.mutate)
				if tc.corrupt {
					packet[len(packet)-1] ^= 1
				}
				if _, err := i.HandleInformational(packet); err == nil {
					t.Fatal("invalid packet accepted")
				}
				if i.exchanges.nextLocal != 2 || i.exchanges.nextRemote != 0 || i.exchanges.lastRequest != nil || !bytes.Equal(i.PendingInformationalRequest(), pending) {
					t.Fatal("invalid packet advanced state")
				}
				// A valid retry remains possible after rejection.
				if _, err := i.HandleInformational(peerInformation(t, i, id, response, nil, nil)); err != nil {
					t.Fatal(err)
				}
			})
		}
	}
}

func TestInformationalReplayCacheBounded(t *testing.T) {
	i := informationalFixture(t)
	first := peerInformation(t, i, 0, false, nil, nil)
	if _, err := i.HandleInformational(first); err != nil {
		t.Fatal(err)
	}
	// Same ID freshly encrypted is not a retransmission of the original bytes.
	if _, err := i.HandleInformational(peerInformation(t, i, 0, false, nil, nil)); err == nil {
		t.Fatal("changed duplicate accepted")
	}
	second := peerInformation(t, i, 1, false, nil, nil)
	expected, err := i.HandleInformational(second)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.HandleInformational(first); err == nil {
		t.Fatal("old request replay accepted")
	}
	second[len(second)-1] ^= 1
	if _, err := i.HandleInformational(second); err == nil {
		t.Fatal("forged duplicate accepted")
	}
	second[len(second)-1] ^= 1
	actual, err := i.HandleInformational(second)
	if err != nil || !bytes.Equal(actual, expected) || i.exchanges.nextRemote != 2 {
		t.Fatal("invalid replay damaged last cache")
	}
	clear(second)
	if bytes.Equal(i.exchanges.lastRequest, second) {
		t.Fatal("caller owns cached request bytes")
	}
}

func TestInformationalMessageIDExhaustion(t *testing.T) {
	i := informationalFixture(t)
	i.exchanges.nextLocal = math.MaxUint32
	if _, err := i.InformationalRequest(); err != nil {
		t.Fatal(err)
	}
	if _, err := i.HandleInformational(peerInformation(t, i, math.MaxUint32, true, nil, nil)); err != nil {
		t.Fatal(err)
	}
	if _, err := i.InformationalRequest(); err == nil {
		t.Fatal("local ID wrapped")
	}
	if i.exchanges.nextLocal != uint64(math.MaxUint32)+1 {
		t.Fatal("lost exhausted state")
	}
	i.exchanges.nextRemote = math.MaxUint32
	request := peerInformation(t, i, math.MaxUint32, false, nil, nil)
	reply, err := i.HandleInformational(request)
	if err != nil {
		t.Fatal(err)
	}
	replay, err := i.HandleInformational(request)
	if err != nil || !bytes.Equal(reply, replay) {
		t.Fatal("last reply not replayable after exhaustion")
	}
	if _, err := i.HandleInformational(peerInformation(t, i, 0, false, nil, nil)); err == nil {
		t.Fatal("remote ID wrapped")
	}
	if i.exchanges.nextRemote != uint64(math.MaxUint32)+1 {
		t.Fatal("lost remote exhausted state")
	}
}
