package ike

import (
	"bytes"
	"encoding/binary"
	"testing"
	"time"
)

// mirrorIKE is an independently oriented responder session using the same
// authenticated IKE material, so both production request/response paths run.
func mirrorIKE(a *Initiator) *Initiator {
	b := &Initiator{spi: a.spi, init: cloneInitResult(a.init), authDone: true, originalResponder: true, peerFragmentation: a.peerFragmentation, exchanges: exchangeState{nextLocal: 0, nextRemote: 2}, children: make(map[uint32]*childSA)}
	for _, child := range a.children {
		c := cloneChild(child.result)
		c.InitiatorSPI, c.ResponderSPI = c.ResponderSPI, c.InitiatorSPI
		c.LocalSelectors, c.RemoteSelectors = c.RemoteSelectors, c.LocalSelectors
		c.Keys.InitiatorToResponder, c.Keys.ResponderToInitiator = c.Keys.ResponderToInitiator, c.Keys.InitiatorToResponder
		b.rememberChild(c, 0, nil)
	}
	return b
}

func completeIKERekey(t *testing.T, a, b *Initiator) (*Initiator, *Initiator) {
	t.Helper()
	request, err := a.IKERekeyRequest()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := a.InformationalRequest(); err == nil {
		t.Fatal("IKE rekey did not share pending slot")
	}
	reply, peerResult, err := b.HandleIKERekeyRequest(request)
	if err != nil || peerResult == nil {
		t.Fatal("peer rekey", err)
	}
	again, duplicate, err := b.HandleIKERekeyRequest(request)
	if err != nil || duplicate != nil || !bytes.Equal(again, reply) {
		t.Fatal("IKE rekey replay created duplicate candidate")
	}
	localResult, err := a.HandleIKERekeyResponse(reply)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := localResult.Session.InformationalRequest(); err == nil {
		t.Fatal("unadopted successor activated early")
	}
	ar, err := a.AdoptIKERekey()
	if err != nil {
		t.Fatal(err)
	}
	br, err := b.AdoptIKERekey()
	if err != nil {
		t.Fatal(err)
	}
	if ar.Surviving != localResult.Session || br.Surviving != peerResult.Session || !ar.DeleteOld || br.DeleteOld {
		t.Fatal("wrong rekey adoption")
	}
	return ar.Surviving, br.Surviving
}

func TestIKERekeyBothOriginalRolesAndChildInheritance(t *testing.T) {
	for _, peerInitiated := range []bool{false, true} {
		a := informationalFixture(t)
		b := mirrorIKE(a)
		originalLocal := a.auth.child.InitiatorSPI
		oldKeys := bytes.Clone(a.init.Keys.SKD)
		requestOwner, responseOwner := a, b
		if peerInitiated {
			requestOwner, responseOwner = b, a
		}
		requester, responder := completeIKERekey(t, requestOwner, responseOwner)
		if requester.originalResponder || !responder.originalResponder {
			t.Fatal("rekey did not reset original roles")
		}
		if !bytes.Equal(requester.init.Keys.SKD, responder.init.Keys.SKD) || bytes.Equal(requester.init.Keys.SKD, oldKeys) {
			t.Fatal("rekey keys mismatch or reused old keys")
		}
		if len(a.children) != 0 || len(b.children) != 0 || len(requester.children) != 1 || len(responder.children) != 1 {
			t.Fatal("CHILD inheritance duplicated/lost owner")
		}
		localSuccessor := requester
		if peerInitiated {
			localSuccessor = responder
		}
		if _, ok := localSuccessor.Child(originalLocal); !ok {
			t.Fatal("CHILD local direction changed across IKE role reversal")
		}
		// Counters and the original-initiator flag restart for the new IKE SA.
		ping, err := requester.InformationalRequest()
		if err != nil {
			t.Fatal(err)
		}
		h, _, _ := DecodeHeader(ping)
		if h.MessageID != 0 || h.Flags != FlagInitiator {
			t.Fatal("new initiator counter/flag wrong")
		}
		pong, err := responder.HandleInformational(ping)
		if err != nil {
			t.Fatal(err)
		}
		h, _, _ = DecodeHeader(pong)
		if h.MessageID != 0 || h.Flags != FlagResponse {
			t.Fatal("new responder reply flag wrong")
		}
		if _, err := requester.HandleInformational(pong); err != nil {
			t.Fatal(err)
		}
		ping, err = responder.InformationalRequest()
		if err != nil {
			t.Fatal(err)
		}
		h, _, _ = DecodeHeader(ping)
		if h.MessageID != 0 || h.Flags != 0 {
			t.Fatal("responder-originated counter/flag wrong")
		}
		pong, err = requester.HandleInformational(ping)
		if err != nil {
			t.Fatal(err)
		}
		h, _, _ = DecodeHeader(pong)
		if h.Flags != FlagInitiator|FlagResponse {
			t.Fatal("original initiator reply flag wrong")
		}
		if _, err := responder.HandleInformational(pong); err != nil {
			t.Fatal(err)
		}
		// Closing the old SA cannot tear down inherited CHILD state.
		closeRequest, err := requestOwner.IKEDeleteRequest()
		if err != nil {
			t.Fatal(err)
		}
		closeReply, deleted, err := responseOwner.HandleIKEDelete(closeRequest)
		if err != nil || len(deleted.Removed) != 0 || deleted.Successor != responder {
			t.Fatal("old Delete removed inherited CHILD", err)
		}
		_, deleted, err = requestOwner.HandleIKEDelete(closeReply)
		if err != nil || len(deleted.Removed) != 0 || deleted.Successor != requester {
			t.Fatal("old Delete acknowledgement lost successor", err)
		}
		if len(requester.children) != 1 || len(responder.children) != 1 {
			t.Fatal("closing old SA touched new CHILD owner")
		}
	}
}

func forceRekeyNonce(t *testing.T, i *Initiator, value byte) []byte {
	t.Helper()
	i.ikePending.nonce = bytes.Repeat([]byte{value}, 32)
	packet, err := i.sealExchange(ExchangeCreateChild, FlagInitiator, uint32(i.exchanges.nextLocal), ikeRekeyPayloads(i.ikePending))
	if err != nil {
		t.Fatal(err)
	}
	i.exchanges.pending = bytes.Clone(packet)
	return packet
}

func TestIKESimultaneousRekeyChoosesSameSurvivor(t *testing.T) {
	a := informationalFixture(t)
	b := mirrorIKE(a)
	if _, err := a.IKERekeyRequest(); err != nil {
		t.Fatal(err)
	}
	if _, err := b.IKERekeyRequest(); err != nil {
		t.Fatal(err)
	}
	ar := forceRekeyNonce(t, a, 0)
	br := forceRekeyNonce(t, b, 255)
	aReply, _, err := a.HandleIKERekeyRequest(br)
	if err != nil {
		t.Fatal(err)
	}
	bReply, _, err := b.HandleIKERekeyRequest(ar)
	if err != nil {
		t.Fatal(err)
	}
	if resolution, err := a.ResolveIKERekey(); err != nil || !resolution.Pending {
		t.Fatal("simultaneous rekey resolved prematurely")
	}
	if _, err := a.HandleIKERekeyResponse(bReply); err != nil {
		t.Fatal(err)
	}
	if _, err := b.HandleIKERekeyResponse(aReply); err != nil {
		t.Fatal(err)
	}
	ra, err := a.AdoptIKERekey()
	if err != nil {
		t.Fatal(err)
	}
	rb, err := b.AdoptIKERekey()
	if err != nil {
		t.Fatal(err)
	}
	ai, arSPI := ra.Surviving.SPIs()
	bi, brSPI := rb.Surviving.SPIs()
	if ai != bi || arSPI != brSPI || !bytes.Equal(ra.Surviving.init.Keys.SKD, rb.Surviving.init.Keys.SKD) {
		t.Fatal("peers chose different rekey survivor")
	}
	if ra.DeleteOld || !ra.DeleteRedundant || !rb.DeleteOld || rb.DeleteRedundant {
		t.Fatal("wrong simultaneous deletion responsibility")
	}
	if len(ra.Surviving.children) != 1 || len(rb.Surviving.children) != 1 || len(ra.Redundant.children) != 0 || len(rb.Redundant.children) != 0 {
		t.Fatal("redundant SA inherited CHILDs")
	}
	deleteRedundant, err := ra.Redundant.IKEDeleteRequest()
	if err != nil {
		t.Fatal(err)
	}
	reply, deleted, err := rb.Redundant.HandleIKEDelete(deleteRedundant)
	if err != nil || len(deleted.Removed) != 0 {
		t.Fatal("redundant Delete", err)
	}
	if _, _, err := ra.Redundant.HandleIKEDelete(reply); err != nil {
		t.Fatal(err)
	}
}

func TestIKERekeyPeerDeleteCancelsUnseenLocalRequest(t *testing.T) {
	a := informationalFixture(t)
	b := mirrorIKE(a)
	if _, err := a.IKERekeyRequest(); err != nil {
		t.Fatal(err)
	} // this request is lost
	request, err := b.IKERekeyRequest()
	if err != nil {
		t.Fatal(err)
	}
	reply, peerCandidate, err := a.HandleIKERekeyRequest(request)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := b.HandleIKERekeyResponse(reply); err != nil {
		t.Fatal(err)
	}
	if _, err := b.AdoptIKERekey(); err != nil {
		t.Fatal(err)
	}
	deletion, err := b.IKEDeleteRequest()
	if err != nil {
		t.Fatal(err)
	}
	_, deleted, err := a.HandleIKEDelete(deletion)
	if err != nil || deleted.Successor != peerCandidate.Session || len(deleted.Removed) != 0 || a.ikePending != nil || a.PendingRequest() != nil || len(deleted.Successor.children) != 1 {
		t.Fatal("early old Delete lost peer successor", err)
	}
}

func TestIKERekeyRefusesConcurrentChildAndRejectsMalformedResponse(t *testing.T) {
	a := informationalFixture(t)
	b := mirrorIKE(a)
	if _, err := a.ChildRequest(childExchangeConfig(a, 0x11223344, 0)); err != nil {
		t.Fatal(err)
	}
	request, err := b.IKERekeyRequest()
	if err != nil {
		t.Fatal(err)
	}
	reply, result, err := a.HandleIKERekeyRequest(request)
	if err != nil || result != nil {
		t.Fatal("CHILD collision not refused", err)
	}
	if _, err := b.HandleIKERekeyResponse(reply); err == nil || b.PendingRequest() != nil {
		t.Fatal("refusal did not finish exchange")
	}
	a = informationalFixture(t)
	b = mirrorIKE(a)
	original, err := a.IKERekeyRequest()
	if err != nil {
		t.Fatal(err)
	}
	pending, _ := b.newIKERekeyPending()
	cases := []struct {
		name string
		edit func([]Payload) []Payload
	}{
		{"missing KE", func(ps []Payload) []Payload { return ps[:2] }},
		{"invalid point", func(ps []Payload) []Payload { clear(ps[2].Data[4:]); return ps }},
		{"reused SPI", func(ps []Payload) []Payload { binary.BigEndian.PutUint64(ps[0].Data[8:], a.spi); return ps }},
		{"TS in IKE rekey", func(ps []Payload) []Payload {
			ts, _ := EncodeTrafficSelectors(a.auth.child.LocalSelectors)
			return append(ps, Payload{Type: PayloadTSi, Data: ts})
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ps := tc.edit(ikeRekeyPayloads(pending))
			packet, err := b.sealExchange(ExchangeCreateChild, FlagResponse, 2, ps)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := a.HandleIKERekeyResponse(packet); err == nil {
				t.Fatal("malformed rekey accepted")
			}
			if !bytes.Equal(original, a.PendingRequest()) || a.localRekey != nil || a.exchanges.nextLocal != 2 {
				t.Fatal("malformed rekey mutated state")
			}
		})
	}
}

func TestIKERekeyUnifiedFragmentAndKeyDerivation(t *testing.T) {
	a := informationalFixture(t)
	a.peerFragmentation = true
	b := mirrorIKE(a)
	if _, err := a.IKERekeyRequest(); err != nil {
		t.Fatal(err)
	}
	packets, err := a.PendingRequestPackets(100)
	if err != nil {
		t.Fatal(err)
	}
	var m *ExchangeMessage
	for _, packet := range packets {
		m, err = b.DecodeExchange(packet, time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	if m == nil || !m.IsIKERekey() {
		t.Fatal("fragmented IKE rekey not classified")
	}
	result, err := b.HandleExchange(m, nil)
	if err != nil || result.IKE == nil {
		t.Fatal("unified IKE rekey handler", err)
	}
	replies, err := b.ReplyPackets(result.Reply, 100)
	if err != nil {
		t.Fatal(err)
	}
	for _, packet := range replies {
		m, err = a.DecodeExchange(packet, time.Now())
		if err != nil {
			t.Fatal(err)
		}
	}
	result, err = a.HandleExchange(m, nil)
	if err != nil || result.IKE == nil {
		t.Fatal("unified IKE rekey response", err)
	}
	old := bytes.Repeat([]byte{1}, 32)
	dh := bytes.Repeat([]byte{2}, 32)
	ni := bytes.Repeat([]byte{3}, 32)
	nr := bytes.Repeat([]byte{4}, 32)
	rekey, err := DeriveRekeyIKEKeys(old, dh, ni, nr, 1, 2)
	if err != nil {
		t.Fatal(err)
	}
	initial, _ := DeriveIKEKeys(dh, ni, nr, 1, 2)
	if bytes.Equal(initial.SKD, rekey.SKD) {
		t.Fatal("rekey reused SA_INIT key derivation")
	}
	changed, _ := DeriveRekeyIKEKeys(bytes.Repeat([]byte{5}, 32), dh, ni, nr, 1, 2)
	if bytes.Equal(changed.SKD, rekey.SKD) {
		t.Fatal("old SK_d did not bind successor")
	}
	if _, err := DeriveRekeyIKEKeys(old, nil, ni, nr, 1, 2); err == nil {
		t.Fatal("IKE rekey without mandatory DH accepted")
	}
}
