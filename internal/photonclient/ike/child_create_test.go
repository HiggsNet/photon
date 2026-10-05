package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"testing"
)

func childExchangeConfig(i *Initiator, spi uint32, group uint16) ChildExchangeConfig {
	return ChildExchangeConfig{Child: ChildConfig{InitiatorSPI: spi, LocalSelectors: append([]TrafficSelector(nil), i.auth.child.LocalSelectors...), RemoteSelectors: append([]TrafficSelector(nil), i.auth.child.RemoteSelectors...)}, DHGroup: group}
}

func peerChildPacket(t *testing.T, i *Initiator, id uint32, response bool, ps []Payload) []byte {
	t.Helper()
	first, plain, err := EncodePayloads(ps)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint8(0)
	if response {
		flags = FlagResponse
	}
	packet, err := SealSK(Header{InitiatorSPI: i.spi, ResponderSPI: i.init.ResponderSPI, ExchangeType: ExchangeCreateChild, Flags: flags, MessageID: id}, first, plain, i.init.Keys.SKER, i.init.Keys.SKAR, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func openLocalChild(t *testing.T, i *Initiator, packet []byte) childOffer {
	t.Helper()
	first, plain, err := OpenSK(packet, i.init.Keys.SKEI, i.init.Keys.SKAI)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := DecodePayloads(first, plain)
	if err != nil {
		t.Fatal(err)
	}
	o, err := parseChildOffer(ps)
	if err != nil {
		t.Fatal(err)
	}
	return o
}

func TestChildCreateLocalAndPeerWithPFS(t *testing.T) {
	for _, group := range []uint16{0, GroupP256} {
		t.Run(string(rune('a'+group)), func(t *testing.T) {
			i := informationalFixture(t)
			local := childExchangeConfig(i, 0x22334455, group)
			packet, err := i.ChildRequest(local)
			if err != nil {
				t.Fatal(err)
			}
			request := openLocalChild(t, i, packet)
			if request.spi != local.Child.InitiatorSPI || request.group != group {
				t.Fatal("wrong local proposal")
			}
			if _, err := i.InformationalRequest(); err == nil {
				t.Fatal("liveness bypassed CHILD pending slot")
			}
			original := bytes.Clone(packet)
			clear(packet)
			if !bytes.Equal(original, i.PendingRequest()) {
				t.Fatal("CHILD request storage escaped")
			}
			peer := local
			peer.Child.InitiatorSPI = 0x66778899
			p, err := newChildPending(peer)
			if err != nil {
				t.Fatal(err)
			}
			ps, err := childPayloads(peer, p.nonce, p.private, false)
			if err != nil {
				t.Fatal(err)
			}
			result, err := i.HandleChildResponse(peerChildPacket(t, i, 2, true, ps))
			if err != nil {
				t.Fatal(err)
			}
			var shared []byte
			if p.private != nil {
				shared, err = P256SharedSecret(p.private, request.ke)
				if err != nil {
					t.Fatal(err)
				}
			}
			expected, err := DeriveChildExchangeKeys(i.init.Keys.SKD, shared, request.nonce, p.nonce)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(result.Child.Keys.InitiatorToResponder, expected.InitiatorToResponder) || !bytes.Equal(result.Child.Keys.ResponderToInitiator, expected.ResponderToInitiator) {
				t.Fatal("local keys do not agree with peer")
			}
			clear(result.Child.Keys.InitiatorToResponder)
			if bytes.Equal(i.children[local.Child.InitiatorSPI].result.Keys.InitiatorToResponder, result.Child.Keys.InitiatorToResponder) {
				t.Fatal("CHILD key storage escaped")
			}
			// Peer-initiated exchange uses its own ID zero and reverses key direction.
			offerConfig := childExchangeConfig(i, 0x778899aa, group)
			offerConfig.Child.LocalSelectors, offerConfig.Child.RemoteSelectors = offerConfig.Child.RemoteSelectors, offerConfig.Child.LocalSelectors
			peerPending, err := newChildPending(offerConfig)
			if err != nil {
				t.Fatal(err)
			}
			offerPS, err := childPayloads(offerConfig, peerPending.nonce, peerPending.private, false)
			if err != nil {
				t.Fatal(err)
			}
			peerPacket := peerChildPacket(t, i, 0, false, offerPS)
			authorized := childExchangeConfig(i, 0x33445566, group)
			reply, result, err := i.HandleChildRequest(peerPacket, authorized)
			if err != nil {
				t.Fatal(err)
			}
			selection := openLocalChild(t, i, reply)
			var peerShared []byte
			if peerPending.private != nil {
				peerShared, err = P256SharedSecret(peerPending.private, selection.ke)
				if err != nil {
					t.Fatal(err)
				}
			}
			expected, err = DeriveChildExchangeKeys(i.init.Keys.SKD, peerShared, peerPending.nonce, selection.nonce)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(result.Child.Keys.InitiatorToResponder, expected.ResponderToInitiator) || !bytes.Equal(result.Child.Keys.ResponderToInitiator, expected.InitiatorToResponder) {
				t.Fatal("peer-initiated keys reversed incorrectly")
			}
			duplicate, installed, err := i.HandleChildRequest(peerPacket, ChildExchangeConfig{})
			if err != nil || installed != nil || !bytes.Equal(duplicate, reply) {
				t.Fatal("peer retransmission not idempotent")
			}
			h, _, _ := DecodeHeader(reply)
			if h.Flags != FlagInitiator|FlagResponse || h.MessageID != 0 {
				t.Fatal("reply direction or ID wrong")
			}
			// A subsequent liveness uses ID 3, proving all local exchanges share IDs.
			live, err := i.InformationalRequest()
			if err != nil {
				t.Fatal(err)
			}
			h, _, _ = DecodeHeader(live)
			if h.MessageID != 3 {
				t.Fatal("CHILD did not consume shared ID")
			}
		})
	}
}

func TestChildRekeyKeepsOldAndValidatesAssociation(t *testing.T) {
	i := informationalFixture(t)
	old := i.auth.child.InitiatorSPI
	c := childExchangeConfig(i, 0x11223344, GroupP256)
	c.RekeySPI = old
	request, err := i.ChildRequest(c)
	if err != nil {
		t.Fatal(err)
	}
	offer := openLocalChild(t, i, request)
	if offer.rekeySPI != old {
		t.Fatal("REKEY_SA must contain sender inbound SPI")
	}
	peer := c
	peer.Child.InitiatorSPI = 0x55667788
	peer.RekeySPI = 0
	pending, _ := newChildPending(peer)
	ps, _ := childPayloads(peer, pending.nonce, pending.private, false)
	result, err := i.HandleChildResponse(peerChildPacket(t, i, 2, true, ps))
	if err != nil {
		t.Fatal(err)
	}
	if result.RekeySPI != old || i.children[old] == nil || i.children[c.Child.InitiatorSPI] == nil {
		t.Fatal("rekey removed old SA before Delete")
	}
	// A peer rekey must name the old peer's inbound SPI, not ours.
	c = childExchangeConfig(i, 0x22334455, 0)
	c.RekeySPI = old
	p := childExchangeConfig(i, 0x66778899, 0)
	p.Child.LocalSelectors, p.Child.RemoteSelectors = p.Child.RemoteSelectors, p.Child.LocalSelectors
	pending, _ = newChildPending(p)
	ps, _ = childPayloads(p, pending.nonce, nil, false)
	notify, _ := EncodeNotify(Notify{Protocol: 3, Type: NotifyRekeySA, SPI: binary.BigEndian.AppendUint32(nil, old)})
	bad := append([]Payload{{Type: PayloadNotify, Data: notify}}, ps...)
	if reply, result, err := i.HandleChildRequest(peerChildPacket(t, i, 0, false, bad), c); err != nil || result != nil || reply == nil {
		t.Fatal("unknown peer rekey was not answered with refusal")
	}
	if i.exchanges.nextRemote != 1 || len(i.children) != 2 {
		t.Fatal("refusal did not consume request without creating a CHILD")
	}
	notify, _ = EncodeNotify(Notify{Protocol: 3, Type: NotifyRekeySA, SPI: binary.BigEndian.AppendUint32(nil, i.children[old].result.ResponderSPI)})
	good := append([]Payload{{Type: PayloadNotify, Data: notify}}, ps...)
	if _, _, err := i.HandleChildRequest(peerChildPacket(t, i, 1, false, good), c); err != nil {
		t.Fatal(err)
	}
	if i.children[old] == nil {
		t.Fatal("peer rekey removed old CHILD")
	}
}

func TestChildRejectsInvalidResponseWithoutConsumingPending(t *testing.T) {
	cases := []struct {
		name string
		edit func([]Payload) []Payload
	}{
		{"missing nonce", func(ps []Payload) []Payload { return append(ps[:1], ps[2:]...) }},
		{"DH downgrade", func(ps []Payload) []Payload { ps[0].Data, _ = EncodeChildExchangeProposal(0x44556677, 0); return ps }},
		{"invalid KE point", func(ps []Payload) []Payload { clear(ps[2].Data[4:]); return ps }},
		{"traffic expansion", func(ps []Payload) []Payload {
			ps[3].Data = append([]byte(nil), ps[3].Data...)
			ps[3].Data[12] = 0
			return ps
		}},
		{"unrequested transport", func(ps []Payload) []Payload {
			return append(ps, Payload{Type: PayloadNotify, Data: []byte{0, 0, 0x40, 7}})
		}},
		{"reused SPI", func(ps []Payload) []Payload { binary.BigEndian.PutUint32(ps[0].Data[8:], 0x50607080); return ps }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			i := informationalFixture(t)
			c := childExchangeConfig(i, 0x11223344, GroupP256)
			original, err := i.ChildRequest(c)
			if err != nil {
				t.Fatal(err)
			}
			c.Child.InitiatorSPI = 0x44556677
			p, _ := newChildPending(c)
			ps, _ := childPayloads(c, p.nonce, p.private, false)
			malformed := tc.edit(ps)
			if _, err := i.HandleChildResponse(peerChildPacket(t, i, 2, true, malformed)); err == nil {
				t.Fatal("bad response accepted")
			}
			if !bytes.Equal(i.PendingRequest(), original) || i.exchanges.nextLocal != 2 || len(i.children) != 1 {
				t.Fatal("bad response changed session")
			}
		})
	}
}

func TestChildProposalAndKeyInputs(t *testing.T) {
	for _, group := range []uint16{0, GroupP256} {
		b, err := EncodeChildExchangeProposal(0x12345678, group)
		if err != nil {
			t.Fatal(err)
		}
		spi, g, err := decodeChildExchangeProposal(b)
		if err != nil || spi != 0x12345678 || g != group {
			t.Fatal("proposal roundtrip")
		}
	}
	if _, err := EncodeChildExchangeProposal(256, 14); err == nil {
		t.Fatal("unsupported DH accepted")
	}
	skD := bytes.Repeat([]byte{1}, 32)
	ni := bytes.Repeat([]byte{2}, 32)
	nr := bytes.Repeat([]byte{3}, 32)
	initial, _ := DeriveInitialChildKeys(skD, ni, nr)
	got, err := DeriveChildExchangeKeys(skD, nil, ni, nr)
	if err != nil || !bytes.Equal(initial.InitiatorToResponder, got.InitiatorToResponder) || !bytes.Equal(initial.ResponderToInitiator, got.ResponderToInitiator) {
		t.Fatal("no-PFS derivation mismatch")
	}
	withPFS, _ := DeriveChildExchangeKeys(skD, bytes.Repeat([]byte{4}, 32), ni, nr)
	if bytes.Equal(got.InitiatorToResponder, withPFS.InitiatorToResponder) {
		t.Fatal("DH secret did not affect key material")
	}
	if _, err := DeriveChildExchangeKeys(skD, []byte{1}, ni, nr); err == nil {
		t.Fatal("bad DH length accepted")
	}
}

func TestChildPendingReservesSPIAndCapacity(t *testing.T) {
	i := informationalFixture(t)
	c := childExchangeConfig(i, 0x11223344, 0)
	if _, err := i.ChildRequest(c); err != nil {
		t.Fatal(err)
	}
	if err := i.validateChildConfig(c); err == nil {
		t.Fatal("peer could claim pending local SPI")
	}
	for n := uint32(0); len(i.children) < maxChildSAs-1; n++ {
		i.children[0x22000000+n] = &childSA{}
	}
	other := childExchangeConfig(i, 0x55667788, 0)
	if err := i.validateChildConfig(other); err == nil {
		t.Fatal("peer could consume pending CHILD capacity")
	}
}
