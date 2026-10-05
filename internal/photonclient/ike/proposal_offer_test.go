package ike

import (
	"bytes"
	"encoding/binary"
	"testing"
)

func offeredTransformWire(kind uint8, id uint16, attributes ...byte) []byte {
	b := []byte{0, 0, 0, 0, kind, 0, byte(id >> 8), byte(id)}
	b = append(b, attributes...)
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}
func offeredProposalWire(protocol, number uint8, spi []byte, transforms ...[]byte) []byte {
	b := append([]byte{0, 0, 0, 0, number, protocol, byte(len(spi)), byte(len(transforms))}, spi...)
	for n, transform := range transforms {
		transform = bytes.Clone(transform)
		if n < len(transforms)-1 {
			transform[0] = 3
		}
		b = append(b, transform...)
	}
	binary.BigEndian.PutUint16(b[2:], uint16(len(b)))
	return b
}
func joinProposalOffers(proposals ...[]byte) []byte {
	var all []byte
	for n, p := range proposals {
		p = bytes.Clone(p)
		if n < len(proposals)-1 {
			p[0] = 2
		}
		all = append(all, p...)
	}
	return all
}

func espAlternatives(spi uint32) []byte {
	spiBytes := binary.BigEndian.AppendUint32(nil, spi)
	unsupported := offeredProposalWire(3, 1, spiBytes, offeredTransformWire(1, 12, 0x80, 14, 0, 128), offeredTransformWire(3, 12), offeredTransformWire(5, 0))
	supported := offeredProposalWire(3, 2, spiBytes, offeredTransformWire(1, 20, 0x80, 14, 1, 0), offeredTransformWire(1, 20, 0x80, 14, 0, 128), offeredTransformWire(1, 20, 0x80, 14, 0, 192), offeredTransformWire(5, 1), offeredTransformWire(5, 0))
	return joinProposalOffers(unsupported, supported)
}

func ikeAlternatives(spi uint64) []byte {
	spiBytes := binary.BigEndian.AppendUint64(nil, spi)
	unsupported := offeredProposalWire(1, 1, spiBytes, offeredTransformWire(1, 12, 0x80, 14, 1, 0), offeredTransformWire(2, 6), offeredTransformWire(3, 13), offeredTransformWire(4, 14))
	supported := offeredProposalWire(1, 2, spiBytes, offeredTransformWire(1, 12, 0x80, 14, 1, 0), offeredTransformWire(1, 12, 0x80, 14, 0, 128), offeredTransformWire(2, 6), offeredTransformWire(2, 5), offeredTransformWire(3, 13), offeredTransformWire(3, 12), offeredTransformWire(4, 14), offeredTransformWire(4, GroupP256))
	return joinProposalOffers(unsupported, supported)
}

func decodeLocalPayloads(t *testing.T, i *Initiator, packet []byte) []Payload {
	t.Helper()
	enc, integ := i.sendKeys()
	first, plain, err := OpenSK(packet, enc, integ)
	if err != nil {
		t.Fatal(err)
	}
	ps, err := DecodePayloads(first, plain)
	if err != nil {
		t.Fatal(err)
	}
	return ps
}

func TestPeerChildOfferAlternativesSelectFixedSuiteAndNumber(t *testing.T) {
	i := informationalFixture(t)
	offered := childExchangeConfig(i, 0x11223344, 0)
	offered.Child.LocalSelectors, offered.Child.RemoteSelectors = offered.Child.RemoteSelectors, offered.Child.LocalSelectors
	p, _ := newChildPending(offered)
	ps, _ := childPayloads(offered, p.nonce, nil, false)
	ps[0].Data = espAlternatives(offered.Child.InitiatorSPI)
	packet := peerChildPacket(t, i, 0, false, ps)
	inspected, err := i.InspectChildRequest(packet)
	if err != nil || inspected.DHGroup != 0 {
		t.Fatal("offer inspection rejected alternatives", err)
	}
	reply, result, err := i.HandleChildRequest(packet, childExchangeConfig(i, 0x55667788, 0))
	if err != nil || result == nil || result.Child.ResponderSPI != offered.Child.InitiatorSPI {
		t.Fatal("peer offer selection failed", err)
	}
	selection := decodeLocalPayloads(t, i, reply)[0].Data
	if selection[4] != 2 || selection[7] != 2 || len(selection) != 32 {
		t.Fatalf("selection lost proposal number or returned alternatives: %x", selection)
	}
	selectedCopy := bytes.Clone(selection)
	selectedCopy[4] = 1
	if spi, err := ValidateChildSelection(selectedCopy); err != nil || spi != result.Child.InitiatorSPI {
		t.Fatal("selected unsupported cipher", err)
	}
	// The strict response validator still rejects peer alternatives for our one
	// exact offer; adding request negotiation cannot silently widen it.
	other := informationalFixture(t)
	config := childExchangeConfig(other, 0x22334455, 0)
	pending, err := other.ChildRequest(config)
	if err != nil {
		t.Fatal(err)
	}
	answer, _ := newChildPending(config)
	answerPS, _ := childPayloads(config, answer.nonce, nil, false)
	answerPS[0].Data = espAlternatives(0x66778899)
	if _, err := other.HandleChildResponse(peerChildPacket(t, other, 2, true, answerPS)); err == nil || !bytes.Equal(other.PendingRequest(), pending) {
		t.Fatal("response alternatives bypassed exact offer")
	}
}

func TestPeerIKEOfferAlternativesAndAuthenticatedInvalidKE(t *testing.T) {
	i := informationalFixture(t)
	p, _ := i.newIKERekeyPending()
	ps := ikeRekeyPayloads(p)
	ps[0].Data = ikeAlternatives(p.spi)
	ps[2].Data = EncodeKE(14, bytes.Repeat([]byte{1}, 256))
	request := peerChildPacket(t, i, 0, false, ps)
	reply, result, err := i.HandleIKERekeyRequest(request)
	if err != nil || result != nil || reply == nil || i.peerRekey != nil || i.exchanges.nextRemote != 1 {
		t.Fatal("wrong KE did not get bounded authenticated error", err)
	}
	notice, err := DecodeNotify(decodeLocalPayloads(t, i, reply)[0].Data)
	if err != nil || notice.Type != 17 || len(notice.Data) != 2 || binary.BigEndian.Uint16(notice.Data) != GroupP256 {
		t.Fatal("INVALID_KE did not request supported group", err)
	}
	duplicate, again, err := i.HandleIKERekeyRequest(request)
	if err != nil || again != nil || !bytes.Equal(duplicate, reply) {
		t.Fatal("INVALID_KE replay changed response")
	}
	// A fresh request with corrected KE consumes the next shared inbound ID.
	p, _ = i.newIKERekeyPending()
	ps = ikeRekeyPayloads(p)
	ps[0].Data = ikeAlternatives(p.spi)
	reply, result, err = i.HandleIKERekeyRequest(peerChildPacket(t, i, 1, false, ps))
	if err != nil || result == nil {
		t.Fatal("corrected KE failed", err)
	}
	selection := decodeLocalPayloads(t, i, reply)[0].Data
	if selection[4] != 2 || selection[7] != 4 {
		t.Fatal("IKE response did not preserve selected proposal")
	}
	selection = bytes.Clone(selection)
	selection[4] = 1
	if _, err := decodeIKERekeyProposal(selection); err != nil {
		t.Fatal("selected wrong IKE suite", err)
	}
}

func TestMalformedProposalOffersNeverMutateSession(t *testing.T) {
	tests := []struct {
		name   string
		mutate func([]byte) []byte
	}{
		{"proposal count chain", func(b []byte) []byte { b[0] = 0; return b }},
		{"duplicate number", func(b []byte) []byte { offset := int(binary.BigEndian.Uint16(b[2:])); b[offset+4] = b[4]; return b }},
		{"truncated proposal", func(b []byte) []byte { return b[:len(b)-1] }},
		{"zero transforms", func(b []byte) []byte { b[7] = 0; return b }},
		{"transform count overflow", func(b []byte) []byte { b[7] = 65; return b }},
		{"malformed attribute", func(b []byte) []byte { b[20] = 0; binary.BigEndian.PutUint16(b[22:], 65535); return b }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			i := informationalFixture(t)
			c := childExchangeConfig(i, 0x11223344, 0)
			c.Child.LocalSelectors, c.Child.RemoteSelectors = c.Child.RemoteSelectors, c.Child.LocalSelectors
			p, _ := newChildPending(c)
			ps, _ := childPayloads(c, p.nonce, nil, false)
			ps[0].Data = tc.mutate(espAlternatives(c.Child.InitiatorSPI))
			packet := peerChildPacket(t, i, 0, false, ps)
			if _, err := i.InspectChildRequest(packet); err == nil {
				t.Fatal("malformed offer inspected as valid")
			}
			if _, _, err := i.HandleChildRequest(packet, childExchangeConfig(i, 0x55667788, 0)); err == nil {
				t.Fatal("malformed offer accepted")
			}
			if i.exchanges.nextRemote != 0 || len(i.children) != 1 || i.exchanges.lastRequest != nil {
				t.Fatal("malformed offer changed session")
			}
		})
	}
}

func TestPeerChildInvalidKECannotBypassPFSSelection(t *testing.T) {
	i := informationalFixture(t)
	c := childExchangeConfig(i, 0x11223344, GroupP256)
	c.Child.LocalSelectors, c.Child.RemoteSelectors = c.Child.RemoteSelectors, c.Child.LocalSelectors
	p, _ := newChildPending(c)
	ps, _ := childPayloads(c, p.nonce, p.private, false)
	ps[2].Data = EncodeKE(14, bytes.Repeat([]byte{2}, 256))
	packet := peerChildPacket(t, i, 0, false, ps)
	reply, result, err := i.HandleChildRequest(packet, childExchangeConfig(i, 0x55667788, GroupP256))
	if err != nil || result != nil || reply == nil || len(i.children) != 1 {
		t.Fatal("wrong CHILD KE established PFS SA", err)
	}
	notice, _ := DecodeNotify(decodeLocalPayloads(t, i, reply)[0].Data)
	if notice.Type != 17 {
		t.Fatal("missing INVALID_KE")
	}
	// The unauthenticated version cannot consume the inbound counter.
	packet = peerChildPacket(t, i, 1, false, ps)
	packet[len(packet)-1] ^= 1
	if _, _, err := i.HandleChildRequest(packet, childExchangeConfig(i, 0x55667788, GroupP256)); err == nil || i.exchanges.nextRemote != 1 {
		t.Fatal("forged KE request changed state")
	}
}

func TestChildNoneSelectionIgnoresOtherProposalKE(t *testing.T) {
	// RFC 7296 3.4 exempts a selected NONE transform from INVALID_KE. A KE for
	// another offered suite is ignored, never treated as negotiated PFS.
	i := informationalFixture(t)
	c := childExchangeConfig(i, 0x11223344, 0)
	c.Child.LocalSelectors, c.Child.RemoteSelectors = c.Child.RemoteSelectors, c.Child.LocalSelectors
	p, _ := newChildPending(c)
	ps, _ := childPayloads(c, p.nonce, nil, false)
	spi := binary.BigEndian.AppendUint32(nil, c.Child.InitiatorSPI)
	unsupported := offeredProposalWire(3, 1, spi, offeredTransformWire(1, 12, 0x80, 14, 0, 128), offeredTransformWire(3, 12), offeredTransformWire(4, 14), offeredTransformWire(5, 0))
	none, _ := EncodeChildExchangeProposal(c.Child.InitiatorSPI, 0)
	none[4] = 2
	ps[0].Data = joinProposalOffers(unsupported, none)
	ps = append(ps, Payload{Type: PayloadKE, Data: EncodeKE(14, bytes.Repeat([]byte{1}, 256))})
	reply, result, err := i.HandleChildRequest(peerChildPacket(t, i, 0, false, ps), childExchangeConfig(i, 0x55667788, 0))
	if err != nil || result == nil || reply == nil {
		t.Fatal("NONE incorrectly rejected another offer's KE", err)
	}
	for _, p := range decodeLocalPayloads(t, i, reply) {
		if p.Type == PayloadKE {
			t.Fatal("NONE selected but KE returned")
		}
	}
}
