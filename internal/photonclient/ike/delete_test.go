package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"testing"
)

func peerDeletePacket(t *testing.T, i *Initiator, id uint32, response bool, spis []uint32) []byte {
	t.Helper()
	var ps []Payload
	if len(spis) > 0 {
		p, err := encodeChildDelete(spis)
		if err != nil {
			t.Fatal(err)
		}
		ps = []Payload{p}
	}
	first, plain, err := EncodePayloads(ps)
	if err != nil {
		t.Fatal(err)
	}
	flags := uint8(0)
	if response {
		flags = FlagResponse
	}
	packet, err := SealSK(Header{InitiatorSPI: i.spi, ResponderSPI: i.init.ResponderSPI, ExchangeType: ExchangeInformational, Flags: flags, MessageID: id}, first, plain, i.init.Keys.SKER, i.init.Keys.SKAR, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestChildDeleteLocalPeerAndSimultaneous(t *testing.T) {
	for _, simultaneous := range []bool{false, true} {
		i := informationalFixture(t)
		old := i.auth.child.InitiatorSPI
		peer := i.children[old].result.ResponderSPI
		request, err := i.ChildDeleteRequest([]uint32{old})
		if err != nil {
			t.Fatal(err)
		}
		if i.children[old] == nil {
			t.Fatal("removed before Delete acknowledgement")
		}
		if !bytes.Equal(request, i.PendingRequest()) {
			t.Fatal("Delete retransmission changed")
		}
		if _, err := i.InformationalRequest(); err == nil {
			t.Fatal("Delete did not reserve common window")
		}
		if simultaneous {
			peerRequest := peerDeletePacket(t, i, 0, false, []uint32{peer})
			reply, result, err := i.HandleChildDelete(peerRequest)
			if err != nil {
				t.Fatal(err)
			}
			if len(result.Removed) != 1 || result.Removed[0] != old || i.children[old] != nil {
				t.Fatal("simultaneous Delete did not remove old pair")
			}
			first, plain, err := OpenSK(reply, i.init.Keys.SKEI, i.init.Keys.SKAI)
			if err != nil || first != 0 || len(plain) != 0 {
				t.Fatal("simultaneous Delete must have empty reply")
			}
			duplicate, result, err := i.HandleChildDelete(peerRequest)
			if err != nil || result != nil || !bytes.Equal(duplicate, reply) {
				t.Fatal("Delete replay removed twice")
			}
		}
		peerSPIs := []uint32{peer}
		if simultaneous {
			peerSPIs = nil
		}
		reply, result, err := i.HandleChildDelete(peerDeletePacket(t, i, 2, true, peerSPIs))
		if err != nil || reply != nil {
			t.Fatal(err)
		}
		if i.children[old] != nil || i.PendingRequest() != nil {
			t.Fatal("Delete did not finish")
		}
		if simultaneous && len(result.Removed) != 0 || !simultaneous && (len(result.Removed) != 1 || result.Removed[0] != old) {
			t.Fatal("wrong removal result")
		}
	}
	i := informationalFixture(t)
	old := i.auth.child.InitiatorSPI
	peer := i.children[old].result.ResponderSPI
	reply, result, err := i.HandleChildDelete(peerDeletePacket(t, i, 0, false, []uint32{peer}))
	if err != nil {
		t.Fatal(err)
	}
	first, plain, _ := OpenSK(reply, i.init.Keys.SKEI, i.init.Keys.SKAI)
	ps, _ := DecodePayloads(first, plain)
	spis, err := parseChildDeletes(ps)
	if err != nil || len(spis) != 1 || spis[0] != old || len(result.Removed) != 1 {
		t.Fatal("peer Delete did not respond with local inbound SPI")
	}
	// A new request for the already removed SPI is answered but causes no removal.
	_, result, err = i.HandleChildDelete(peerDeletePacket(t, i, 1, false, []uint32{peer}))
	if err != nil || len(result.Removed) != 0 {
		t.Fatal("unknown SPI not ignored")
	}
}

func TestChildDeleteInvalidDoesNotRemoveOrComplete(t *testing.T) {
	i := informationalFixture(t)
	old := i.auth.child.InitiatorSPI
	pending, err := i.ChildDeleteRequest([]uint32{old})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := i.HandleChildDelete(peerDeletePacket(t, i, 2, true, []uint32{0x11112222})); err == nil {
		t.Fatal("unrequested SPI accepted")
	}
	if !bytes.Equal(pending, i.PendingRequest()) || i.children[old] == nil {
		t.Fatal("invalid response changed state")
	}
	forged := peerDeletePacket(t, i, 0, false, []uint32{i.children[old].result.ResponderSPI})
	forged[len(forged)-1] ^= 1
	if _, _, err := i.HandleChildDelete(forged); err == nil {
		t.Fatal("unauthenticated Delete accepted")
	}
	if i.children[old] == nil || i.exchanges.nextRemote != 0 {
		t.Fatal("forged Delete changed state")
	}
}

func TestChildSimultaneousRekeyResolution(t *testing.T) {
	for _, localLoses := range []bool{false, true} {
		i := informationalFixture(t)
		old := i.auth.child.InitiatorSPI
		local := childExchangeConfig(i, 0x11223344, 0)
		local.RekeySPI = old
		if _, err := i.ChildRequest(local); err != nil {
			t.Fatal(err)
		}
		// Choose known local Ni to prove each branch of the nonce comparison. The
		// response is authenticated; this fixture controls test-only pending state.
		value := byte(0xff)
		if localLoses {
			value = 0
		}
		i.childPending.nonce = bytes.Repeat([]byte{value}, 32)
		remote := childExchangeConfig(i, 0x55667788, 0)
		remote.Child.LocalSelectors, remote.Child.RemoteSelectors = remote.Child.RemoteSelectors, remote.Child.LocalSelectors
		rp, _ := newChildPending(remote)
		rp.nonce = bytes.Repeat([]byte{0x80}, 32)
		ps, _ := childPayloads(remote, rp.nonce, nil, false)
		notification, _ := EncodeNotify(Notify{Protocol: 3, Type: NotifyRekeySA, SPI: binary.BigEndian.AppendUint32(nil, i.children[old].result.ResponderSPI)})
		ps = append(ps, Payload{Type: PayloadNotify, Data: notification})
		authorized := childExchangeConfig(i, 0x22334455, 0)
		authorized.RekeySPI = old
		if _, _, err := i.HandleChildRequest(peerChildPacket(t, i, 0, false, ps), authorized); err != nil {
			t.Fatal(err)
		}
		i.children[authorized.Child.InitiatorSPI].minimumNonce = bytes.Repeat([]byte{0x80}, 32)
		resolution, err := i.ResolveChildRekey(old)
		if err != nil || !resolution.Pending || resolution.DeleteSPI != 0 {
			t.Fatal("resolved before local response")
		}
		answer := childExchangeConfig(i, 0x66778899, 0)
		ap, _ := newChildPending(answer)
		ap.nonce = bytes.Repeat([]byte{0xff}, 32)
		ps, _ = childPayloads(answer, ap.nonce, nil, false)
		if _, err := i.HandleChildResponse(peerChildPacket(t, i, 2, true, ps)); err != nil {
			t.Fatal(err)
		}
		resolution, err = i.ResolveChildRekey(old)
		if err != nil || resolution.Pending {
			t.Fatal(err)
		}
		winner, loser, deleteSPI := local.Child.InitiatorSPI, authorized.Child.InitiatorSPI, old
		if localLoses {
			winner, loser, deleteSPI = loser, winner, winner
		}
		if resolution.SurvivingSPI != winner || resolution.RedundantSPI != loser || resolution.DeleteSPI != deleteSPI {
			t.Fatalf("wrong resolution %+v", resolution)
		}
		if len(i.children) != 3 {
			t.Fatal("resolution removed receive overlap")
		}
	}
	if compareRekeyNonce([]byte{1}, []byte{1, 0}) >= 0 || compareRekeyNonce([]byte{0xff}, []byte{1, 0}) <= 0 {
		t.Fatal("nonce comparison is not octet-wise")
	}
}

func TestChildAuthenticatedRefusalCompletesOnlyMatchingExchange(t *testing.T) {
	i := informationalFixture(t)
	old := i.auth.child.InitiatorSPI
	c := childExchangeConfig(i, 0x11223344, 0)
	c.RekeySPI = old
	if _, err := i.ChildRequest(c); err != nil {
		t.Fatal(err)
	}
	notification, _ := EncodeNotify(Notify{Protocol: 3, Type: NotifyChildNotFound, SPI: binary.BigEndian.AppendUint32(nil, old+1)})
	if _, err := i.HandleChildResponse(peerChildPacket(t, i, 2, true, []Payload{{Type: PayloadNotify, Data: notification}})); err == nil || i.PendingRequest() == nil {
		t.Fatal("mismatched error consumed pending")
	}
	notification, _ = EncodeNotify(Notify{Protocol: 3, Type: NotifyChildNotFound, SPI: binary.BigEndian.AppendUint32(nil, old)})
	_, err := i.HandleChildResponse(peerChildPacket(t, i, 2, true, []Payload{{Type: PayloadNotify, Data: notification}}))
	var refusal *ChildExchangeError
	if !errors.As(err, &refusal) || refusal.Notification != NotifyChildNotFound || refusal.RemovedSPI != old || i.PendingRequest() != nil || i.children[old] != nil {
		t.Fatalf("refusal did not complete: %v", err)
	}
	if _, err := i.InformationalRequest(); err != nil {
		t.Fatal("refused exchange kept pending slot", err)
	}
}

func TestInspectChildAndDeleteRekeyCollision(t *testing.T) {
	i := informationalFixture(t)
	old := i.auth.child.InitiatorSPI
	oldPeer := i.children[old].result.ResponderSPI
	c := childExchangeConfig(i, 0x11223344, 0)
	c.Child.LocalSelectors, c.Child.RemoteSelectors = c.Child.RemoteSelectors, c.Child.LocalSelectors
	p, _ := newChildPending(c)
	ps, _ := childPayloads(c, p.nonce, nil, false)
	n, _ := EncodeNotify(Notify{Protocol: 3, Type: NotifyRekeySA, SPI: binary.BigEndian.AppendUint32(nil, oldPeer)})
	ps = append(ps, Payload{Type: PayloadNotify, Data: n})
	packet := peerChildPacket(t, i, 0, false, ps)
	offer, err := i.InspectChildRequest(packet)
	if err != nil || offer.RekeySPI != old || offer.PeerRekeySPI != oldPeer || offer.DHGroup != 0 || offer.LocalSelectors[0] != i.auth.child.LocalSelectors[0] || i.exchanges.nextRemote != 0 {
		t.Fatal("inspection changed state or orientation", err)
	}
	forged := bytes.Clone(packet)
	forged[len(forged)-1] ^= 1
	if _, err := i.InspectChildRequest(forged); err == nil {
		t.Fatal("unauthenticated inspection accepted")
	}
	if _, err := i.ChildDeleteRequest([]uint32{old}); err != nil {
		t.Fatal(err)
	}
	reply, result, err := i.HandleChildRequest(packet, ChildExchangeConfig{})
	if err != nil || result != nil || reply == nil {
		t.Fatal("rekey during Delete did not refuse", err)
	}
	first, plain, _ := OpenSK(reply, i.init.Keys.SKEI, i.init.Keys.SKAI)
	payloads, _ := DecodePayloads(first, plain)
	notice, err := DecodeNotify(payloads[0].Data)
	if err != nil || notice.Type != NotifyTemporaryFailure || i.children[old] == nil || i.exchanges.nextRemote != 1 || i.exchanges.pendingKind != exchangeDelete {
		t.Fatal("wrong collision reply/state")
	}
}
