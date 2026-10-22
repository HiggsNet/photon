package ike

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func fragmentPeerExchange(t *testing.T, i *Initiator, packet []byte) [][]byte {
	t.Helper()
	h, _, err := DecodeHeader(packet)
	if err != nil {
		t.Fatal(err)
	}
	first, plain, err := OpenSK(packet, i.init.Keys.SKER, i.init.Keys.SKAR)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := SealSKF(h, first, plain, i.init.Keys.SKER, i.init.Keys.SKAR, 100, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return packets
}

func decodeFragments(t *testing.T, i *Initiator, packets [][]byte) *ExchangeMessage {
	t.Helper()
	var completed *ExchangeMessage
	for n := len(packets) - 1; n >= 0; n-- {
		m, err := i.DecodeExchange(packets[n], time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if m != nil {
			if completed != nil {
				t.Fatal("completed twice")
			}
			completed = m
		}
	}
	if completed == nil {
		t.Fatal("no completed exchange")
	}
	return completed
}

func TestPostAuthFragmentedChildResponseAndRetransmission(t *testing.T) {
	i := informationalFixture(t)
	i.peerFragmentation = true
	c := childExchangeConfig(i, 0x11223344, GroupP256)
	if _, err := i.ChildRequest(c); err != nil {
		t.Fatal(err)
	}
	packets, err := i.PendingRequestPackets(100)
	if err != nil || len(packets) < 2 {
		t.Fatal("outbound fragmentation failed", err)
	}
	first := bytes.Clone(packets[0])
	clear(packets[0])
	retries, err := i.PendingRequestPackets(120)
	if err != nil || !bytes.Equal(retries[0], first) {
		t.Fatal("outbound cache mutated or refragmented")
	}
	c.Child.InitiatorSPI = 0x55667788
	p, _ := newChildPending(c)
	ps, _ := childPayloads(c, p.nonce, p.private, false)
	peer := peerChildPacket(t, i, 2, true, ps)
	fragments := fragmentPeerExchange(t, i, peer)
	for n, f := range fragments {
		if n == 0 {
			forged := bytes.Clone(f)
			forged[len(forged)-1] ^= 1
			if _, err := i.DecodeExchange(forged, time.Now()); err == nil {
				t.Fatal("forged fragment accepted")
			}
		}
		m, err := i.DecodeExchange(f, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if n < len(fragments)-1 {
			if m != nil || i.exchanges.nextLocal != 2 || i.PendingRequest() == nil {
				t.Fatal("incomplete fragment completed exchange")
			}
			continue
		}
		result, err := i.HandleExchange(m, nil)
		if err != nil || result.Child == nil || result.Child.Child.ResponderSPI != c.Child.InitiatorSPI {
			t.Fatal("fragmented CHILD response failed", err)
		}
		if _, err := i.HandleExchange(m, nil); err == nil {
			t.Fatal("opaque response reused after completion")
		}
	}
}

func TestPostAuthFragmentInspectAuthorizationAndReplay(t *testing.T) {
	i := informationalFixture(t)
	i.peerFragmentation = true
	peer := childExchangeConfig(i, 0x11223344, GroupP256)
	peer.Child.LocalSelectors, peer.Child.RemoteSelectors = peer.Child.RemoteSelectors, peer.Child.LocalSelectors
	p, _ := newChildPending(peer)
	ps, _ := childPayloads(peer, p.nonce, p.private, false)
	wire := peerChildPacket(t, i, 0, false, ps)
	packets := fragmentPeerExchange(t, i, wire)
	m := decodeFragments(t, i, packets)
	if m.Header().MessageID != 0 {
		t.Fatal("wrong decoded header")
	}
	offer, err := i.InspectChildExchange(m)
	if err != nil || offer.LocalSelectors[0] != i.auth.child.LocalSelectors[0] {
		t.Fatal("inspection orientation", err)
	}
	offer.LocalSelectors[0].StartPort = 65535
	if _, err := i.HandleExchange(m, nil); err == nil {
		t.Fatal("peer offer bypassed policy")
	}
	other := informationalFixture(t)
	if _, err := other.HandleExchange(m, nil); err == nil {
		t.Fatal("message accepted by another session")
	}
	authorized := childExchangeConfig(i, 0x55667788, GroupP256)
	result, err := i.HandleExchange(m, &authorized)
	if err != nil || result.Child == nil {
		t.Fatal("authenticated child failed", err)
	}
	reply, err := i.ReplyPackets(result.Reply, 100)
	if err != nil || len(reply) < 2 {
		t.Fatal("reply fragmentation failed", err)
	}
	response0 := bytes.Clone(reply[0])
	clear(reply[0])
	// Complete retransmission uses the same authenticated canonical content.
	duplicate := decodeFragments(t, i, packets)
	replay, err := i.HandleExchange(duplicate, &ChildExchangeConfig{})
	if err != nil || replay.Child != nil || !bytes.Equal(replay.Reply, result.Reply) {
		t.Fatal("fragment replay installed twice", err)
	}
	again, err := i.ReplyPackets(replay.Reply, 120)
	if err != nil || !bytes.Equal(again[0], response0) {
		t.Fatal("reply fragment cache changed")
	}
	// One last-request fragment cannot monopolize the next request's slot.
	if m, err := i.DecodeExchange(packets[0], time.Now()); err != nil || m != nil {
		t.Fatal("partial replay", err)
	}
	nextWire := peerChildPacket(t, i, 1, false, ps)
	nextFragments := fragmentPeerExchange(t, i, nextWire)
	if _, err := i.DecodeExchange(nextFragments[0], time.Now()); err != nil {
		t.Fatal("new request could not replace incomplete replay", err)
	}
	i.ResetExchangeFragments()
	if i.exchanges.fragmentRequest.total != 0 {
		t.Fatal("fragment timeout reset retained state")
	}
}

func TestPostAuthFragmentRequiresNegotiationAndWindow(t *testing.T) {
	i := informationalFixture(t)
	c := childExchangeConfig(i, 0x11223344, 0)
	p, _ := newChildPending(c)
	ps, _ := childPayloads(c, p.nonce, nil, false)
	fragments := fragmentPeerExchange(t, i, peerChildPacket(t, i, 0, false, ps))
	if _, err := i.DecodeExchange(fragments[0], time.Now()); err == nil {
		t.Fatal("unnegotiated SKF accepted")
	}
	i.peerFragmentation = true
	future := fragmentPeerExchange(t, i, peerChildPacket(t, i, 1, false, ps))
	if _, err := i.DecodeExchange(future[0], time.Now()); err == nil || i.exchanges.fragmentRequest.total != 0 {
		t.Fatal("future ID allocated reassembly")
	}
}
