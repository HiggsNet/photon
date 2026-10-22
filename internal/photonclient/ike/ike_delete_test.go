package ike

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func peerIKEDelete(t *testing.T, i *Initiator, id uint32, response bool) []byte {
	t.Helper()
	var ps []Payload
	flags := uint8(0)
	if response {
		flags = FlagResponse
	} else {
		ps = []Payload{{Type: PayloadDelete, Data: []byte{1, 0, 0, 0}}}
	}
	first, plain, _ := EncodePayloads(ps)
	packet, err := SealSK(Header{InitiatorSPI: i.spi, ResponderSPI: i.init.ResponderSPI, ExchangeType: ExchangeInformational, Flags: flags, MessageID: id}, first, plain, i.init.Keys.SKER, i.init.Keys.SKAR, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return packet
}

func TestIKEDeleteLocalAndPeerSimultaneous(t *testing.T) {
	for _, peerInitiated := range []bool{false, true} {
		i := informationalFixture(t)
		if _, err := i.IKEDeleteRequest(); err != nil {
			t.Fatal(err)
		}
		if _, err := i.InformationalRequest(); err == nil {
			t.Fatal("closed SA began another exchange")
		}
		if peerInitiated {
			packet := peerIKEDelete(t, i, 0, false)
			m, err := i.DecodeExchange(packet, time.Now())
			if err != nil {
				t.Fatal(err)
			}
			result, err := i.HandleExchange(m, nil)
			if err != nil || result.Deleted == nil || !result.Deleted.IKE || len(result.Deleted.Removed) != 1 || len(result.Reply) == 0 {
				t.Fatal("peer IKE Delete failed", err)
			}
			duplicate, removed, err := i.HandleIKEDelete(packet)
			if err != nil || removed != nil || !bytes.Equal(duplicate, result.Reply) {
				t.Fatal("closed IKE SA lost final reply cache")
			}
			if _, _, err := i.HandleIKEDelete(peerIKEDelete(t, i, 1, false)); err == nil {
				t.Fatal("closed IKE SA accepted new request")
			}
		} else {
			_, result, err := i.HandleIKEDelete(peerIKEDelete(t, i, 2, true))
			if err != nil || !result.IKE || len(result.Removed) != 1 {
				t.Fatal("local IKE Delete failed", err)
			}
		}
		if !i.closed || i.PendingRequest() != nil || len(i.children) != 0 {
			t.Fatal("IKE close left active protocol state")
		}
	}
}

func TestUnauthenticatedIKEDeleteDoesNotClose(t *testing.T) {
	i := informationalFixture(t)
	packet := peerIKEDelete(t, i, 0, false)
	packet[len(packet)-1] ^= 1
	if _, _, err := i.HandleIKEDelete(packet); err == nil || i.closed || len(i.children) != 1 {
		t.Fatal("forged IKE Delete closed session")
	}
}
