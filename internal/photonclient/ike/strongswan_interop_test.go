package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"net"
	"os"
	"testing"
	"time"
)

// TestStrongSwanSAInit is opt-in and runs only against the isolated responder
// created by docs/scripts/ike-init-smoke.sh. SA_INIT is unauthenticated; success
// proves proposal/KE/nonce compatibility and (via a protected rejection) key
// agreement, not peer identity or a CHILD SA.
func TestStrongSwanSAInit(t *testing.T) {
	peer := os.Getenv("PHOTON_IKE_INIT_PEER")
	if peer == "" {
		t.Skip("run docs/scripts/ike-init-smoke.sh for isolated StrongSwan interop")
	}
	addr, err := net.ResolveUDPAddr("udp4", peer)
	if err != nil {
		t.Fatal(err)
	}
	if !addr.IP.IsLoopback() {
		t.Fatal("SA_INIT smoke requires an isolated loopback responder")
	}
	conn, err := net.DialUDP("udp4", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	initiator, err := NewInitiator()
	if err != nil {
		t.Fatal(err)
	}
	request := initiator.Request()
	var response []byte
	for attempt := 0; attempt < 3; attempt++ {
		if !bytes.Equal(request, initiator.Request()) {
			t.Fatal("retransmitted SA_INIT changed bytes")
		}
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(request); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 65535)
		n, err := conn.Read(buf)
		if err == nil {
			response = buf[:n]
			break
		}
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatal(err)
		}
	}
	if response == nil {
		t.Fatal("StrongSwan did not respond to SA_INIT")
	}
	result, err := initiator.HandleInitResponse(response)
	if err != nil {
		t.Fatalf("StrongSwan SA_INIT rejected: %v", err)
	}
	if result.ResponderSPI == 0 || len(result.Nonce) < 16 {
		t.Fatal("incomplete responder SPI/nonce")
	}
	t.Logf("StrongSwan accepted portable SA_INIT (%d request bytes, %d response bytes); peer remains unauthenticated", len(request), len(response))

	// An intentionally incomplete IKE_AUTH must be rejected. Decrypting its
	// protected error proves both directions derived matching encryption and
	// integrity keys without claiming authentication or CHILD establishment.
	header, _, err := DecodeHeader(request)
	if err != nil {
		t.Fatal(err)
	}
	header.ResponderSPI = result.ResponderSPI
	header.ExchangeType = 35 // IKE_AUTH
	header.MessageID = 1
	first, plaintext, err := EncodePayloads([]Payload{{Type: 35, Data: append([]byte{11, 0, 0, 0}, []byte("photon-init-negative-probe")...)}}) // IDi, ID_KEY_ID
	if err != nil {
		t.Fatal(err)
	}
	probe, err := SealSK(header, first, plaintext, result.Keys.SKEI, result.Keys.SKAI, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write(probe); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 65535)
	n, err := conn.Read(buf)
	if err != nil {
		t.Fatalf("read protected negative IKE_AUTH response: %v", err)
	}
	responseHeader, _, err := DecodeHeader(buf[:n])
	if err != nil {
		t.Fatal(err)
	}
	if responseHeader.InitiatorSPI != header.InitiatorSPI || responseHeader.ResponderSPI != header.ResponderSPI || responseHeader.ExchangeType != 35 || responseHeader.MessageID != 1 || responseHeader.Flags != FlagResponse {
		t.Fatalf("unexpected negative response header: %+v", responseHeader)
	}
	first, plaintext, err = OpenSK(buf[:n], result.Keys.SKER, result.Keys.SKAR)
	if err != nil {
		t.Fatalf("peer key agreement failed: %v", err)
	}
	payloads, err := DecodePayloads(first, plaintext)
	if err != nil {
		t.Fatal(err)
	}
	for _, payload := range payloads {
		if payload.Type == PayloadNotify && len(payload.Data) >= 4 {
			notifyType := binary.BigEndian.Uint16(payload.Data[2:4])
			if notifyType == 7 || notifyType == 24 { // INVALID_SYNTAX or AUTHENTICATION_FAILED
				t.Logf("matching bidirectional key material verified by protected rejection notify %d; no authenticated IKE or CHILD SA", notifyType)
				return
			}
		}
	}
	t.Fatalf("expected protected syntax/authentication rejection, got %#v", payloads)
}
