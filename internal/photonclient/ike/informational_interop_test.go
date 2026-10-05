//go:build linux

package ike

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// TestStrongSwanInformational runs only in the isolated IKE_AUTH smoke rig.
// It proves post-authentication liveness, including a lost-response retry.
func TestStrongSwanInformational(t *testing.T) {
	if os.Getenv("PHOTON_IKE_AUTH_SMOKE") != "1" {
		t.Skip("run docs/scripts/ike-auth-smoke.sh for isolated StrongSwan INFORMATIONAL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	vici, err := ipsec.NewGoviciClient("/tmp/ike-auth.vici")
	if err != nil {
		t.Fatal(err)
	}
	defer vici.Close()
	driver := &ipsec.StrongSwanDriver{VICI: vici}
	serverPub, serverPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	clientPub, clientPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	serverDER, err := x509.MarshalPKCS8PrivateKey(serverPriv)
	if err != nil {
		t.Fatal(err)
	}
	clientDER, err := x509.MarshalPKIXPublicKey(clientPub)
	if err != nil {
		t.Fatal(err)
	}
	const name = "photon-portable-informational"
	const serverID = "informational-gateway.photon.test."
	const clientID = "informational-leaf.photon.test."
	if err := driver.LoadPrivateKey(ctx, name, serverDER, ipsec.AlgorithmEd25519); err != nil {
		t.Fatal(err)
	}
	defer driver.UnloadPrivateKey(context.Background(), name)
	spec := ipsec.TransportLinkSpec{
		TransportID: name, LocalZone: serverID, PeerZone: clientID,
		LocalAddress: "127.0.0.1", XFRMIfID: 424245,
		LocalTunnelAddr: netip.MustParseAddr("10.55.2.1"), PeerTunnelAddr: netip.MustParseAddr("10.55.2.2"),
		LocalPrivateKey: serverDER, LocalPrivateKeyAlgorithm: ipsec.AlgorithmEd25519, PeerPublicKey: clientDER,
	}
	if err := driver.LoadConnection(ctx, spec); err != nil {
		t.Fatal(err)
	}
	defer driver.UnloadConnection(context.Background(), name)
	for index, transport := range []string{"udp500", "natt4500"} {
		t.Run(transport, func(t *testing.T) {
			defer driver.TerminateSA(context.Background(), name)
			conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.Close()
			peer := netip.MustParseAddrPort("127.0.0.1:500")
			var i *Initiator
			if transport == "natt4500" {
				i, err = NewInitiatorWithEndpoints(conn.LocalAddr().(*net.UDPAddr).AddrPort(), peer)
			} else {
				i, err = NewInitiator()
			}
			if err != nil {
				t.Fatal(err)
			}
			// SA_INIT always uses UDP500. Switch to marker-framed UDP4500 only
			// after the peer's forced encapsulation has been verified by NAT-D.
			natt := false
			roundTrip := func(request []byte) []byte {
				t.Helper()
				if natt {
					var err error
					request, err = EncapsulateIKE(request)
					if err != nil {
						t.Fatal(err)
					}
				}
				for attempt := 0; attempt < 3; attempt++ {
					if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
						t.Fatal(err)
					}
					if _, err := conn.WriteToUDPAddrPort(request, peer); err != nil {
						t.Fatal(err)
					}
					response := make([]byte, 65535)
					n, from, err := conn.ReadFromUDPAddrPort(response)
					if err != nil {
						if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
							continue
						}
						t.Fatal(err)
					}
					if from != peer {
						t.Fatalf("response from unexpected endpoint %s", from)
					}
					response = response[:n]
					if natt {
						kind, packet, err := ParseNATDatagram(response)
						if err != nil || kind != NATDatagramIKE {
							t.Fatalf("invalid NAT-T IKE response: kind=%v error=%v", kind, err)
						}
						return packet
					}
					return response
				}
				t.Fatal("StrongSwan did not respond")
				return nil
			}
			initial, err := i.HandleInitResponse(roundTrip(i.Request()))
			if err != nil {
				t.Fatal(err)
			}
			if transport == "natt4500" {
				if !initial.NAT.Required() {
					t.Fatal("production forced encapsulation was not detected")
				}
				natt = true
				peer = netip.MustParseAddrPort("127.0.0.1:4500")
			}
			selector := TrafficSelector{StartAddr: netip.MustParseAddr("0.0.0.0"), EndAddr: netip.MustParseAddr("255.255.255.255"), EndPort: 65535}
			request, err := i.AuthRequest(AuthConfig{
				LocalID: clientID, RemoteID: serverID, PrivateKey: clientPriv, RemotePublicKey: serverPub,
				Child: ChildConfig{InitiatorSPI: 0x12345780 + uint32(index), LocalSelectors: []TrafficSelector{selector}, RemoteSelectors: []TrafficSelector{selector}},
			})
			if err != nil {
				t.Fatal(err)
			}
			if _, err := i.HandleAuthResponse(roundTrip(request)); err != nil {
				t.Fatal(err)
			}
			for messageID := uint32(2); messageID <= 3; messageID++ {
				request, err := i.InformationalRequest()
				if err != nil {
					t.Fatal(err)
				}
				header, _, err := DecodeHeader(request)
				if err != nil {
					t.Fatal(err)
				}
				if header.MessageID != messageID || header.ExchangeType != ExchangeInformational {
					t.Fatalf("unexpected liveness request header: %+v", header)
				}
				response := roundTrip(request)
				if messageID == 2 {
					// Discard the first response without committing the exchange, as if
					// it were lost in transit, and ask StrongSwan for its cached reply.
					retry := i.PendingInformationalRequest()
					if !bytes.Equal(request, retry) {
						t.Fatal("pending liveness retransmission changed ciphertext")
					}
					retriedResponse := roundTrip(retry)
					if !bytes.Equal(response, retriedResponse) {
						t.Fatal("StrongSwan did not retransmit its cached response")
					}
					response = retriedResponse
				}
				if reply, err := i.HandleInformational(response); err != nil || reply != nil {
					t.Fatalf("liveness message ID %d: unexpected reply=%t, error=%v", messageID, reply != nil, err)
				}
			}
			sas, err := driver.ListSAs(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, sa := range sas {
				if sa.Name == name && sa.IKEState == "ESTABLISHED" && sa.ChildState == "INSTALLED" {
					t.Log("two authenticated empty INFORMATIONAL exchanges and same-ciphertext retransmission passed; IKE and CHILD remain established")
					return
				}
			}
			t.Fatal("StrongSwan IKE/CHILD did not remain established after liveness")
		})
	}
}
