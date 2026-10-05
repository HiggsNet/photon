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

// A separate container sets charon.fragment_size=256 to force multiple response
// fragments without changing Photon's production connection or crypto proposals.
func TestStrongSwanFragmentation(t *testing.T) {
	if os.Getenv("PHOTON_IKE_FRAGMENT_SMOKE") != "1" {
		t.Skip("run isolated fragmentation smoke rig")
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
	const name = "photon-portable-fragment"
	const serverID = "fragment-gateway.photon.test."
	const clientID = "fragment-leaf.photon.test."
	if err := driver.LoadPrivateKey(ctx, name, serverDER, ipsec.AlgorithmEd25519); err != nil {
		t.Fatal(err)
	}
	defer driver.UnloadPrivateKey(context.Background(), name)
	spec := ipsec.TransportLinkSpec{TransportID: name, LocalZone: serverID, PeerZone: clientID, LocalAddress: "127.0.0.1", XFRMIfID: 424247, LocalTunnelAddr: netip.MustParseAddr("10.57.0.1"), PeerTunnelAddr: netip.MustParseAddr("10.57.0.2"), LocalPrivateKey: serverDER, LocalPrivateKeyAlgorithm: ipsec.AlgorithmEd25519, PeerPublicKey: clientDER}
	if err := driver.LoadConnection(ctx, spec); err != nil {
		t.Fatal(err)
	}
	defer driver.UnloadConnection(context.Background(), name)
	defer driver.TerminateSA(context.Background(), name)
	conn, err := net.DialUDP("udp4", nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 500})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	i, err := NewInitiator()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := i.HandleInitResponse(authRoundTrip(t, conn, i.Request())); err != nil {
		t.Fatal(err)
	}
	if !i.peerFragmentation {
		t.Fatal("StrongSwan did not negotiate fragmentation")
	}
	selector := TrafficSelector{StartAddr: netip.MustParseAddr("0.0.0.0"), EndAddr: netip.MustParseAddr("255.255.255.255"), EndPort: 65535}
	if _, err := i.AuthRequest(AuthConfig{LocalID: clientID, RemoteID: serverID, PrivateKey: clientPriv, RemotePublicKey: serverPub, Child: ChildConfig{InitiatorSPI: 0x17345678, LocalSelectors: []TrafficSelector{selector}, RemoteSelectors: []TrafficSelector{selector}}}); err != nil {
		t.Fatal(err)
	}
	requests, err := i.AuthRequestFragments(180)
	if err != nil {
		t.Fatal(err)
	}
	if len(requests) < 2 {
		t.Fatal("AUTH request did not split")
	}
	send := func() {
		t.Helper()
		// Reorder and duplicate a real request fragment before completing the set.
		for n := len(requests) - 1; n >= 0; n-- {
			if _, err := conn.Write(requests[n]); err != nil {
				t.Fatal(err)
			}
			if n == len(requests)-1 {
				if _, err := conn.Write(requests[n]); err != nil {
					t.Fatal(err)
				}
			}
		}
	}
	receive := func() [][]byte {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		var packets [][]byte
		total := 0
		for total == 0 || len(packets) < total {
			b := make([]byte, 65535)
			n, err := conn.Read(b)
			if err != nil {
				t.Fatal(err)
			}
			b = b[:n]
			_, next, err := DecodeHeader(b)
			if err != nil {
				t.Fatal(err)
			}
			if next != PayloadSKF || len(b) < HeaderLen+8 {
				t.Fatal("StrongSwan response is not SKF")
			}
			if total == 0 {
				total = int(b[HeaderLen+6])<<8 | int(b[HeaderLen+7])
				if total < 2 || total > maxFragments {
					t.Fatalf("response fragment count=%d", total)
				}
			}
			packets = append(packets, b)
		}
		return packets
	}
	send()
	initial := receive()
	// Simulate a lost response set and retransmit the exact original request.
	retry, err := i.AuthRequestFragments(180)
	if err != nil {
		t.Fatal(err)
	}
	for n := range requests {
		if !bytes.Equal(retry[n], requests[n]) {
			t.Fatal("retry ciphertext changed")
		}
	}
	send()
	packets := receive()
	if len(initial) != len(packets) {
		t.Fatal("response count changed on retry")
	}
	for n := range packets {
		if !bytes.Equal(initial[n], packets[n]) {
			t.Fatal("StrongSwan did not cache response fragments")
		}
	}
	var result *AuthResult
	for n := len(packets) - 1; n >= 0; n-- {
		result, err = i.HandleAuthFragment(packets[n], time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if n > 0 && result != nil {
			t.Fatal("partial response passed AUTH")
		}
	}
	if result == nil || result.RemoteID != serverID {
		t.Fatal("pinned server identity not authenticated")
	}
	sas, err := driver.ListSAs(ctx)
	if err != nil {
		t.Fatal(err)
	}
	for _, sa := range sas {
		if sa.Name == name && sa.IKEState == "ESTABLISHED" && sa.ChildState == "INSTALLED" {
			t.Logf("fragmented AUTH: request=%d response=%d; out-of-order/duplicate request, cached retransmission and pinned identity passed", len(requests), len(packets))
			return
		}
	}
	t.Fatal("StrongSwan CHILD not installed after fragmented AUTH")
}
