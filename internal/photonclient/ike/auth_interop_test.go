//go:build linux

package ike

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/hex"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// TestStrongSwanIKEAuth uses only the isolated charon started by the smoke
// script. Credentials are generated per run and never leave the container.
func TestStrongSwanIKEAuth(t *testing.T) {
	if os.Getenv("PHOTON_IKE_AUTH_SMOKE") != "1" {
		t.Skip("run docs/scripts/ike-auth-smoke.sh for isolated StrongSwan IKE_AUTH")
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
	const connection = "photon-portable-auth"
	const serverID = "gateway.photon.test."
	const clientID = "leaf.photon.test."
	if err := driver.LoadPrivateKey(ctx, connection, serverDER, ipsec.AlgorithmEd25519); err != nil {
		t.Fatal(err)
	}
	defer driver.UnloadPrivateKey(context.Background(), connection)
	spec := ipsec.TransportLinkSpec{
		TransportID: connection, LocalZone: serverID, PeerZone: clientID,
		LocalAddress: "127.0.0.1", XFRMIfID: 424243,
		LocalTunnelAddr: netip.MustParseAddr("10.55.0.1"), PeerTunnelAddr: netip.MustParseAddr("10.55.0.2"),
		LocalPrivateKey: serverDER, LocalPrivateKeyAlgorithm: ipsec.AlgorithmEd25519, PeerPublicKey: clientDER,
	}
	// Use the actual production driver/generator, including raw public keys,
	// forced encapsulation, broad selectors and default (omitted) proposals.
	if err := driver.LoadConnection(ctx, spec); err != nil {
		t.Fatal(err)
	}
	defer driver.UnloadConnection(context.Background(), connection)
	defer driver.TerminateSA(context.Background(), connection)
	for index, scenario := range []string{"valid-ipv4", "valid-ipv6", "wrong-server-key", "wrong-server-id", "wrong-client-key"} {
		t.Run(scenario, func(t *testing.T) {
			connectionName, expectedLocalID, expectedRemoteID := connection, clientID, serverID
			selector := TrafficSelector{StartAddr: netip.MustParseAddr("0.0.0.0"), EndAddr: netip.MustParseAddr("255.255.255.255"), EndPort: 65535}
			if scenario == "valid-ipv6" {
				connectionName += "-v6"
				v6spec := spec
				v6spec.TransportID, v6spec.XFRMIfID = connectionName, spec.XFRMIfID+1
				v6spec.LocalZone, v6spec.PeerZone = "gateway-v6.photon.test.", "leaf-v6.photon.test."
				v6spec.LocalTunnelAddr, v6spec.PeerTunnelAddr = netip.MustParseAddr("fd55::1"), netip.MustParseAddr("fd55::2")
				if err := driver.LoadPrivateKey(ctx, connectionName, serverDER, ipsec.AlgorithmEd25519); err != nil {
					t.Fatal(err)
				}
				defer driver.UnloadPrivateKey(context.Background(), connectionName)
				if err := driver.LoadConnection(ctx, v6spec); err != nil {
					t.Fatal(err)
				}
				defer driver.UnloadConnection(context.Background(), connectionName)
				defer driver.TerminateSA(context.Background(), connectionName)
				expectedLocalID, expectedRemoteID = string(v6spec.PeerZone), string(v6spec.LocalZone)
				selector.StartAddr, selector.EndAddr = netip.MustParseAddr("::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
			}
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
			cfg := AuthConfig{LocalID: expectedLocalID, RemoteID: expectedRemoteID, PrivateKey: clientPriv, RemotePublicKey: serverPub,
				Child: ChildConfig{InitiatorSPI: 0x12345678 + uint32(index), LocalSelectors: []TrafficSelector{selector}, RemoteSelectors: []TrafficSelector{selector}}}
			switch scenario {
			case "wrong-server-key":
				cfg.RemotePublicKey, _, err = ed25519.GenerateKey(rand.Reader)
			case "wrong-server-id":
				cfg.RemoteID = "other.photon.test."
			case "wrong-client-key":
				_, cfg.PrivateKey, err = ed25519.GenerateKey(rand.Reader)
			}
			if err != nil {
				t.Fatal(err)
			}
			request, err := i.AuthRequest(cfg)
			if err != nil {
				t.Fatal(err)
			}
			result, err := i.HandleAuthResponse(authRoundTrip(t, conn, request))
			if !strings.HasPrefix(scenario, "valid-") {
				if err == nil || result != nil {
					t.Fatal("untrusted peer or client accepted")
				}
				if scenario == "wrong-server-key" && !strings.Contains(err.Error(), "signature") {
					t.Fatal("wrong server pin was not rejected by signature verification")
				}
				t.Logf("untrusted authentication rejected: %v", err)
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if result.RemoteID != expectedRemoteID || result.Child.InitiatorSPI != cfg.Child.InitiatorSPI || result.Child.ResponderSPI == 0 {
				t.Fatal("incorrect authenticated CHILD identity or SPI")
			}
			if len(result.Child.LocalSelectors) != 1 || len(result.Child.RemoteSelectors) != 1 || result.Child.LocalSelectors[0] != selector || result.Child.RemoteSelectors[0] != selector {
				t.Fatal("unexpected negotiated CHILD traffic selectors")
			}
			if len(result.Child.Keys.InitiatorToResponder) != 20 || len(result.Child.Keys.ResponderToInitiator) != 20 || bytes.Equal(result.Child.Keys.InitiatorToResponder, result.Child.Keys.ResponderToInitiator) {
				t.Fatal("invalid directional AES-GCM key material")
			}
			verifyKernelChildKeys(t, result.Child)
			sas, err := driver.ListSAs(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, sa := range sas {
				if sa.Name == connectionName && sa.IKEState == "ESTABLISHED" && sa.ChildState == "INSTALLED" && sa.LocalIdentity == expectedRemoteID && sa.RemoteIdentity == expectedLocalID {
					t.Logf("portable Ed25519 IKE_AUTH and first AES-GCM CHILD verified by client and StrongSwan; no ESP data-plane claim")
					return
				}
			}
			t.Fatalf("StrongSwan did not confirm authenticated IKE and installed CHILD: %+v", sas)
		})
	}
}

// Compare temporary kernel key material in memory. Never print command output
// or key bytes, including failure paths.
func verifyKernelChildKeys(t *testing.T, child ChildResult) {
	t.Helper()
	output, err := exec.Command("ip", "xfrm", "state").Output()
	if err != nil {
		t.Fatal("read isolated kernel XFRM state failed")
	}
	defer clear(output)
	wanted := map[uint32][]byte{child.ResponderSPI: child.Keys.InitiatorToResponder, child.InitiatorSPI: child.Keys.ResponderToInitiator}
	var spi uint32
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 4 && fields[0] == "proto" && fields[1] == "esp" && fields[2] == "spi" {
			parsed, err := strconv.ParseUint(fields[3], 0, 32)
			if err != nil {
				t.Fatal("invalid kernel CHILD SPI")
			}
			spi = uint32(parsed)
		}
		if len(fields) < 4 || fields[0] != "aead" {
			continue
		}
		expected, ok := wanted[spi]
		if !ok {
			continue
		}
		if fields[1] != "rfc4106(gcm(aes))" || fields[3] != "128" {
			t.Fatal("unexpected kernel CHILD algorithm")
		}
		key, err := hex.DecodeString(strings.TrimPrefix(fields[2], "0x"))
		if err != nil || !bytes.Equal(expected, key) {
			clear(key)
			t.Fatal("kernel CHILD key/salt differs from portable directional key derivation")
		}
		clear(key)
		delete(wanted, spi)
	}
	if len(wanted) != 0 {
		t.Fatal("kernel missing negotiated CHILD SPI")
	}
	t.Log("both directional AES-GCM keys/salts match isolated Linux XFRM state")
}

func authRoundTrip(t *testing.T, conn *net.UDPConn, request []byte) []byte {
	t.Helper()
	for attempt := 0; attempt < 3; attempt++ {
		if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write(request); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, 65535)
		n, err := conn.Read(response)
		if err == nil {
			return response[:n]
		}
		if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
			t.Fatal(err)
		}
	}
	t.Fatal("StrongSwan did not respond")
	return nil
}
