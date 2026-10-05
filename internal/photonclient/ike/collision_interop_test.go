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

// TestStrongSwanSimultaneousChildRekey deliberately holds charon's request until
// our own CREATE_CHILD_SA is pending, then crosses both exchanges. This cannot
// pass by accidentally serializing two ordinary rekeys. Default Linux proposals
// remain unchanged; the survivor's ESP keys are compared with installed XFRM.
func TestStrongSwanSimultaneousChildRekey(t *testing.T) {
	runStrongSwanSimultaneousRekey(t, false)
}

func TestStrongSwanSimultaneousIKERekey(t *testing.T) {
	runStrongSwanSimultaneousRekey(t, true)
}

func runStrongSwanSimultaneousRekey(t *testing.T, ikeOnly bool) {
	if os.Getenv("PHOTON_IKE_AUTH_SMOKE") != "1" {
		t.Skip("run docs/scripts/ike-auth-smoke.sh")
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
	const name = "photon-simultaneous-child"
	const serverID = "collision-gateway.photon.test."
	const clientID = "collision-leaf.photon.test."
	if err := driver.LoadPrivateKey(ctx, name, serverDER, ipsec.AlgorithmEd25519); err != nil {
		t.Fatal(err)
	}
	defer driver.UnloadPrivateKey(context.Background(), name)
	spec := ipsec.TransportLinkSpec{TransportID: name, LocalZone: serverID, PeerZone: clientID, LocalAddress: "127.0.0.1", XFRMIfID: 424248, LocalTunnelAddr: netip.MustParseAddr("10.55.8.1"), PeerTunnelAddr: netip.MustParseAddr("10.55.8.2"), LocalPrivateKey: serverDER, LocalPrivateKeyAlgorithm: ipsec.AlgorithmEd25519, PeerPublicKey: clientDER}
	if err := driver.LoadConnection(ctx, spec); err != nil {
		t.Fatal(err)
	}
	defer driver.UnloadConnection(context.Background(), name)
	defer driver.TerminateSA(context.Background(), name)
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 2)})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	peer := netip.MustParseAddrPort("127.0.0.1:500")
	i, err := NewInitiatorWithEndpoints(conn.LocalAddr().(*net.UDPAddr).AddrPort(), peer)
	if err != nil {
		t.Fatal(err)
	}
	natt := false
	send := func(packet []byte) {
		t.Helper()
		wire := packet
		if natt {
			wire, err = EncapsulateIKE(packet)
			if err != nil {
				t.Fatal(err)
			}
		}
		if err := conn.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.WriteToUDPAddrPort(wire, peer); err != nil {
			t.Fatal(err)
		}
	}
	read := func() []byte {
		t.Helper()
		if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatal(err)
		}
		for {
			buf := make([]byte, 65535)
			n, from, err := conn.ReadFromUDPAddrPort(buf)
			if err != nil {
				t.Fatal(err)
			}
			if from != peer {
				t.Fatalf("unexpected peer %v", from)
			}
			packet := buf[:n]
			if natt {
				kind, body, err := ParseNATDatagram(packet)
				if err != nil {
					t.Fatal(err)
				}
				if kind != NATDatagramIKE {
					continue
				}
				packet = body
			}
			return packet
		}
	}
	send(i.Request())
	initial, err := i.HandleInitResponse(read())
	if err != nil {
		t.Fatal(err)
	}
	if !initial.NAT.Required() {
		t.Fatal("default profile did not force UDP encapsulation")
	}
	natt = true
	peer = netip.MustParseAddrPort("127.0.0.1:4500")
	selector := TrafficSelector{StartAddr: netip.MustParseAddr("0.0.0.0"), EndAddr: netip.MustParseAddr("255.255.255.255"), EndPort: 65535}
	request, err := i.AuthRequest(AuthConfig{LocalID: clientID, RemoteID: serverID, PrivateKey: clientPriv, RemotePublicKey: serverPub, Child: ChildConfig{InitiatorSPI: 0x12558000, LocalSelectors: []TrafficSelector{selector}, RemoteSelectors: []TrafficSelector{selector}}})
	if err != nil {
		t.Fatal(err)
	}
	send(request)
	auth, err := i.HandleAuthResponse(read())
	if err != nil {
		t.Fatal(err)
	}
	if ikeOnly {
		trigger := func() {
			t.Helper()
			response, err := vici.Call(ctx, "rekey", map[string]any{"ike": spec.TransportID})
			if err != nil || response["success"] != "yes" {
				t.Fatal("charon IKE rekey trigger", err, response)
			}
		}
		runCrossedIKERekey(t, i, auth.Child, trigger, send, read)
		return
	}
	old := auth.Child.InitiatorSPI
	localConfig := configForExistingChild(auth.Child, 0x12558001)
	if _, err := i.ChildRequest(localConfig); err != nil {
		t.Fatal(err)
	}
	// Fix only our generated test nonce before putting the request on the wire.
	// Its all-zero minimum makes our candidate unambiguously redundant, so this
	// test exercises the losing endpoint's deletion responsibility every run.
	i.childPending.nonce = make([]byte, 32)
	localPS, err := childPayloads(localConfig, i.childPending.nonce, nil, false)
	if err != nil {
		t.Fatal(err)
	}
	notification, _ := EncodeNotify(Notify{Protocol: 3, Type: NotifyRekeySA, SPI: []byte{0x12, 0x55, 0x80, 0x00}})
	localPS = append([]Payload{{Type: PayloadNotify, Data: notification}}, localPS...)
	request, err = i.sealExchange(ExchangeCreateChild, FlagInitiator, 2, localPS)
	if err != nil {
		t.Fatal(err)
	}
	i.exchanges.pending = bytes.Clone(request)
	response, err := vici.Call(ctx, "rekey", map[string]any{"child": ipsec.ChildSAName(spec)})
	if err != nil || response["success"] != "yes" {
		t.Fatal("charon rekey trigger", err, response)
	}
	peerRequest := read()
	offer, err := i.InspectChildRequest(peerRequest)
	if err != nil || offer.RekeySPI != old {
		t.Fatal("did not intercept peer's pending rekey", err)
	}
	send(request)           // charon is now rekeying the same predecessor in both directions
	localResponse := read() // prove charon saw our request before completing its own
	localHeader, _, err := DecodeHeader(localResponse)
	if err != nil || localHeader.ExchangeType != ExchangeCreateChild || localHeader.Flags&FlagResponse == 0 {
		t.Fatal("charon did not process crossed CHILD request", err)
	}
	reply, peerResult, err := i.HandleChildRequest(peerRequest, ChildExchangeConfig{Child: ChildConfig{InitiatorSPI: 0x12558002, LocalSelectors: offer.LocalSelectors, RemoteSelectors: offer.RemoteSelectors}, RekeySPI: old, DHGroup: offer.DHGroup})
	if err != nil || peerResult == nil {
		t.Fatal("peer rekey response", err)
	}
	pending, err := i.ResolveChildRekey(old)
	if err != nil || !pending.Pending {
		t.Fatal("requests did not actually overlap")
	}
	send(reply)
	localCompleted, deleteStarted, oldDeleted := false, false, false
	survivor := peerResult.Child.InitiatorSPI
	for step := 0; step < 12; step++ {
		packet := localResponse
		if step > 0 {
			packet = read()
		}
		message, err := i.DecodeExchange(packet, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if message == nil {
			continue
		}
		result, err := i.HandleExchange(message, nil)
		if err != nil {
			t.Fatal("crossed rekey message", err)
		}
		if result.Reply != nil {
			send(result.Reply)
		}
		if result.Child != nil {
			localCompleted = true
			decision, err := i.ResolveChildRekey(old)
			if err != nil || decision.Pending || decision.SurvivingSPI != survivor || decision.DeleteSPI != localConfig.Child.InitiatorSPI || decision.LocalInitiated {
				t.Fatal("nonce conflict selected wrong survivor", err, decision)
			}
			deletion, err := i.ChildDeleteRequest([]uint32{decision.DeleteSPI})
			if err != nil {
				t.Fatal(err)
			}
			send(deletion)
			deleteStarted = true
		}
		if result.Deleted != nil {
			for _, spi := range result.Deleted.Removed {
				oldDeleted = oldDeleted || spi == old
			}
		}
		if localCompleted && deleteStarted && oldDeleted && i.PendingRequest() == nil && len(i.children) == 1 {
			break
		}
		if step == 11 {
			t.Fatal("simultaneous cleanup did not converge")
		}
	}
	if _, ok := i.Child(old); ok {
		t.Fatal("replaced CHILD still present")
	}
	if _, ok := i.Child(localConfig.Child.InitiatorSPI); ok {
		t.Fatal("redundant local CHILD still present")
	}
	selected, ok := i.Child(survivor)
	if !ok {
		t.Fatal("peer-created survivor missing")
	}
	verifyKernelChildKeys(t, selected)
	probe, err := i.InformationalRequest()
	if err != nil {
		t.Fatal(err)
	}
	send(probe)
	if reply, err := i.HandleInformational(read()); err != nil || reply != nil {
		t.Fatal("IKE liveness after collision failed", err)
	}
	t.Log("forced crossed CHILD rekey: lower-nonce local candidate deleted, peer survivor keys match XFRM, old CHILD removed and authenticated liveness intact")
}

func runCrossedIKERekey(t *testing.T, i *Initiator, child ChildResult, trigger func(), send func([]byte), read func() []byte) {
	t.Helper()
	if _, err := i.IKERekeyRequest(); err != nil {
		t.Fatal(err)
	}
	ownRequest := forceRekeyNonce(t, i, 0)
	trigger()
	var peerRequest []byte
	// The production default proposal may begin with MODP; demand our supported
	// P-256 group through the real authenticated INVALID_KE retry, while keeping
	// our own (not-yet-sent) rekey pending throughout.
	for attempts := 0; attempts < 3; attempts++ {
		packet := read()
		m, err := i.DecodeExchange(packet, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if m == nil {
			attempts--
			continue
		}
		if !m.IsIKERekey() || m.Header().Flags&FlagResponse != 0 {
			t.Fatal("expected peer IKE rekey request")
		}
		_, ps, _, err := i.openAuthenticated(m, ExchangeCreateChild)
		if err != nil {
			t.Fatal(err)
		}
		offer, err := parseIKERekeyPayloads(ps, true)
		if err != nil {
			t.Fatal(err)
		}
		if offer.keGroup == GroupP256 {
			peerRequest = packet
			break
		}
		reply, result, err := i.HandleIKERekeyRequest(packet)
		if err != nil || result != nil || reply == nil {
			t.Fatal("peer IKE KE correction failed", err)
		}
		send(reply)
	}
	if peerRequest == nil {
		t.Fatal("peer did not retry IKE rekey with supported group")
	}
	send(ownRequest)
	localResponse := read()
	localHeader, _, err := DecodeHeader(localResponse)
	if err != nil || localHeader.ExchangeType != ExchangeCreateChild || localHeader.Flags&FlagResponse == 0 {
		t.Fatal("charon did not process crossed IKE request", err)
	}
	reply, result, err := i.HandleIKERekeyRequest(peerRequest)
	if err != nil || result == nil {
		t.Fatal("crossed peer IKE rekey", err)
	}
	peerCandidate := result.Session
	decision, err := i.ResolveIKERekey()
	if err != nil || !decision.Pending {
		t.Fatal("IKE requests did not overlap")
	}
	send(reply)
	var redundant *Initiator
	var survivor *Initiator
	oldClosed, redundantClosed := false, false
	for step := 0; step < 16; step++ {
		packet := localResponse
		if step > 0 {
			packet = read()
		}
		h, _, err := DecodeHeader(packet)
		if err != nil {
			t.Fatal(err)
		}
		session := i
		match := func(s *Initiator) bool {
			if s == nil {
				return false
			}
			si, sr := s.SPIs()
			return si == h.InitiatorSPI && sr == h.ResponderSPI
		}
		if !match(session) {
			if match(redundant) {
				session = redundant
			} else if match(peerCandidate) {
				session = peerCandidate
			} else {
				t.Fatal("unknown IKE collision SPI pair")
			}
		}
		m, err := session.DecodeExchange(packet, time.Now())
		if err != nil {
			t.Fatal(err)
		}
		if m == nil {
			continue
		}
		exchange, err := session.HandleExchange(m, nil)
		if err != nil {
			t.Fatal("IKE collision handling", err)
		}
		t.Logf("IKE collision step %d: exchange=%d flags=%x id=%d rekey=%t delete=%t", step, h.ExchangeType, h.Flags, h.MessageID, exchange.IKE != nil, exchange.Deleted != nil)
		if exchange.Reply != nil {
			send(exchange.Reply)
		}
		if exchange.IKE != nil {
			resolution, err := i.AdoptIKERekey()
			if err != nil || resolution.Pending || resolution.Surviving != peerCandidate || resolution.DeleteOld || !resolution.DeleteRedundant {
				t.Fatal("wrong IKE collision survivor", err)
			}
			survivor, redundant = resolution.Surviving, resolution.Redundant
			deletion, err := redundant.IKEDeleteRequest()
			if err != nil {
				t.Fatal(err)
			}
			send(deletion)
			t.Log("sent redundant IKE Delete")
		}
		if exchange.Deleted != nil && exchange.Deleted.IKE {
			if session == i {
				oldClosed = true
				if survivor != nil && exchange.Deleted.Successor != survivor {
					t.Fatal("old Delete lost inherited SA")
				}
				// The first redundant-SA Delete may race charon's registration
				// of that new SA. Retry its original ciphertext after the old-SA
				// close, as the real transport's retransmission owner does.
				if redundant != nil && len(redundant.PendingRequest()) != 0 {
					send(redundant.PendingRequest())
				}
			}
			if session == redundant {
				redundantClosed = true
			}
		}
		if survivor != nil && oldClosed && redundantClosed {
			break
		}
		if step == 15 {
			t.Fatal("IKE simultaneous cleanup did not converge")
		}
	}
	if survivor == nil || !oldClosed || !redundantClosed || len(survivor.children) != 1 || len(i.children) != 0 || len(redundant.children) != 0 {
		t.Fatal("IKE collision duplicated or lost CHILD ownership")
	}
	inherited, ok := survivor.Child(child.InitiatorSPI)
	if !ok {
		t.Fatal("survivor did not inherit CHILD")
	}
	verifyKernelChildKeys(t, inherited)
	probe, err := survivor.InformationalRequest()
	if err != nil {
		t.Fatal(err)
	}
	header, _, _ := DecodeHeader(probe)
	if header.MessageID != 0 || header.Flags != 0 {
		t.Fatal("surviving peer-initiated IKE role/counter wrong")
	}
	send(probe)
	if reply, err := survivor.HandleInformational(read()); err != nil || reply != nil {
		t.Fatal("new IKE role liveness failed", err)
	}
	t.Log("forced crossed IKE rekey: lower-nonce local IKE deleted, peer survivor inherited CHILD/XFRM keys, old IKE closed, reversed-role ID-zero DPD passed")
}
