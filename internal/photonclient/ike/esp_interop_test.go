//go:build linux

package ike

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/esp"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// This opt-in test owns only the network namespace created by esp-smoke.sh.
// A real Linux kernel decrypts the request and generates/encrypts the reply.
func TestStrongSwanESP(t *testing.T) {
	if os.Getenv("PHOTON_ESP_SMOKE") != "1" {
		t.Skip("run docs/scripts/esp-smoke.sh")
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
	for index, v6 := range []bool{false, true} {
		t.Run(fmt.Sprintf("ipv%d", 4+2*index), func(t *testing.T) {
			name := fmt.Sprintf("photon-esp-%d", index)
			iface := fmt.Sprintf("phesp%d", index)
			ifID := uint32(525250 + index)
			local, remote := netip.MustParseAddr("10.55.0.1"), netip.MustParseAddr("10.55.0.2")
			selector := TrafficSelector{StartAddr: netip.MustParseAddr("0.0.0.0"), EndAddr: netip.MustParseAddr("255.255.255.255"), EndPort: 65535}
			if v6 {
				local, remote = netip.MustParseAddr("fd55::1"), netip.MustParseAddr("fd55::2")
				selector.StartAddr, selector.EndAddr = netip.MustParseAddr("::"), netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")
			}
			runIP := func(args ...string) {
				t.Helper()
				if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
					t.Fatalf("ip %v: %v: %s", args, err, output)
				}
			}
			runIP("link", "add", iface, "type", "xfrm", "if_id", fmt.Sprint(ifID))
			defer exec.Command("ip", "link", "del", iface).Run()
			runIP("link", "set", iface, "up")
			if v6 {
				runIP("addr", "add", local.String()+"/128", "dev", iface, "nodad")
			} else {
				runIP("addr", "add", local.String()+"/32", "dev", iface)
			}
			runIP("route", "add", remote.String(), "dev", iface)
			if err := driver.LoadPrivateKey(ctx, name, serverDER, ipsec.AlgorithmEd25519); err != nil {
				t.Fatal(err)
			}
			defer driver.UnloadPrivateKey(context.Background(), name)
			spec := ipsec.TransportLinkSpec{TransportID: name, LocalZone: zone.ZonePath(name + "-gateway."), PeerZone: zone.ZonePath(name + "-leaf."), LocalAddress: "127.0.0.1", XFRMIfID: ifID, LocalTunnelAddr: local, PeerTunnelAddr: remote, LocalPrivateKey: serverDER, LocalPrivateKeyAlgorithm: ipsec.AlgorithmEd25519, PeerPublicKey: clientDER}
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
			initiator, err := NewInitiatorWithEndpoints(conn.LocalAddr().(*net.UDPAddr).AddrPort(), peer)
			if err != nil {
				t.Fatal(err)
			}
			roundTrip := func(packet []byte, port int) []byte {
				t.Helper()
				for attempt := 0; attempt < 3; attempt++ {
					conn.SetDeadline(time.Now().Add(2 * time.Second))
					if _, err := conn.WriteToUDP(packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: port}); err != nil {
						t.Fatal(err)
					}
					buffer := make([]byte, 65535)
					n, from, err := conn.ReadFromUDP(buffer)
					if err == nil {
						if !from.IP.Equal(net.IPv4(127, 0, 0, 1)) || from.Port != port {
							t.Fatalf("response from unexpected endpoint %s", from)
						}
						return buffer[:n]
					}
					if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
						t.Fatal(err)
					}
				}
				t.Fatal("no response from isolated kernel/charon")
				return nil
			}
			initial, err := initiator.HandleInitResponse(roundTrip(initiator.Request(), 500))
			if err != nil {
				t.Fatal(err)
			}
			if !initial.NAT.Required() {
				t.Fatal("production forced encapsulation was not detected")
			}
			request, err := initiator.AuthRequest(AuthConfig{LocalID: string(spec.PeerZone), RemoteID: string(spec.LocalZone), PrivateKey: clientPriv, RemotePublicKey: serverPub, Child: ChildConfig{InitiatorSPI: 0x55667788 + uint32(index), LocalSelectors: []TrafficSelector{selector}, RemoteSelectors: []TrafficSelector{selector}}})
			if err != nil {
				t.Fatal(err)
			}
			framed, err := EncapsulateIKE(request)
			if err != nil {
				t.Fatal(err)
			}
			kind, response, err := ParseNATDatagram(roundTrip(framed, 4500))
			if err != nil || kind != NATDatagramIKE {
				t.Fatalf("invalid NAT-T AUTH response: %v", err)
			}
			authenticated, err := initiator.HandleAuthResponse(response)
			if err != nil {
				t.Fatal(err)
			}
			sender, err := esp.NewSender(authenticated.Child.ResponderSPI, authenticated.Child.Keys.InitiatorToResponder)
			if err != nil {
				t.Fatal(err)
			}
			receiver, err := esp.NewReceiver(authenticated.Child.InitiatorSPI, authenticated.Child.Keys.ResponderToInitiator)
			if err != nil {
				t.Fatal(err)
			}
			assertKernelDrop := func(packet []byte, counter string) {
				t.Helper()
				before := espKernelCounter(t, counter)
				if err := conn.SetDeadline(time.Now().Add(150 * time.Millisecond)); err != nil {
					t.Fatal(err)
				}
				if _, err := conn.WriteToUDP(packet, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}); err != nil {
					t.Fatal(err)
				}
				buffer := make([]byte, 65535)
				if _, _, err := conn.ReadFromUDP(buffer); err == nil {
					t.Fatal("kernel replied to invalid ESP")
				} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
					t.Fatal(err)
				}
				if espKernelCounter(t, counter) != before+1 {
					t.Fatalf("kernel did not record expected %s drop", counter)
				}
			}
			for sequence := uint16(1); sequence <= 3; sequence++ {
				inner := espEchoPacket(remote, local, sequence)
				encrypted, err := sender.Seal(inner)
				if err != nil {
					t.Fatal(err)
				}
				if sequence == 1 {
					invalid := bytes.Clone(encrypted)
					invalid[len(invalid)-1] ^= 1
					assertKernelDrop(invalid, "XfrmInStateProtoError")
				}
				wireReply := roundTrip(encrypted, 4500)
				kind, replyESP, err := ParseNATDatagram(wireReply)
				if err != nil || kind != NATDatagramESP {
					t.Fatalf("expected ESP reply: %v", err)
				}
				invalidReply := bytes.Clone(replyESP)
				invalidReply[len(invalidReply)-1] ^= 1
				if _, err := receiver.Open(invalidReply); err == nil {
					t.Fatal("invalid kernel reply tag accepted")
				}
				reply, err := receiver.Open(replyESP)
				if err != nil {
					t.Fatal(err)
				}
				headerSize, replyType := 20, byte(0)
				if v6 {
					headerSize, replyType = 40, 129
				}
				if len(reply) != len(inner) || reply[headerSize] != replyType || !bytes.Equal(reply[headerSize+4:], inner[headerSize+4:]) {
					t.Fatalf("incorrect decrypted ICMP echo reply, length %d", len(reply))
				}
				if v6 {
					if reply[0]>>4 != 6 || reply[6] != 58 || !bytes.Equal(reply[8:24], local.AsSlice()) || !bytes.Equal(reply[24:40], remote.AsSlice()) {
						t.Fatal("incorrect kernel IPv6 reply endpoints or protocol")
					}
				} else {
					if reply[0] != 0x45 || reply[9] != 1 || !bytes.Equal(reply[12:16], local.AsSlice()) || !bytes.Equal(reply[16:20], remote.AsSlice()) {
						t.Fatal("incorrect kernel IPv4 reply endpoints or protocol")
					}
				}
				if _, err := receiver.Open(replyESP); err == nil {
					t.Fatal("duplicate kernel ESP reply accepted")
				}
				if sequence == 1 {
					assertKernelDrop(encrypted, "XfrmInStateSeqError")
				}
			}
			// Also exercise independently originated kernel traffic, rather than
			// proving the responder direction only through echo replies.
			family := "udp4"
			if v6 {
				family = "udp6"
			}
			originator, err := net.ListenUDP(family, &net.UDPAddr{IP: net.IP(local.AsSlice()), Port: 33333})
			if err != nil {
				t.Fatal(err)
			}
			defer originator.Close()
			payload := []byte("kernel-originated-photon-esp")
			if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
				t.Fatal(err)
			}
			if _, err := originator.WriteToUDP(payload, &net.UDPAddr{IP: net.IP(remote.AsSlice()), Port: 33334}); err != nil {
				t.Fatal(err)
			}
			buffer := make([]byte, 65535)
			n, from, err := conn.ReadFromUDP(buffer)
			if err != nil {
				t.Fatal(err)
			}
			if !from.IP.Equal(net.IPv4(127, 0, 0, 1)) || from.Port != 4500 {
				t.Fatal("kernel ESP came from wrong outer endpoint")
			}
			kind, packet, err := ParseNATDatagram(buffer[:n])
			if err != nil || kind != NATDatagramESP {
				t.Fatal("kernel-originated packet was not ESP")
			}
			inner, err := receiver.Open(packet)
			if err != nil {
				t.Fatal(err)
			}
			headerSize := 20
			protocolOffset := 9
			if v6 {
				headerSize = 40
				protocolOffset = 6
			}
			if len(inner) != headerSize+8+len(payload) || inner[protocolOffset] != 17 || binary.BigEndian.Uint16(inner[headerSize:headerSize+2]) != 33333 || binary.BigEndian.Uint16(inner[headerSize+2:headerSize+4]) != 33334 || !bytes.Equal(inner[headerSize+8:], payload) {
				t.Fatal("incorrect independently originated kernel UDP payload")
			}
			t.Log("real NAT-D, UDP4500 marker IKE_AUTH, three bidirectional kernel AES-GCM ESP ICMP echo exchanges, and independently kernel-originated UDP passed; bad tags and replay rejected in both directions, subsequent valid packets recover")
		})
	}
}

func espKernelCounter(t *testing.T, name string) uint64 {
	t.Helper()
	data, err := os.ReadFile("/proc/net/xfrm_stat")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) == 2 && fields[0] == name {
			n, err := strconv.ParseUint(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			return n
		}
	}
	t.Fatalf("missing kernel counter %s", name)
	return 0
}

func espEchoPacket(source, destination netip.Addr, sequence uint16) []byte {
	headerSize := 20
	if source.Is6() {
		headerSize = 40
	}
	packet := make([]byte, headerSize+8+16)
	icmp := packet[headerSize:]
	icmp[0] = 8
	binary.BigEndian.PutUint16(icmp[4:6], 0x5048)
	binary.BigEndian.PutUint16(icmp[6:8], sequence)
	copy(icmp[8:], []byte("photon-esp-smoke!"))
	if source.Is4() {
		packet[0] = 0x45
		binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
		packet[8], packet[9] = 64, 1
		copy(packet[12:16], source.AsSlice())
		copy(packet[16:20], destination.AsSlice())
		binary.BigEndian.PutUint16(packet[10:12], espChecksum(packet[:20]))
		binary.BigEndian.PutUint16(icmp[2:4], espChecksum(icmp))
	} else {
		packet[0] = 0x60
		binary.BigEndian.PutUint16(packet[4:6], uint16(len(icmp)))
		packet[6], packet[7] = 58, 64
		copy(packet[8:24], source.AsSlice())
		copy(packet[24:40], destination.AsSlice())
		icmp[0] = 128
		pseudo := append([]byte{}, packet[8:40]...)
		pseudo = append(pseudo, 0, 0, 0, byte(len(icmp)), 0, 0, 0, 58)
		pseudo = append(pseudo, icmp...)
		binary.BigEndian.PutUint16(icmp[2:4], espChecksum(pseudo))
	}
	return packet
}

func espChecksum(data []byte) uint16 {
	var sum uint32
	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data))
		data = data[2:]
	}
	if len(data) > 0 {
		sum += uint32(data[0]) << 8
	}
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
