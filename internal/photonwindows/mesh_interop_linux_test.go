//go:build linux

package photonwindows

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// Invoked only by the existing --network none StrongSwan container rig. There
// is one Windows UDP owner and two simultaneous real IKE/ESP kernel peers.
func TestStrongSwanWindowsMeshTunnels(t *testing.T) {
	runStrongSwanWindowsMeshTunnels(t, false, false)
}

func TestStrongSwanWindowsDualOuterTunnels(t *testing.T) {
	runStrongSwanWindowsMeshTunnels(t, false, true)
}

func TestStrongSwanWindowsMeshTimedRekey(t *testing.T) {
	if os.Getenv("PHOTON_WINDOWS_TIMED_REKEY_SMOKE") != "1" {
		t.Skip("set PHOTON_WINDOWS_TIMED_REKEY_SMOKE=1 for the real five-minute timer")
	}
	runStrongSwanWindowsMeshTunnels(t, true, false)
}

func runStrongSwanWindowsMeshTunnels(t *testing.T, timed, dualOuter bool) {
	if os.Getenv("PHOTON_WINDOWS_TUNNEL_SMOKE") != "1" {
		t.Skip("run docs/scripts/ike-auth-smoke.sh")
	}
	limit := 25 * time.Second
	if timed {
		limit = 6 * time.Minute
	}
	ctx, cancel := context.WithTimeout(t.Context(), limit)
	defer cancel()
	vici, err := ipsec.NewGoviciClient("/tmp/ike-auth.vici")
	if err != nil {
		t.Fatal(err)
	}
	defer vici.Close()
	driver := &ipsec.StrongSwanDriver{VICI: vici}
	clientPublic, clientPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	clientDER, _ := x509.MarshalPKIXPublicKey(clientPublic)
	listen := "127.0.0.2:0"
	if dualOuter {
		listen = "0.0.0.0:0"
	}
	socket, err := openPacketSockets(ctx, listen)
	if err != nil {
		t.Fatal(err)
	}
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		var buffer [1201]byte
		for {
			if _, _, err := socket.ReadDatagram(buffer[:]); err != nil {
				return
			}
		}
	}()
	defer func() { socket.Close(); <-readerDone }()
	var tunnels []*gatewayTunnel
	var sharedGatewayKey ed25519.PrivateKey
	if dualOuter {
		_, sharedGatewayKey, err = ed25519.GenerateKey(nil)
		if err != nil {
			t.Fatal(err)
		}
	}
	for i := range 2 {
		name, iface := fmt.Sprintf("photon-mesh-%d", i), fmt.Sprintf("phmesh%d", i)
		serverPrivate := sharedGatewayKey
		if serverPrivate == nil {
			_, serverPrivate, err = ed25519.GenerateKey(nil)
			if err != nil {
				t.Fatal(err)
			}
		}
		serverPublic := serverPrivate.Public().(ed25519.PublicKey)
		serverDER, _ := x509.MarshalPKCS8PrivateKey(serverPrivate)
		ifID := uint32(524249 + i)
		serverIP, clientIP := fmt.Sprintf("10.55.%d.1", 4+i), fmt.Sprintf("10.55.%d.2", 4+i)
		for _, args := range [][]string{{"link", "add", iface, "type", "xfrm", "if_id", fmt.Sprint(ifID)}, {"link", "set", iface, "up"}, {"addr", "add", serverIP + "/32", "dev", iface}, {"route", "add", clientIP + "/32", "dev", iface}} {
			if output, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
				t.Fatalf("isolated mesh interface: %v %s", err, output)
			}
		}
		defer exec.Command("ip", "link", "del", iface).Run()
		if !dualOuter || i == 0 {
			if err := driver.LoadPrivateKey(ctx, name, serverDER, ipsec.AlgorithmEd25519); err != nil {
				t.Fatal(err)
			}
			defer driver.UnloadPrivateKey(context.Background(), name)
		}
		gateway := fmt.Sprintf("127.0.0.%d", 1+i*2)
		gatewayZone := zone.ZonePath(fmt.Sprintf("mesh-%d.gateway.", i))
		path := ""
		if dualOuter {
			gatewayZone = "mesh.gateway."
			if i == 1 {
				gateway = "::1"
			}
			path = "family:" + outerFamily(netip.MustParseAddr(gateway))
		}
		spec := ipsec.TransportLinkSpec{TransportID: name, LocalZone: gatewayZone, PeerZone: "mesh.windows.", PathKey: path, LocalAddress: gateway, XFRMIfID: ifID, LocalTunnelAddr: netip.MustParseAddr(serverIP), PeerTunnelAddr: netip.MustParseAddr(clientIP), LocalPrivateKey: serverDER, LocalPrivateKeyAlgorithm: ipsec.AlgorithmEd25519, PeerPublicKey: clientDER}
		if err := driver.LoadConnection(ctx, spec); err != nil {
			t.Fatal(err)
		}
		defer driver.UnloadConnection(context.Background(), name)
		defer driver.TerminateSA(context.Background(), name)
		data := newSerialGatewayDataplane(ctx)
		defer data.close()
		tunnel := &gatewayTunnel{socket: socket, data: data}
		defer tunnel.stop()
		plan := GatewayPlan{Selected: &GatewaySelection{Zone: spec.LocalZone, Identity: string(spec.LocalZone), PublicKey: serverPublic, Contact: ipsec.ContactPoint{Address: gateway, IKEPort: 500, NATTPort: 4500}}}
		if err := tunnel.start(plan, "mesh.windows.", clientPrivate, time.Now()); err != nil {
			t.Fatal(err)
		}
		tunnels = append(tunnels, tunnel)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for tunnels[0].phase != 3 || tunnels[1].phase != 3 {
		select {
		case packet := <-socket.ikePackets:
			for _, tunnel := range tunnels {
				if tunnel.generation == packet.generation {
					if err := tunnel.handle(packet, tunnel.plan, time.Now()); err != nil {
						t.Fatal(err)
					}
				}
			}
		case <-ticker.C:
			for _, tunnel := range tunnels {
				if err := tunnel.tick(tunnel.plan, time.Now()); err != nil {
					t.Fatal(err)
				}
			}
		case <-ctx.Done():
			t.Fatal("two simultaneous AUTH exchanges timed out")
		}
	}
	echo := func(index int) {
		t.Helper()
		tunnel := tunnels[index]
		packet := tunnelEchoPacket()
		packet[14], packet[18] = byte(4+index), byte(4+index)
		packet[10], packet[11] = 0, 0
		var sum uint32
		for i := 0; i < 20; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(packet[i:]))
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		binary.BigEndian.PutUint16(packet[10:12], ^uint16(sum))
		allow := func(p []byte, outbound bool) bool {
			if len(p) != 28 || p[9] != 1 || p[14] != byte(4+index) || p[18] != byte(4+index) {
				return false
			}
			if outbound {
				return p[15] == 2 && p[19] == 1 && p[20] == 8
			}
			return p[15] == 1 && p[19] == 2 && p[20] == 0
		}
		completion, ok := tunnel.data.processOwnedOutbound(tunnel.generation, tunnel.plan, packet, allow, fixturePacketTiming{})
		if !ok {
			t.Fatal("mesh echo encryption failed")
		}
		wire, endpoint, outbound, ok := tunnel.data.accept(completion, tunnel.plan, allow)
		if !ok || !outbound {
			t.Fatal("mesh echo authorization failed")
		}
		if err := socket.WriteTunnel(tunnel.generation, wire, endpoint); err != nil {
			t.Fatal(err)
		}
		for {
			select {
			case received := <-socket.espPackets:
				if received.generation != tunnel.generation {
					continue
				}
				result, ok := tunnel.data.processOwnedInbound(received.generation, tunnel.plan, received.peer, received.packet, received.timing)
				if !ok {
					t.Fatal("mesh kernel reply decrypt failed")
				}
				if _, _, outbound, ok := tunnel.data.accept(result, tunnel.plan, allow); !ok || outbound {
					t.Fatal("mesh kernel reply authorization failed")
				}
				return
			case <-ctx.Done():
				t.Fatal("mesh kernel echo timed out")
			}
		}
	}
	echo(0)
	echo(1)
	if timed {
		verifyMeshTimedRekey(t, ctx, socket, tunnels)
	}
	generation, spi := tunnels[1].generation, tunnels[1].child.InitiatorSPI
	tunnels[0].stop()
	echo(1)
	if tunnels[1].generation != generation || tunnels[1].child.InitiatorSPI != spi {
		t.Fatal("one peer's stop restarted the surviving SA")
	}
	t.Log("two simultaneous IKE/ESP peers passed; surviving peer retained generation/SPI and kernel echo after other peer stopped")
}
