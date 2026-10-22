//go:build linux

package photonwindows

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/binary"
	"net/netip"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// Uses the same isolated charon as the portable protocol rig. This exercises
// the actual shared UDP owner, lifecycle and worker install, not Windows routes.
func TestStrongSwanWindowsTunnel(t *testing.T) {
	if os.Getenv("PHOTON_WINDOWS_TUNNEL_SMOKE") != "1" {
		t.Skip("run docs/scripts/ike-auth-smoke.sh")
	}
	for _, outer := range []struct{ name, gateway, local string }{
		{"outer-ipv4", "127.0.0.1", "127.0.0.2:0"},
		{"outer-ipv6", "::1", "[::1]:0"},
	} {
		t.Run(outer.name, func(t *testing.T) { runStrongSwanWindowsTunnel(t, outer.gateway, outer.local) })
	}
}

func runStrongSwanWindowsTunnel(t *testing.T, gateway, local string) {
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	vici, err := ipsec.NewGoviciClient("/tmp/ike-auth.vici")
	if err != nil {
		t.Fatal(err)
	}
	defer vici.Close()
	driver := &ipsec.StrongSwanDriver{VICI: vici}
	serverPub, serverPriv, _ := ed25519.GenerateKey(rand.Reader)
	clientPub, clientPriv, _ := ed25519.GenerateKey(rand.Reader)
	serverDER, _ := x509.MarshalPKCS8PrivateKey(serverPriv)
	clientDER, _ := x509.MarshalPKIXPublicKey(clientPub)
	const name = "photon-windows-tunnel"
	for _, args := range [][]string{{"link", "add", "phwintest", "type", "xfrm", "if_id", "524248"}, {"link", "set", "phwintest", "up"}, {"addr", "add", "10.55.3.1/32", "dev", "phwintest"}, {"route", "add", "10.55.3.2/32", "dev", "phwintest"}} {
		if output, err := exec.Command("ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("isolated XFRM interface: %v %s", err, output)
		}
	}
	defer exec.Command("ip", "link", "del", "phwintest").Run()
	if err := driver.LoadPrivateKey(ctx, name, serverDER, ipsec.AlgorithmEd25519); err != nil {
		t.Fatal(err)
	}
	defer driver.UnloadPrivateKey(context.Background(), name)
	spec := ipsec.TransportLinkSpec{TransportID: name, LocalZone: "windows-gateway.", PeerZone: "windows-leaf.", LocalAddress: gateway, XFRMIfID: 524248, LocalTunnelAddr: netip.MustParseAddr("10.55.3.1"), PeerTunnelAddr: netip.MustParseAddr("10.55.3.2"), LocalPrivateKey: serverDER, LocalPrivateKeyAlgorithm: ipsec.AlgorithmEd25519, PeerPublicKey: clientDER}
	if err := driver.LoadConnection(ctx, spec); err != nil {
		t.Fatal(err)
	}
	defer driver.UnloadConnection(context.Background(), name)
	defer driver.TerminateSA(context.Background(), name)
	socket, err := openPacketSockets(ctx, local)
	if err != nil {
		t.Fatal(err)
	}
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		for {
			if _, _, err := socket.ReadDatagram(make([]byte, 1201)); err != nil {
				return
			}
		}
	}()
	defer func() { socket.Close(); <-readerDone }()
	data := newGatewayDataplane(ctx)
	defer data.close()
	tunnel := &gatewayTunnel{socket: socket, data: data}
	defer tunnel.stop()
	plan := GatewayPlan{Selected: &GatewaySelection{Zone: spec.LocalZone, Identity: string(spec.LocalZone), PublicKey: serverPub, Contact: ipsec.ContactPoint{Address: gateway, IKEPort: 500, NATTPort: 4500}}}
	if err := tunnel.start(plan, string(spec.PeerZone), clientPriv, time.Now()); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for tunnel.phase != 3 {
		select {
		case packet := <-socket.ikePackets:
			if err := tunnel.handle(packet, plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ticker.C:
			if err := tunnel.tick(plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("shared UDP AUTH timed out")
		}
	}
	if data.active == nil || !tunnel.natt {
		t.Fatal("authenticated CHILD not installed")
	}
	if err := tunnel.tick(plan, tunnel.probeAt); err != nil {
		t.Fatal(err)
	}
	select {
	case packet := <-socket.ikePackets:
		if err := tunnel.handle(packet, plan, time.Now()); err != nil {
			t.Fatal(err)
		}
	case <-ctx.Done():
		t.Fatal("DPD timed out")
	}
	if len(tunnel.pending) != 0 {
		t.Fatal("DPD did not complete")
	}
	checkEcho := func() {
		t.Helper()
		inner := tunnelEchoPacket()
		allow := func(p []byte, outbound bool) bool {
			if len(p) != 28 || p[9] != 1 {
				return false
			}
			if outbound {
				return p[15] == 2 && p[19] == 1 && p[20] == 8
			}
			return p[15] == 1 && p[19] == 2 && p[20] == 0
		}
		if !data.submitOutbound(tunnel.generation, plan, inner, allow) {
			t.Fatal("echo submit")
		}
		result := dataplaneResult(t, data)
		wire, endpoint, outbound, ok := data.accept(result, plan, allow)
		if !ok || !outbound {
			t.Fatal("echo encrypt completion")
		}
		if err := socket.WriteTunnel(tunnel.generation, wire, endpoint); err != nil {
			t.Fatal(err)
		}
		select {
		case packet := <-socket.espPackets:
			if !data.submitInbound(packet.generation, plan, packet.peer, packet.packet) {
				t.Fatal("echo receive submit")
			}
		case <-ctx.Done():
			t.Fatal("kernel echo timeout")
		}
		result = dataplaneResult(t, data)
		if reply, _, outbound, ok := data.accept(result, plan, allow); !ok || outbound || reply[20] != 0 {
			t.Fatal("kernel echo decrypt")
		}
	}
	checkEcho()
	oldSPI := tunnel.child.InitiatorSPI
	tunnel.rekeyAt = time.Now()
	for tunnel.child.InitiatorSPI == oldSPI || len(tunnel.pending) != 0 {
		select {
		case packet := <-socket.ikePackets:
			if err := tunnel.handle(packet, plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ticker.C:
			if err := tunnel.tick(plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("automatic CHILD rekey timeout")
		}
	}
	checkEcho()
	tunnel.deleteAt = time.Now()
	for data.sas[oldSPI] != nil {
		select {
		case packet := <-socket.ikePackets:
			if err := tunnel.handle(packet, plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ticker.C:
			if err := tunnel.tick(plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("old CHILD deletion timeout")
		}
	}
	checkEcho()
	oldSession := tunnel.session
	tunnel.ikeRekeyAt = time.Now()
	for tunnel.session == oldSession {
		select {
		case packet := <-socket.ikePackets:
			if err := tunnel.handle(packet, plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ticker.C:
			if err := tunnel.tick(plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("automatic IKE rekey timeout")
		}
	}
	probeStarted := time.Now()
	tunnel.probeAt = probeStarted
	for !tunnel.probeAt.After(probeStarted) || len(tunnel.pending) != 0 {
		select {
		case packet := <-socket.ikePackets:
			if err := tunnel.handle(packet, plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ticker.C:
			if err := tunnel.tick(plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("new IKE keys did not complete liveness")
		}
	}
	checkEcho()
	// Exercise the responder direction through the same real shared socket and
	// kernel SA, after our local IKE rekey changed the key and Message ID space.
	peerRekey := func(kind, target string, complete func() bool) {
		t.Helper()
		response, err := vici.Call(ctx, "rekey", map[string]any{kind: target})
		if err != nil || response["success"] != "yes" {
			t.Fatalf("trigger peer %s rekey: %v, response=%v", kind, err, response)
		}
		for !complete() {
			select {
			case packet := <-socket.ikePackets:
				if err := tunnel.handle(packet, plan, time.Now()); err != nil {
					t.Fatalf("peer %s rekey: %v", kind, err)
				}
			case <-ticker.C:
				if err := tunnel.tick(plan, time.Now()); err != nil {
					t.Fatalf("peer %s rekey tick: %v", kind, err)
				}
			case <-ctx.Done():
				t.Fatalf("peer %s rekey timeout", kind)
			}
		}
	}
	previousChild := tunnel.child.InitiatorSPI
	peerRekey("child", ipsec.ChildSAName(spec), func() bool {
		return tunnel.child.InitiatorSPI != previousChild && data.sas[previousChild] == nil && len(tunnel.pending) == 0
	})
	checkEcho()
	previousIKE := tunnel.session
	peerRekey("ike", name, func() bool { return tunnel.session != previousIKE })
	// The peer now owns the original initiator role. An outbound probe verifies
	// flipped I flags, key directions and zero-based new-SA message IDs.
	probeStarted = time.Now()
	tunnel.probeAt = probeStarted
	for !tunnel.probeAt.After(probeStarted) || len(tunnel.pending) != 0 {
		select {
		case packet := <-socket.ikePackets:
			if err := tunnel.handle(packet, plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ticker.C:
			if err := tunnel.tick(plan, time.Now()); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatal("peer-rekeyed IKE liveness timeout")
		}
	}
	checkEcho()
	old := tunnel.generation
	if err := socket.Rebind(ctx); err != nil {
		t.Fatal(err)
	}
	tunnel.stop()
	if data.active != nil || old == tunnel.generation {
		t.Fatal("network change retained old SA")
	}
	t.Log("shared UDP INIT/AUTH/NAT-T, DPD, local and peer CHILD/IKE rekey/Delete, role reversal and kernel echo passed; rebind retired old SA")
}

func tunnelEchoPacket() []byte {
	p := make([]byte, 28)
	p[0], p[8], p[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(p[2:4], 28)
	copy(p[12:16], []byte{10, 55, 3, 2})
	copy(p[16:20], []byte{10, 55, 3, 1})
	p[20], p[25], p[27] = 8, 1, 1
	checksum := func(b []byte) uint16 {
		var sum uint32
		for i := 0; i < len(b); i += 2 {
			sum += uint32(binary.BigEndian.Uint16(b[i:]))
		}
		for sum>>16 != 0 {
			sum = (sum & 0xffff) + (sum >> 16)
		}
		return ^uint16(sum)
	}
	binary.BigEndian.PutUint16(p[10:12], checksum(p[:20]))
	binary.BigEndian.PutUint16(p[22:24], checksum(p[20:]))
	return p
}
