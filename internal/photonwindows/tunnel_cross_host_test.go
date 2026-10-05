package photonwindows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"runtime"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// The isolated Linux fixture creates these per-run credentials. They are never
// printed and are removed from both machines by the smoke script's cleanup.
type windowsTunnelCrossConfig struct {
	Gateway          string             `json:"gateway"`
	IKEPort          uint16             `json:"ike_port"`
	NATTPort         uint16             `json:"natt_port"`
	GatewayID        string             `json:"gateway_id"`
	LocalID          string             `json:"local_id"`
	GatewayPublicKey ed25519.PublicKey  `json:"gateway_public_key"`
	PrivateKey       ed25519.PrivateKey `json:"private_key"`
}

// TestWindowsStrongSwanCrossHost runs the actual portable Windows composition
// owners on Windows against a separate isolated Linux kernel/StrongSwan host.
// It does not install Wintun or OS routes and makes no B4 traffic-policy claim.
func TestWindowsStrongSwanCrossHost(t *testing.T) {
	path := os.Getenv("PHOTON_WINDOWS_TUNNEL_CROSS_CONFIG")
	if path == "" {
		t.Skip("run docs/scripts/windows-tunnel-cross-host-smoke.sh")
	}
	if runtime.GOOS != "windows" {
		t.Fatal("cross-host client acceptance must run on Windows")
	}
	encoded, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	defer clear(encoded)
	var config windowsTunnelCrossConfig
	if err := json.Unmarshal(encoded, &config); err != nil {
		t.Fatal("invalid cross-host fixture credentials")
	}
	defer clear(config.PrivateKey)
	address, err := netip.ParseAddr(config.Gateway)
	if err != nil || !address.Is4() || config.IKEPort == 0 || config.NATTPort == 0 || len(config.PrivateKey) != ed25519.PrivateKeySize || len(config.GatewayPublicKey) != ed25519.PublicKeySize {
		t.Fatal("invalid cross-host fixture configuration")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 75*time.Second)
	defer cancel()
	socket, err := openPacketSockets(ctx, "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		buffer := make([]byte, 65535)
		for {
			if _, _, err := socket.ReadDatagram(buffer); err != nil {
				return
			}
		}
	}()
	defer func() { socket.Close(); <-readerDone }()
	data := newGatewayDataplane(ctx)
	defer data.close()
	tunnel := &gatewayTunnel{socket: socket, data: data}
	defer tunnel.stop()
	plan := GatewayPlan{Selected: &GatewaySelection{Zone: zone.ZonePath(config.GatewayID), Identity: config.GatewayID, PublicKey: config.GatewayPublicKey, Contact: ipsec.ContactPoint{Address: config.Gateway, IKEPort: config.IKEPort, NATTPort: config.NATTPort}}}
	if err := tunnel.start(plan, config.LocalID, config.PrivateKey, time.Now()); err != nil {
		t.Fatal(err)
	}
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	pump := func(label string, done func() bool) {
		t.Helper()
		for !done() {
			select {
			case packet := <-socket.ikePackets:
				if err := tunnel.handle(packet, plan, time.Now()); err != nil {
					t.Fatalf("%s: %v", label, err)
				}
			case <-ticker.C:
				if err := tunnel.tick(plan, time.Now()); err != nil {
					t.Fatalf("%s: %v", label, err)
				}
			case <-ctx.Done():
				t.Fatalf("%s timeout", label)
			}
		}
	}
	pump("AUTH", func() bool { return tunnel.phase == 3 })
	if !tunnel.natt || data.active == nil {
		t.Fatal("Windows AUTH did not install NAT-T CHILD")
	}
	t.Logf("Windows %s/%s authenticated a separate Linux StrongSwan peer through UDP %d/%d", runtime.GOOS, runtime.GOARCH, config.IKEPort, config.NATTPort)
	probe := func() {
		t.Helper()
		started := time.Now()
		tunnel.probeAt = started
		pump("DPD", func() bool { return tunnel.probeAt.After(started) && len(tunnel.pending) == 0 })
	}
	probe()
	sequence := uint16(0)
	echo := func(label string) {
		t.Helper()
		sequence++
		inner := windowsCrossEcho(sequence)
		allow := func(p []byte, outbound bool) bool {
			if len(p) != len(inner) || p[0] != 0x45 || p[9] != 1 || !bytes.Equal(p[24:], inner[24:]) {
				return false
			}
			if outbound {
				return bytes.Equal(p[12:20], inner[12:20]) && p[20] == 8
			}
			return bytes.Equal(p[12:16], inner[16:20]) && bytes.Equal(p[16:20], inner[12:16]) && p[20] == 0
		}
		if !data.submitOutbound(tunnel.generation, plan, inner, allow) {
			t.Fatalf("%s: outbound rejected", label)
		}
		select {
		case completion := <-data.completed:
			wire, endpoint, outbound, ok := data.accept(completion, plan, allow)
			if !ok || !outbound {
				t.Fatalf("%s: encrypt completion rejected", label)
			}
			if err := socket.WriteTunnel(tunnel.generation, wire, endpoint); err != nil {
				t.Fatal(err)
			}
		case <-ctx.Done():
			t.Fatalf("%s: encryption timeout", label)
		}
		for {
			select {
			case packet := <-socket.ikePackets:
				if err := tunnel.handle(packet, plan, time.Now()); err != nil {
					t.Fatal(err)
				}
			case packet := <-socket.espPackets:
				if !data.submitInbound(packet.generation, plan, packet.peer, packet.packet) {
					t.Fatalf("%s: inbound rejected", label)
				}
			case completion := <-data.completed:
				plain, _, outbound, ok := data.accept(completion, plan, allow)
				if !ok || outbound || plain[20] != 0 {
					t.Fatalf("%s: decrypted kernel echo rejected", label)
				}
				t.Log(label + ": Windows AES-GCM ESP and remote Linux kernel echo passed")
				return
			case <-ticker.C:
				if err := tunnel.tick(plan, time.Now()); err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatalf("%s: kernel echo timeout", label)
			}
		}
	}
	echo("initial CHILD")
	oldSPI := tunnel.child.InitiatorSPI
	tunnel.rekeyAt = time.Now()
	pump("CHILD rekey", func() bool { return tunnel.child.InitiatorSPI != oldSPI && len(tunnel.pending) == 0 })
	echo("replacement CHILD")
	tunnel.deleteAt = time.Now()
	pump("old CHILD Delete", func() bool { return data.sas[oldSPI] == nil })
	echo("after CHILD Delete")
	oldSession := tunnel.session
	tunnel.ikeRekeyAt = time.Now()
	pump("IKE rekey", func() bool { return tunnel.session != oldSession })
	probe()
	echo("after IKE rekey")
	t.Log("real Windows shared UDP, authenticated NAT-T, DPD, CHILD rekey/Delete, IKE rekey and four remote kernel echoes passed; Wintun and OS routing were not installed")
}

func windowsCrossEcho(sequence uint16) []byte {
	packet := make([]byte, 40)
	packet[0], packet[8], packet[9] = 0x45, 64, 1
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)))
	copy(packet[12:16], []byte{10, 55, 4, 2})
	copy(packet[16:20], []byte{10, 55, 4, 1})
	packet[20] = 8
	binary.BigEndian.PutUint16(packet[24:26], 0x5048)
	binary.BigEndian.PutUint16(packet[26:28], sequence)
	copy(packet[28:], []byte("windows-esp!"))
	checksum := func(p []byte) uint16 {
		var sum uint32
		for n := 0; n < len(p); n += 2 {
			sum += uint32(binary.BigEndian.Uint16(p[n:]))
		}
		for sum>>16 != 0 {
			sum = (sum & 65535) + (sum >> 16)
		}
		return ^uint16(sum)
	}
	binary.BigEndian.PutUint16(packet[10:12], checksum(packet[:20]))
	binary.BigEndian.PutUint16(packet[22:24], checksum(packet[20:]))
	return packet
}
