package photonwindows

import (
	"crypto/ed25519"
	"crypto/rand"
	"net"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/esp"
	"github.com/HiggsNet/photon/internal/photonclient/ike"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestTunnelSequenceExhaustionSchedulesFreshChild(t *testing.T) {
	data, plan, _, _ := dataplaneFixture(t)
	now := time.Now()
	tunnel := gatewayTunnel{data: data, rekeyAt: now.Add(time.Minute)}
	result := dataplaneCompletion{job: dataplaneJob{ctx: data.generationCtx, generation: data.generation, sa: data.active, outbound: true}, err: esp.ErrSequenceExhausted}
	stale := result
	stale.job.generation--
	tunnel.observeData(stale, plan, now)
	if !tunnel.rekeyAt.After(now) {
		t.Fatal("stale error changed rekey schedule")
	}
	tunnel.observeData(result, plan, now)
	if !tunnel.rekeyAt.Equal(now) {
		t.Fatal("sequence exhaustion did not wake rekey")
	}
}

func TestTunnelRetryAndRevocation(t *testing.T) {
	s, err := openPacketSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	public, private, _ := ed25519.GenerateKey(rand.Reader)
	port := peer.LocalAddr().(*net.UDPAddr).AddrPort().Port()
	plan := GatewayPlan{Selected: &GatewaySelection{Zone: "gateway.", Identity: "gateway.", PublicKey: public, Contact: ipsec.ContactPoint{Address: "127.0.0.1", IKEPort: port, NATTPort: 4500}}}
	data := newGatewayDataplane(t.Context())
	defer data.close()
	tunnel := &gatewayTunnel{socket: s, data: data}
	now := time.Now()
	if err := tunnel.start(plan, "leaf.", private, now); err != nil {
		t.Fatal(err)
	}
	defer tunnel.stop()
	for attempt := 1; attempt < 5; attempt++ {
		if err := tunnel.tick(plan, tunnel.retryAt); err != nil {
			t.Fatalf("retry %d: %v", attempt, err)
		}
	}
	if err := tunnel.tick(plan, tunnel.retryAt); err == nil {
		t.Fatal("unbounded retry")
	}
	if err := tunnel.tick(GatewayPlan{Rejected: "revoked"}, now); err == nil {
		t.Fatal("revoked gateway retained")
	}
	old := tunnel.generation
	tunnel.stop()
	if data.active != nil || tunnel.phase != 0 || tunnel.generation == old {
		t.Fatal("stop retained SA/generation")
	}
	if err := s.WriteTunnel(old, []byte{0xff}, netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), port)); err == nil {
		t.Fatal("old completion can send")
	}
}

func TestTunnelRevocationPrecedesOldIKERetransmission(t *testing.T) {
	socket, err := openPacketSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer socket.Close()
	peer, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer peer.Close()
	endpoint := peer.LocalAddr().(*net.UDPAddr).AddrPort()
	session, err := ike.NewInitiator()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	old := &ikeOverlap{session: session, pending: [][]byte{session.Request()}, retryAt: now.Add(-time.Second), until: now.Add(time.Minute)}
	tunnel := &gatewayTunnel{socket: socket, phase: 3, peer: endpoint, generation: socket.SelectTunnel(endpoint, endpoint), ikeExpiresAt: now.Add(time.Hour), oldIKE: []*ikeOverlap{old}, plan: GatewayPlan{Selected: &GatewaySelection{Identity: "revoked-gateway."}}}
	if err := tunnel.tick(GatewayPlan{Rejected: "revoked"}, now); err == nil {
		t.Fatal("revoked gateway accepted")
	}
	if old.attempts != 0 {
		t.Fatal("revoked old IKE retransmission was attempted")
	}
	if err := peer.SetReadDeadline(time.Now().Add(100 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, _, err := peer.ReadFromUDP(make([]byte, 2048)); err == nil {
		t.Fatal("packet sent after revocation")
	} else if timeout, ok := err.(net.Error); !ok || !timeout.Timeout() {
		t.Fatal(err)
	}
}
