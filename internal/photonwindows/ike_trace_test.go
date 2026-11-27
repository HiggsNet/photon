package photonwindows

import (
	"bytes"
	"log/slog"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

func TestIKESocketTraceRecordsIngressOverflow(t *testing.T) {
	var output bytes.Buffer
	trace := startIKETrace(slog.New(slog.NewTextHandler(&output, &slog.HandlerOptions{Level: slog.LevelDebug})))
	socket, err := openPacketSockets(t.Context(), "127.0.0.1:0")
	if err != nil {
		trace.close()
		t.Fatal(err)
	}
	socket.ikeTrace = trace
	readerDone := make(chan struct{})
	go func() {
		defer close(readerDone)
		_, _, _ = socket.ReadDatagram(make([]byte, 1200))
	}()
	t.Cleanup(func() {
		socket.Close()
		<-readerDone
		trace.close()
		log := output.String()
		if count := strings.Count(log, "stage=ingress_queued"); count != cap(socket.ikePackets) {
			t.Errorf("queue admissions=%d, want %d", count, cap(socket.ikePackets))
		}
		if count := strings.Count(log, "stage=ingress_queue_full"); count != 1 {
			t.Errorf("logged ingress drops=%d, want 1", count)
		}
		if !strings.Contains(log, "rx_id=17") || !strings.Contains(log, "socket_read_at=") ||
			!strings.Contains(log, "initiator_spi=101 responder_spi=102 exchange=37 flags=32 message_id=77") {
			t.Error("trace lost the socket timestamp or correlation fields")
		}
	})

	sender, err := net.DialUDP("udp4", nil, socket.LocalAddr())
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	peer := sender.LocalAddr().(*net.UDPAddr).AddrPort()
	generation := socket.reserveTunnel(peer, peer)
	header := ike.Header{InitiatorSPI: 101, ResponderSPI: 102, ExchangeType: 37, Flags: ike.FlagResponse, MessageID: 77}
	body, err := header.Marshal(0, ike.HeaderLen)
	if err != nil {
		t.Fatal(err)
	}
	wire, err := ike.EncapsulateIKE(body)
	if err != nil {
		t.Fatal(err)
	}
	for range cap(socket.ikePackets) + 1 {
		if _, err := sender.Write(wire); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for socket.ikeIngressDrops.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if dropped, depth := socket.ikeIngressDrops.Load(), len(socket.ikePackets); dropped != 1 || depth != cap(socket.ikePackets) {
		t.Fatalf("shared ingress drops=%d, queue depth=%d", dropped, depth)
	}
	first := <-socket.ikePackets
	if first.generation != generation || first.trace == nil || first.trace.id != 1 || first.trace.at.IsZero() {
		t.Fatalf("queued datagram lost its original receive metadata: %+v", first.trace)
	}
}
