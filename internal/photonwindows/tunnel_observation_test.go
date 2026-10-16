package photonwindows

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestTunnelObservationRejectedAuthPreservesExchange(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	plan := GatewayPlan{Selected: &GatewaySelection{Zone: "gateway."}}
	tunnel := &gatewayTunnel{phase: 2, plan: plan, peer: netip.MustParseAddrPort("192.0.2.1:4500"), generation: 7, attempts: 3, pending: [][]byte{{1, 2, 3}}, retryAt: now.Add(time.Second)}
	deadline := tunnel.retryAt
	// This reaches the real AUTH decoder, not a synthetic observation event.
	err := tunnel.handle(tunnelDatagram{generation: 7, peer: tunnel.peer, packet: []byte{1}}, plan, now)
	if err == nil {
		t.Fatal("malformed AUTH response accepted")
	}
	got := tunnel.observeIKE()
	if got.Phase != "auth" || !got.AttemptActive || got.Live || got.ChildLive || got.Gateway != "" || got.Generation != 0 {
		t.Fatalf("unauthenticated attempt promoted to live: %+v", got)
	}
	if got.AttemptGateway != "gateway." || got.AttemptRemoteEndpoint != "192.0.2.1:4500" || got.AttemptGeneration != 7 || got.SendAttempts != 3 || !got.NextRetransmitAt.Equal(deadline) {
		t.Fatalf("attempt context lost: %+v", got)
	}
	if got.LastFailure == nil || got.LastFailure.Historical || got.LastFailure.Event != "packet_rejected" || got.LastFailure.Message != err.Error() || got.LastFailure.Phase != "auth" || !got.LastFailure.At.Equal(now) || got.LastEvent != "packet_rejected" {
		t.Fatalf("missing rejection context: %+v", got)
	}
	if !tunnel.retryAt.Equal(deadline) || tunnel.attempts != 3 || len(tunnel.pending) != 1 || tunnel.phase != 2 || tunnel.failed != nil {
		t.Fatal("diagnosis changed retry or validation behavior")
	}
	// Returned DTOs must not alias the event owner's mutable history.
	got.LastFailure.Message = "modified by consumer"
	if tunnel.observeIKE().LastFailure.Message == got.LastFailure.Message {
		t.Fatal("observation aliases owner")
	}
	if got.LastRejection == nil || got.LastRejection.Message != err.Error() || got.LastRejection == got.LastFailure {
		t.Fatal("rejection must be an independently detached public record")
	}
	got.LastRejection.Message = "modified rejection"
	if tunnel.observeIKE().LastRejection.Message != err.Error() {
		t.Fatal("rejection aliases owner")
	}
	// Exhaustion is a lifecycle failure, not a replacement for the concrete
	// AUTH packet rejection which preceded it.
	tunnel.attempts = 5
	if err := tunnel.tick(plan, deadline); err == nil {
		t.Fatal("missing retransmission exhaustion")
	}
	got = tunnel.observeIKE()
	if got.LastFailure.Event != "lifecycle_failed" || got.LastRejection.Message != err.Error() || got.LastRejection.Historical || got.LastRejection.Phase != "auth" || got.LastRejection.Generation != 7 || !got.LastRejection.At.Equal(now) {
		t.Fatalf("timeout lost concrete rejection: %+v", got)
	}
	// Stop uses only endpoint reservation here: no network socket or I/O is
	// needed to prove that ending the AUTH attempt preserves its rejection.
	tunnel.socket = &packetSockets{}
	tunnel.data = newSerialGatewayDataplane(t.Context())
	defer tunnel.data.close()
	tunnel.stop()
	got = tunnel.observeIKE()
	if !got.LastRejection.Historical || got.LastRejection.Phase != "auth" || got.LastRejection.Generation != 7 || got.AttemptActive {
		t.Fatalf("stopping lost AUTH rejection: %+v", got)
	}
	_, private, keyErr := ed25519.GenerateKey(rand.Reader)
	if keyErr != nil {
		t.Fatal(keyErr)
	}
	// A fresh attempt can itself fail before sending; that newer failure must
	// not erase or relabel the previous attempt's concrete AUTH rejection.
	if startErr := tunnel.start(GatewayPlan{Selected: &GatewaySelection{Zone: "next."}}, "leaf.", private, now.Add(time.Minute)); startErr == nil {
		t.Fatal("invalid new endpoint accepted")
	}
	got = tunnel.observeIKE()
	if got.LastFailure.Event != "start_failed" || got.AttemptGateway != "next." || got.LastRejection.Message != err.Error() || !got.LastRejection.Historical || got.LastRejection.Phase != "auth" || got.LastRejection.Generation != 7 || got.LastRejection.Gateway != "gateway." || got.LastRejection.RemoteEndpoint != "192.0.2.1:4500" {
		t.Fatalf("new attempt overwrote old AUTH rejection: %+v", got)
	}
}

func TestTunnelObservationFailureHistoryAndBounds(t *testing.T) {
	now := time.Unix(1700000000, 0).UTC()
	tunnel := &gatewayTunnel{phase: 2, generation: 9, peer: netip.MustParseAddrPort("192.0.2.9:4500"), plan: GatewayPlan{Selected: &GatewaySelection{Zone: "old."}}}
	tunnel.observeEvent("packet_rejected", now, errors.New(strings.Repeat("x", 4096)))
	failure := tunnel.observeIKE().LastFailure
	if failure == nil || len(failure.Message) > 256 {
		t.Fatalf("unbounded failure: %+v", failure)
	}
	// Successful authentication preserves the old reason as explicit history.
	tunnel.phase = 3
	tunnel.observeProgress()
	tunnel.observeEvent("authenticated", now.Add(time.Second), nil)
	got := tunnel.observeIKE()
	if got.LastEvent != "authenticated" || !got.LastFailure.Historical || !got.LastRejection.Historical || got.LastFailure.Phase != "auth" || got.LastFailure.Generation != 9 || got.LastFailure.Gateway != "old." {
		t.Fatalf("history rewritten as current session failure: %+v", got)
	}
	// A later attempt's target must not relabel the earlier failure.
	tunnel.generation, tunnel.peer = 11, netip.MustParseAddrPort("192.0.2.11:4500")
	tunnel.plan.Selected = &GatewaySelection{Zone: "new."}
	tunnel.phase = 1
	tunnel.observeEvent("exchange_sent", now.Add(2*time.Second), nil)
	got = tunnel.observeIKE()
	if got.AttemptGateway != "new." || got.AttemptGeneration != 11 || got.LastFailure.Gateway != "old." || got.LastFailure.RemoteEndpoint != "192.0.2.9:4500" {
		t.Fatalf("cross-attempt history corrupted: %+v", got)
	}
	wire, err := json.Marshal(got)
	if err != nil || !json.Valid(wire) || len(wire) > 4096 {
		t.Fatalf("invalid/unbounded public JSON: %s, %v", wire, err)
	}
}

func TestTunnelObservationRealRetryStopAndRestart(t *testing.T) {
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
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	port := peer.LocalAddr().(*net.UDPAddr).Port
	plan := GatewayPlan{Selected: &GatewaySelection{Zone: "gateway.", Identity: "gateway.", PublicKey: public, Contact: ipsec.ContactPoint{Address: "127.0.0.1", IKEPort: uint16(port), NATTPort: 4500}}}
	data := newGatewayDataplane(t.Context())
	defer data.close()
	tunnel := &gatewayTunnel{socket: socket, data: data}
	defer tunnel.stop()
	now := time.Now()
	if err := tunnel.start(plan, "leaf.", private, now); err != nil {
		t.Fatal(err)
	}
	first := tunnel.observeIKE()
	if first.SendAttempts != 1 || !first.NextRetransmitAt.Equal(now.Add(time.Second)) || first.LastEvent != "exchange_sent" || !first.RetryAt.IsZero() {
		t.Fatalf("first send: %+v", first)
	}
	// A concrete packet rejection must survive the later exhausted-budget
	// error, stop, and a fresh attempt with a different socket generation.
	rejected := errors.New("ike: invalid SA_INIT response")
	tunnel.observeEvent("packet_rejected", now, rejected)
	for range 4 {
		if err := tunnel.tick(plan, tunnel.retryAt); err != nil {
			t.Fatal(err)
		}
	}
	if err := tunnel.tick(plan, tunnel.retryAt); err == nil {
		t.Fatal("missing retry exhaustion")
	}
	failed := tunnel.observeIKE()
	if failed.LastFailure == nil || failed.LastFailure.Event != "lifecycle_failed" || failed.SendAttempts != 5 || failed.LastFailure.Historical || failed.LastRejection == nil || failed.LastRejection.Message != rejected.Error() || failed.LastRejection.Historical {
		t.Fatalf("retry failure: %+v", failed)
	}
	tunnel.stop()
	tunnel.diagnostic.retryAt = now.Add(time.Minute) // existing console backoff mirror
	stopped := tunnel.observeIKE()
	if stopped.LastRejection == nil || !stopped.LastRejection.Historical || stopped.LastRejection.Message != rejected.Error() || stopped.LastRejection.Generation != first.AttemptGeneration || stopped.LastRejection.Phase != "init" || !stopped.LastRejection.At.Equal(now) {
		t.Fatalf("stop lost rejection context: %+v", stopped)
	}
	if stopped.AttemptActive || stopped.Live || stopped.Phase != "idle" || !stopped.NextRetransmitAt.IsZero() || stopped.SendAttempts != 0 || !stopped.LastFailure.Historical || stopped.AttemptGeneration != first.AttemptGeneration || stopped.LastFailure.Generation != first.AttemptGeneration || !stopped.RetryAt.Equal(now.Add(time.Minute)) {
		t.Fatalf("stopped state claims active retransmission or loses history: %+v", stopped)
	}
	if err := tunnel.start(plan, "leaf.", private, now.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	restarted := tunnel.observeIKE()
	if restarted.LastRejection == nil || !restarted.LastRejection.Historical || restarted.LastRejection.Generation != first.AttemptGeneration || restarted.LastRejection.Message != rejected.Error() || restarted.LastRejection.RemoteEndpoint != first.AttemptRemoteEndpoint {
		t.Fatalf("restart relabeled old rejection: %+v", restarted)
	}
	if !restarted.AttemptActive || restarted.AttemptGeneration == first.AttemptGeneration || !restarted.RetryAt.IsZero() || !restarted.LastFailure.Historical || restarted.SendAttempts != 1 {
		t.Fatalf("restart state: %+v", restarted)
	}
	wire, err := json.Marshal(restarted)
	if err != nil || strings.Contains(string(wire), "private") || strings.Contains(string(wire), "pending") {
		t.Fatalf("diagnostic exposes private runtime state: %s, %v", wire, err)
	}
}
