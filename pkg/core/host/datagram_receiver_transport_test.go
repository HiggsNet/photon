package host_test

import (
	"testing"
	"time"

	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/host"
)

func TestGossipDriverDatagramReceiverAcceptsGossipTransport(t *testing.T) {
	datagramA, err := photonlinux.ListenGossipDatagram("127.0.0.1:0")
	if err != nil {
		t.Skipf("UDP sockets are unavailable: %v", err)
	}
	transportA, err := gossip.NewTransport(gossip.Config{PeerID: "test-a"}, datagramA)
	if err != nil {
		t.Fatalf("NewTransport(A): %v", err)
	}
	defer transportA.Close()
	datagramB, err := photonlinux.ListenGossipDatagram("127.0.0.1:0")
	if err != nil {
		t.Skipf("UDP sockets are unavailable: %v", err)
	}
	transportB, err := gossip.NewTransport(gossip.Config{PeerID: "test-b"}, datagramB)
	if err != nil {
		t.Fatalf("NewTransport(B): %v", err)
	}

	transportA.AddPeer("test-b", transportB.LocalAddr())
	transportB.AddPeer("test-a", transportA.LocalAddr())
	driver := host.NewGossipDriver(host.NewClock(nil), host.DefaultEventBuffer, nil, host.GossipDriverConfig{})
	if err := driver.StartGossipTransport(t.Context(), transportB, nil); err != nil {
		t.Fatalf("StartGossipTransport: %v", err)
	}
	defer driver.Stop()
	if err := transportA.Send("test-b", &gossip.Message{Type: gossip.MessagePing, Ping: &gossip.Ping{}}); err != nil {
		t.Fatalf("Send: %v", err)
	}
	select {
	case event := <-driver.Events():
		received, ok := event.(host.GossipPacketReceived)
		packet := received.Packet
		if !ok || packet == nil || packet.Message == nil || packet.Message.Type != gossip.MessagePing {
			t.Fatalf("packet = %#v, want PING", packet)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("timeout waiting for packet")
	}
}
