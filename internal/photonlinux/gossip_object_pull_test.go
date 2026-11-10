package photonlinux

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestGossipObjectPullClientExchange(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("TCP sockets are unavailable: %v", err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		serverDone <- gossip.ServeObjectPull(conn, func(request *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
			return &gossip.ObjectPullResponse{OK: request != nil && request.Type == gossip.ObjectPullZone}
		})
	}()
	client := GossipObjectPullClient{DialTimeout: time.Second, IOTimeout: time.Second}
	response, err := client.Exchange(t.Context(), listener.Addr().String(), &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a."})
	if err != nil {
		t.Fatalf("Exchange: %v", err)
	}
	if !response.OK {
		t.Fatalf("response = %#v, want OK", response)
	}
	if err := <-serverDone; err != nil {
		t.Fatalf("ServeObjectPull: %v", err)
	}
}

func TestGossipObjectPullClientHonorsExpiredContext(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	_, err := (GossipObjectPullClient{}).Exchange(ctx, "127.0.0.1:1", &gossip.ObjectPullRequest{
		Type: gossip.ObjectPullZone, Zone: "node-a.",
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("Exchange error = %v, want context.Canceled", err)
	}
}

func TestGossipObjectPullClientCancelClosesConnectedSocket(t *testing.T) {
	listener, err := net.ListenTCP("tcp4", &net.TCPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	_ = listener.SetDeadline(time.Now().Add(time.Second))

	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	result := make(chan error, 1)
	go func() {
		_, err := (GossipObjectPullClient{}).Exchange(ctx, listener.Addr().String(), &gossip.ObjectPullRequest{
			Type: gossip.ObjectPullZone, Zone: "node-a.",
		})
		result <- err
	}()
	conn, err := listener.AcceptTCP()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	if _, err := gossip.DecodeObjectPullRequest(conn); err != nil {
		t.Fatal(err)
	}
	cancel()
	var buffer [1]byte
	if _, err := conn.Read(buffer[:]); !errors.Is(err, io.EOF) {
		t.Fatalf("server read = %v, want EOF from client socket closure", err)
	}
	select {
	case err := <-result:
		if err == nil {
			t.Fatal("canceled exchange returned success")
		}
	case <-time.After(time.Second):
		t.Fatal("cancel did not interrupt the TCP read")
	}
}

func TestGossipObjectPullExecutorFallsBackThroughLinuxClient(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	serverDone := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			serverDone <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(time.Second))
		serverDone <- gossip.ServeObjectPull(conn, func(req *gossip.ObjectPullRequest) *gossip.ObjectPullResponse {
			return &gossip.ObjectPullResponse{OK: true, Snapshot: &corestate.ZoneSnapshot{Zone: req.Zone}}
		})
	}()
	peer := zone.ZonePath("peer.catofes.")
	network := zone.NewNetworkState()
	// Seed a discovery projection; signature/adoption checks are covered by the
	// common signed-network tests. This exercises actual Linux TCP fallback.
	state := zone.NewZoneState(peer, nil)
	value, err := json.Marshal(gossip.EndpointRecord{UpdatedAt: time.Now().Unix(), Endpoints: []gossip.EndpointEntry{{Address: "127.0.0.1", Port: uint16(listener.Addr().(*net.TCPAddr).Port), Source: "advertise"}}})
	if err != nil {
		t.Fatal(err)
	}
	state.Records[gossip.EndpointRecordKeyUDP] = &zone.Record{Value: value}
	network.Zones[peer] = state
	executor := host.NewGossipObjectPullExecutor(host.GossipObjectPullExecutorConfig{
		Client: GossipObjectPullClient{},
		Discovery: func(string) host.GossipDiscoveryInput {
			return host.GossipDiscoveryInput{
				Network:   network,
				Bootstrap: map[string]*net.UDPAddr{peer.String(): {IP: net.IPv6loopback, Port: listener.Addr().(*net.TCPAddr).Port}},
			}
		},
	})
	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	result := executor.PullGossipObject(ctx, gossip.StartObjectPullAction{PeerID: peer.String(), Zone: peer})
	if result.Err != nil || result.Addr != listener.Addr().String() || result.Snapshot == nil {
		t.Fatalf("Linux fallback result = %#v", result)
	}
	if err := <-serverDone; err != nil {
		t.Fatal(err)
	}
}
