package photonwindows

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type consoleLog struct{ ready chan string }

func (l consoleLog) Write(data []byte) (int, error) {
	var record struct {
		Message string `json:"msg"`
		Address string `json:"address"`
	}
	if json.Unmarshal(data, &record) == nil && record.Message == "gossip_started" {
		l.ready <- record.Address
	}
	return len(data), nil
}
func startConsole(t *testing.T, config *Config) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	logs := consoleLog{make(chan string, 1)}
	go func() { done <- RunConsole(ctx, config, slog.New(slog.NewJSONHandler(logs, nil))) }()
	stopped := false
	stop := func() {
		t.Helper()
		if stopped {
			return
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("console exit: %v", err)
			}
		case <-time.After(2 * time.Second):
			t.Error("console failed to stop")
		}
	}
	t.Cleanup(stop)
	select {
	case addr := <-logs.ready:
		return addr, stop
	case err := <-done:
		stopped = true
		cancel()
		t.Fatalf("console startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("console startup timeout")
	}
	return "", stop
}

func TestConsoleRealGossipPersistsAndRestarts(t *testing.T) {
	for _, listen := range []string{"127.0.0.1:0", "[::1]:0"} {
		t.Run(listen, func(t *testing.T) { testConsoleRealGossipPersistsAndRestarts(t, listen) })
	}
}

func testConsoleRealGossipPersistsAndRestarts(t *testing.T, listen string) {
	fixture := newWindowsGossipFixture(t)
	config := func(path string, managed zone.ZonePath) *Config {
		return &Config{State: StateConfig{Path: path}, ManagedZone: managed, TrustedRootPublicKey: fixture.rootPublic, GossipListen: listen}
	}
	left, stopLeft := startConsole(t, config(fixture.leftPath, "node-a.catofes."))
	rightConfig := config(fixture.rightPath, "node-b.catofes.")
	rightConfig.Gateway.BootstrapHints = []BootstrapHint{{Peer: "node-a.catofes.", Address: left}}
	right, stopRight := startConsole(t, rightConfig)
	waitForWindowsState(t, 5*time.Second, func() bool {
		response, err := (objectPullClient{}).Exchange(t.Context(), right, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a.catofes."})
		return err == nil && response.OK && response.Snapshot != nil
	})
	stopRight()
	stopLeft()
	state := fixture.openState(t, fixture.rightPath, "node-b.catofes.")
	view, err := state.ReadView(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if view.Revision != fixture.rightRevision+1 || view.State.Network.Zones["node-a.catofes."] == nil {
		t.Fatalf("missing persisted convergence at revision %d", view.Revision)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	// Rebind the exact UDP/TCP address and reopen the same database after shutdown.
	rightConfig.GossipListen = right
	rightConfig.Gateway.BootstrapHints = nil
	restarted, stopRestarted := startConsole(t, rightConfig)
	response, err := (objectPullClient{}).Exchange(t.Context(), restarted, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a.catofes."})
	if err != nil || !response.OK {
		t.Fatalf("restored object: %v, %v", response, err)
	}
	stopRestarted()
}

func TestConsoleStartupFailureReleasesStateAndUDP(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	occupied, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer occupied.Close()
	config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: occupied.Addr().String()}
	if err := RunConsole(t.Context(), config, slog.New(slog.NewTextHandler(io.Discard, nil))); err == nil {
		t.Fatal("expected TCP bind failure")
	}
	state := fixture.openState(t, fixture.leftPath, "node-a.catofes.")
	defer state.Close()
	packet, err := net.ListenPacket("udp", config.GossipListen)
	if err != nil {
		t.Fatalf("UDP leaked after startup failure: %v", err)
	}
	packet.Close()
}

func TestObjectPullCancellationClosesBlockedRead(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := (objectPullClient{}).Exchange(ctx, listener.Addr().String(), &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a.catofes."})
		done <- err
	}()
	conn, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	cancel()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("expected cancelled exchange")
		}
	case <-time.After(time.Second):
		t.Fatal("cancellation did not unblock read")
	}
}
