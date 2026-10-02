package photonwindows

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

type consoleLog struct {
	ready    chan string
	gateways chan gatewayLog
}

type gatewayLog struct {
	Revision   uint64             `json:"revision"`
	Candidates []GatewayCandidate `json:"candidates"`
}

func (l consoleLog) Write(data []byte) (int, error) {
	var record struct {
		Message string `json:"msg"`
		Address string `json:"address"`
	}
	if json.Unmarshal(data, &record) == nil && record.Message == "gossip_started" {
		l.ready <- record.Address
	}
	if record.Message == "gateway_candidates_changed" && l.gateways != nil {
		var update gatewayLog
		if json.Unmarshal(data, &update) == nil {
			l.gateways <- update
		}
	}
	return len(data), nil
}
func startConsole(t *testing.T, config *Config) (string, func()) {
	t.Helper()
	return startConsoleWithLogs(t, config, consoleLog{ready: make(chan string, 1)})
}

func startConsoleWithLogs(t *testing.T, config *Config, logs consoleLog) (string, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
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

func TestConsoleReevaluatesGatewayAfterGossip(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	left, stopLeft := startConsole(t, &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"})
	defer stopLeft()
	logs := consoleLog{ready: make(chan string, 1), gateways: make(chan gatewayLog, 16)}
	_, stopRight := startConsoleWithLogs(t, &Config{State: StateConfig{Path: fixture.rightPath}, ManagedZone: "node-b.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0", Gateway: GatewayConfig{AllowedZones: []zone.ZonePath{"node-a.catofes."}, BootstrapHints: []BootstrapHint{{Peer: "node-a.catofes.", Address: left}}}}, logs)
	defer stopRight()
	var first gatewayLog
	select {
	case first = <-logs.gateways:
	case <-time.After(5 * time.Second):
		t.Fatal("missing initial gateway diagnosis")
	}
	if first.Revision != uint64(fixture.rightRevision) || len(first.Candidates) != 1 || first.Candidates[0].Rejected == "" {
		t.Fatalf("initial diagnosis: %+v", first)
	}
	select {
	case next := <-logs.gateways:
		if next.Revision <= first.Revision || len(next.Candidates) != 1 || next.Candidates[0].Rejected == "" || next.Candidates[0].Rejected == first.Candidates[0].Rejected {
			t.Fatalf("gossip did not refresh diagnosis: %+v", next)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("missing gateway diagnosis after convergence")
	}
}

func TestConsoleReevaluatesGatewayExpiryWithoutRevisionChange(t *testing.T) {
	network, root, private := signedNetwork(t)
	expires := time.Now().Add(3 * time.Second)
	proof := network.Zones["catofes."].Delegations["node-a.catofes."]
	proof.ExpiresAt = &expires
	if err := photoncrypto.SignDelegation(proof, "catofes.", private); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "state.db")
	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	err = store.CommitCommon(t.Context(), &corestate.CommitCandidate{Verified: &corestate.VerifiedState{ManagedZone: "catofes.", TrustedRootPublicKey: root, IdentityPrivateKey: private, Network: network}}, corestate.ChangeSet{VerifiedRevision: 1, NetworkChanged: true})
	closeErr := store.Close()
	if err != nil || closeErr != nil {
		t.Fatalf("persist: %v, %v", err, closeErr)
	}
	logs := consoleLog{ready: make(chan string, 1), gateways: make(chan gatewayLog, 16)}
	_, stop := startConsoleWithLogs(t, &Config{State: StateConfig{Path: path}, ManagedZone: "catofes.", TrustedRootPublicKey: root, GossipListen: "127.0.0.1:0", Gateway: GatewayConfig{AllowedZones: []zone.ZonePath{"node-a.catofes."}}}, logs)
	defer stop()
	var first gatewayLog
	select {
	case first = <-logs.gateways:
	case <-time.After(time.Second):
		t.Fatal("missing initial diagnosis")
	}
	if len(first.Candidates) != 1 || first.Candidates[0].Rejected != "missing or mismatched record: ipsec/profile" {
		t.Fatalf("initial: %+v", first)
	}
	select {
	case next := <-logs.gateways:
		if next.Revision != first.Revision || len(next.Candidates) != 1 || next.Candidates[0].Rejected == "" || next.Candidates[0].Rejected == first.Candidates[0].Rejected {
			t.Fatalf("expiry: %+v", next)
		}
	case <-time.After(7 * time.Second):
		t.Fatal("no expiry observation without revision change")
	}
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
