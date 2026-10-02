package photonwindows

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestDaemonRebindKeepsStateAndObjectPull(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"}
	logs := consoleLog{ready: make(chan string, 1)}
	daemon := NewDaemon(config, slog.New(slog.NewJSONHandler(logs, nil)))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	defer cancel()
	var address string
	select {
	case address = <-logs.ready:
	case err := <-done:
		t.Fatalf("startup: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("startup timed out")
	}
	for range 3 {
		if err := daemon.Rebind(t.Context()); err != nil {
			t.Fatal(err)
		}
		response, err := (objectPullClient{}).Exchange(t.Context(), address, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a.catofes."})
		if err != nil || !response.OK {
			t.Fatalf("object-pull after rebind: %v %v", response, err)
		}
	}
	if err := daemon.Run(ctx); err == nil {
		t.Fatal("duplicate daemon run accepted")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("daemon did not stop")
	}
	if !errors.Is(daemon.Rebind(t.Context()), net.ErrClosed) {
		t.Fatal("stopped daemon accepted rebind")
	}
	// Closing the daemon releases the original database handle.
	state := fixture.openState(t, fixture.leftPath, "node-a.catofes.")
	state.Close()
}

type daemonPlanLog struct {
	consoleLog
	plans chan struct{}
}

func (l daemonPlanLog) Write(data []byte) (int, error) {
	var record struct {
		Message string `json:"msg"`
	}
	if json.Unmarshal(data, &record) == nil && record.Message == "gateway_plan_changed" {
		l.plans <- struct{}{}
	}
	return l.consoleLog.Write(data)
}

func TestDaemonDiscardsPlannerCompletionAfterRebind(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"}
	logs := daemonPlanLog{consoleLog: consoleLog{ready: make(chan string, 1)}, plans: make(chan struct{}, 16)}
	daemon := NewDaemon(config, slog.New(slog.NewJSONHandler(logs, nil)))
	entered := make(chan context.Context, 2)
	release := make(chan struct{})
	daemon.planGateway = func(ctx context.Context, _ *Config, view corestate.View, now time.Time) GatewayPlan {
		entered <- ctx
		// Model a resolver completion racing with cancellation: it returns an old
		// result even though its request has been superseded by network rebind.
		select {
		case <-ctx.Done():
		case <-release:
		}
		return GatewayPlan{Revision: view.Revision, EvaluatedAt: now, Rejected: "no contact"}
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	defer cancel()
	select {
	case <-logs.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("startup timeout")
	}
	var old context.Context
	select {
	case old = <-entered:
	case <-time.After(time.Second):
		t.Fatal("planner did not start")
	}
	if err := daemon.Rebind(t.Context()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-old.Done():
	case <-time.After(time.Second):
		t.Fatal("rebind did not cancel old lookup")
	}
	select {
	case <-entered:
	case <-time.After(time.Second):
		t.Fatal("replacement plan did not start")
	}
	// Querying while DNS is blocked must remain responsive and fail closed.
	plan, err := daemon.GatewayPlan(t.Context())
	if err != nil || plan.Selected != nil || plan.Rejected == "" {
		t.Fatalf("pending plan: %+v, %v", plan, err)
	}
	select {
	case <-logs.plans:
		t.Fatal("superseded completion was consumed")
	default:
	}
	close(release)
	select {
	case <-logs.plans:
	case <-time.After(time.Second):
		t.Fatal("current completion was not consumed")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked by planner")
	}
}

func TestDaemonReportsPlannerTimeout(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"}
	logs := daemonPlanLog{consoleLog: consoleLog{ready: make(chan string, 1)}, plans: make(chan struct{}, 16)}
	daemon := NewDaemon(config, slog.New(slog.NewJSONHandler(logs, nil)))
	daemon.planGateway = func(ctx context.Context, _ *Config, view corestate.View, now time.Time) GatewayPlan {
		<-ctx.Done()
		return GatewayPlan{Revision: view.Revision, EvaluatedAt: now, Rejected: ctx.Err().Error()}
	}
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	defer cancel()
	select {
	case <-logs.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("startup timeout")
	}
	// A request deadline must not discard its completion (including already
	// resolved bootstrap hints); only the daemon's lifetime cancels delivery.
	select {
	case <-logs.plans:
	case <-time.After(4 * time.Second):
		t.Fatal("timed out plan completion discarded")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown blocked")
	}
}
