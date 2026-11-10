package photonwindows

import (
	"context"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

type stalledGossipLog struct {
	slog.Handler
	entered chan struct{}
	release chan struct{}
}

func (l stalledGossipLog) Handle(ctx context.Context, record slog.Record) error {
	if record.Message == "session_state_changed" {
		select {
		case l.entered <- struct{}{}:
		default:
		}
		<-l.release
	}
	return l.Handler.Handle(ctx, record)
}

func TestDaemonServesMeshWhileGossipWorkerStalls(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	config := &Config{
		State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.",
		TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0",
		Gateway: GatewayConfig{BootstrapHints: []BootstrapHint{{Peer: zone.ZonePath("node-b.catofes."), Address: "127.0.0.1:33434"}}},
	}
	log := stalledGossipLog{
		Handler: slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelDebug}),
		entered: make(chan struct{}, 1), release: make(chan struct{}),
	}
	d := NewDaemon(config, slog.New(log))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		close(log.release)
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(5 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	select {
	case <-log.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("Gossip did not reach the stalled operation")
	}
	select {
	case <-d.ready:
	case <-time.After(time.Second):
		t.Fatal("Gossip stalled the Mesh event owner")
	}
	query, stop := context.WithTimeout(ctx, time.Second)
	defer stop()
	if observation, err := d.Observe(query); err != nil || !observation.Running {
		t.Fatalf("Mesh observation while Gossip is stalled: running=%t, err=%v", observation.Running, err)
	}
}
