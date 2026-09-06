package host

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type blockingObjectPullClient struct{ entered chan struct{} }

func (client *blockingObjectPullClient) Exchange(ctx context.Context, _ string, _ *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	select {
	case client.entered <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return nil, ctx.Err()
}

func TestGossipObjectPullWorkersUpdateRuntimeObservability(t *testing.T) {
	now := time.Unix(100, 0)
	driver := NewGossipDriver(newFakeClock(now), 4, nil, GossipDriverConfig{})
	defer driver.Stop()
	client := &memoryObjectPullClient{response: &gossip.ObjectPullResponse{OK: true, Snapshot: &corestate.ZoneSnapshot{Zone: "a.catofes."}}}
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{
		Client: client,
		Now:    func() time.Time { return now },
		Discovery: func() GossipDiscoveryInput {
			return GossipDiscoveryInput{Network: zone.NewNetworkState(), Bootstrap: map[string]*net.UDPAddr{"peer-a": {IP: net.ParseIP("127.0.0.1"), Port: 1}}}
		},
	})
	if err := driver.StartGossipObjectPullWorkers(t.Context(), executor, 1, 1); err != nil {
		t.Fatal(err)
	}
	if err := driver.SubmitGossipObjectPull(gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "a.catofes."}); err != nil {
		t.Fatal(err)
	}
	select {
	case <-driver.Events():
	case <-time.After(time.Second):
		t.Fatal("object-pull completion was not delivered")
	}
	diagnostics, ok := driver.Observability.Snapshot("peer-a", now)
	if !ok || diagnostics.ObjectPullStats == nil || diagnostics.ObjectPullStats.Attempts != 1 || diagnostics.ObjectPullStats.Successes != 1 || diagnostics.ObjectPullStats.LastBytes == 0 {
		t.Fatalf("object-pull diagnostics = %#v", diagnostics)
	}
}

func TestGossipObjectPullWorkersProvideBoundedBackpressureAndStop(t *testing.T) {
	driver := NewGossipDriver(nil, 4, nil, GossipDriverConfig{})
	client := &blockingObjectPullClient{entered: make(chan struct{}, 1)}
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{
		Client: client,
		Discovery: func() GossipDiscoveryInput {
			return GossipDiscoveryInput{
				Network: zone.NewNetworkState(),
				Bootstrap: map[string]*net.UDPAddr{
					"peer-a": {IP: net.ParseIP("127.0.0.1"), Port: 1},
					"peer-b": {IP: net.ParseIP("127.0.0.1"), Port: 2},
				},
			}
		},
	})
	if err := driver.StartGossipObjectPullWorkers(t.Context(), executor, 1, 1); err != nil {
		t.Fatal(err)
	}
	first := gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "a.catofes."}
	if err := driver.SubmitGossipObjectPull(first); err != nil {
		t.Fatal(err)
	}
	<-client.entered
	if err := driver.SubmitGossipObjectPull(gossip.StartObjectPullAction{PeerID: "peer-b", Zone: "b.catofes."}); err != nil {
		t.Fatal(err)
	}
	if err := driver.SubmitGossipObjectPull(gossip.StartObjectPullAction{PeerID: "peer-c", Zone: "c.catofes."}); !errors.Is(err, ErrGossipObjectPullQueueFull) {
		t.Fatalf("third submit error = %v, want %v", err, ErrGossipObjectPullQueueFull)
	}
	if got := driver.PendingGossipObjectPullCount(); got != 2 {
		t.Fatalf("pending = %d, want 2", got)
	}
	driver.Stop()
	if got := driver.PendingGossipObjectPullCount(); got != 0 {
		t.Fatalf("pending after stop = %d, want 0", got)
	}
	if err := driver.SubmitGossipObjectPull(first); !errors.Is(err, ErrGossipDriverStopped) {
		t.Fatalf("submit after stop = %v, want %v", err, ErrGossipDriverStopped)
	}
}
