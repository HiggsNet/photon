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

type memoryObjectPullClient struct {
	response *gossip.ObjectPullResponse
	err      error
	addr     string
	request  *gossip.ObjectPullRequest
}

func (client *memoryObjectPullClient) Exchange(_ context.Context, addr string, request *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	client.addr = addr
	client.request = request
	return client.response, client.err
}

func TestGossipObjectPullExecutorResolvesValidatesAndObserves(t *testing.T) {
	now := time.Unix(1000, 0)
	snapshot := &corestate.ZoneSnapshot{Zone: "node-a."}
	client := &memoryObjectPullClient{response: &gossip.ObjectPullResponse{OK: true, Snapshot: snapshot}}
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{
		Client: client,
		Now:    func() time.Time { return now },
		Discovery: func() GossipDiscoveryInput {
			return GossipDiscoveryInput{
				Network:   zone.NewNetworkState(),
				Bootstrap: map[string]*net.UDPAddr{"peer-a": {IP: net.ParseIP("192.0.2.10"), Port: 33434}},
			}
		},
	})
	completion := executor.PullGossipObject(t.Context(), gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "node-a."})
	if completion.Err != nil || completion.Snapshot != snapshot {
		t.Fatalf("completion = %#v", completion)
	}
	if client.addr != "192.0.2.10:33434" || client.request == nil || client.request.Zone != "node-a." {
		t.Fatalf("client exchange = addr %q request %#v", client.addr, client.request)
	}
	if completion.Bytes == 0 || completion.Addr != client.addr || completion.Unreachable {
		t.Fatalf("completion diagnostics = %#v", completion)
	}
}

func TestGossipObjectPullExecutorRejectsMissingAddressAndInvalidResponse(t *testing.T) {
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{
		Client:    &memoryObjectPullClient{},
		Discovery: func() GossipDiscoveryInput { return GossipDiscoveryInput{Network: zone.NewNetworkState()} },
	})
	localFailure := executor.PullFrom(t.Context(), GossipDiscoveryInput{}, gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "node-a."})
	if localFailure.Err == nil || localFailure.Unreachable {
		t.Fatalf("missing local state classified as unreachable: %#v", localFailure)
	}
	completion := executor.PullGossipObject(t.Context(), gossip.StartObjectPullAction{PeerID: "unknown", Zone: "node-a."})
	if completion.Err == nil {
		t.Fatal("missing address succeeded")
	}

	wantErr := errors.New("dial failed")
	client := &memoryObjectPullClient{err: wantErr}
	executor = NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{Client: client})
	completion = executor.PullFrom(t.Context(), GossipDiscoveryInput{
		Network:   zone.NewNetworkState(),
		Bootstrap: map[string]*net.UDPAddr{"peer-a": {IP: net.ParseIP("127.0.0.1"), Port: 1}},
	}, gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "node-a."})
	if !errors.Is(completion.Err, wantErr) {
		t.Fatalf("error = %v, want %v", completion.Err, wantErr)
	}
}

func TestGossipObjectPullCancellationIsNotUnreachable(t *testing.T) {
	err := &net.OpError{Op: "dial", Net: "tcp", Err: context.Canceled}
	if isGossipObjectPullUnreachable(err) {
		t.Fatal("cancellation triggered transport fallback")
	}
}

func TestGossipObjectPullExecutorRejectsWrongZone(t *testing.T) {
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{
		Client: &memoryObjectPullClient{response: &gossip.ObjectPullResponse{
			OK: true, Snapshot: &corestate.ZoneSnapshot{Zone: "other."},
		}},
	})
	completion := executor.PullFrom(t.Context(), GossipDiscoveryInput{
		Network:   zone.NewNetworkState(),
		Bootstrap: map[string]*net.UDPAddr{"peer-a": {IP: net.ParseIP("127.0.0.1"), Port: 1}},
	}, gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "node-a."})
	if completion.Err == nil {
		t.Fatal("wrong-zone response succeeded")
	}
}

func TestGossipObjectPullExecutorPerPeerLimit(t *testing.T) {
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{PerPeerLimit: 2})
	first, err := executor.acquirePeer("peer-a")
	if err != nil {
		t.Fatal(err)
	}
	defer first()
	second, err := executor.acquirePeer("peer-a")
	if err != nil {
		t.Fatal(err)
	}
	defer second()
	if _, err := executor.acquirePeer("peer-a"); err == nil {
		t.Fatal("third same-peer pull acquired beyond limit")
	}
	if other, err := executor.acquirePeer("peer-b"); err != nil {
		t.Fatalf("independent peer rejected: %v", err)
	} else {
		other()
	}
}

func TestGossipObjectPullExecutorQuotaAccountsBytesAndObjects(t *testing.T) {
	now := time.Unix(1000, 0)
	executor := NewGossipObjectPullExecutor(GossipObjectPullExecutorConfig{Quota: gossip.QuotaConfig{
		ByteRate: 1, ByteBurst: 8, ObjectRate: 1, ObjectBurst: 1,
	}})
	if err := executor.allowQuota("peer-a", 4, now); err != nil {
		t.Fatalf("allow(first): %v", err)
	}
	if err := executor.allowQuota("peer-a", 1, now); !errors.Is(err, gossip.ErrQuotaExceeded) {
		t.Fatalf("allow(over objects) = %v, want ErrQuotaExceeded", err)
	}
	if err := executor.allowQuota("peer-a", 9, now.Add(2*time.Second)); !errors.Is(err, gossip.ErrQuotaExceeded) {
		t.Fatalf("allow(over bytes) = %v, want ErrQuotaExceeded", err)
	}
}
