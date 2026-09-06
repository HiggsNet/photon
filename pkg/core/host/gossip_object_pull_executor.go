package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

const DefaultGossipObjectPullPerPeer = 2

var ErrGossipObjectPullClientRequired = errors.New("gossip object-pull client is required")

// GossipObjectPullClient is the injected outbound stream-exchange capability.
// Platform implementations own dial, connection deadlines and socket I/O.
type GossipObjectPullClient interface {
	Exchange(context.Context, string, *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error)
}

type GossipObjectPullExecutorConfig struct {
	Client       GossipObjectPullClient
	Discovery    func() GossipDiscoveryInput
	Now          func() time.Time
	PerPeerLimit int
	Quota        gossip.QuotaConfig
}

// GossipObjectPullExecutor is the common worker used by GossipDriver and offline
// recovery. It owns peer concurrency, quota, address resolution and response
// validation; the injected client performs only the TCP exchange.
type GossipObjectPullExecutor struct {
	config GossipObjectPullExecutorConfig

	peerMu  sync.Mutex
	peers   map[string]int
	quotaMu sync.Mutex
	quotas  *gossip.PeerQuotas
}

func NewGossipObjectPullExecutor(config GossipObjectPullExecutorConfig) *GossipObjectPullExecutor {
	if config.Now == nil {
		config.Now = time.Now
	}
	if config.PerPeerLimit <= 0 {
		config.PerPeerLimit = DefaultGossipObjectPullPerPeer
	}
	if config.Quota.ByteRate <= 0 {
		config.Quota = gossip.QuotaConfig{ByteRate: 8 << 20, ByteBurst: 8 << 20, ObjectRate: 16, ObjectBurst: 16}
	}
	return &GossipObjectPullExecutor{
		config: config,
		peers:  make(map[string]int),
		quotas: gossip.NewPeerQuotas(config.Quota),
	}
}

func (executor *GossipObjectPullExecutor) PullGossipObject(ctx context.Context, action gossip.StartObjectPullAction) GossipObjectPullCompletion {
	if executor == nil || executor.config.Discovery == nil {
		return GossipObjectPullCompletion{PeerID: action.PeerID, Zone: action.Zone, Err: errors.New("gossip object-pull discovery is required")}
	}
	return executor.PullFrom(ctx, executor.config.Discovery(), action)
}

func (executor *GossipObjectPullExecutor) PullFrom(ctx context.Context, input GossipDiscoveryInput, action gossip.StartObjectPullAction) GossipObjectPullCompletion {
	completion := GossipObjectPullCompletion{PeerID: action.PeerID, Zone: action.Zone}
	if executor == nil || executor.config.Client == nil {
		completion.Err = ErrGossipObjectPullClientRequired
		return completion
	}
	now := executor.config.Now()
	if input.Network == nil {
		completion.Err = fmt.Errorf("no committed state for peer %s", action.PeerID)
		completion.Unreachable = true
		return completion
	}
	addr := ResolveGossipObjectPullAddress(input, action.PeerID, now)
	if addr == "" {
		completion.Err = fmt.Errorf("no TCP address for peer %s", action.PeerID)
		completion.Unreachable = true
		return completion
	}
	completion.Addr = addr
	release, err := executor.acquirePeer(action.PeerID)
	if err != nil {
		completion.Err = err
		return completion
	}
	defer release()
	request := &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: action.Zone}
	requestBytes, err := gossip.EncodeObjectPullRequest(request)
	if err == nil {
		err = executor.allowQuota(action.PeerID, int64(len(requestBytes)), now)
	}
	if err != nil {
		completion.Err = err
		return completion
	}
	response, err := executor.config.Client.Exchange(ctx, addr, request)
	responseBytes := encodedObjectPullResponseSize(response)
	if err == nil {
		err = executor.allowQuota(action.PeerID, int64(responseBytes), executor.config.Now())
	}
	if err == nil && (response == nil || !response.OK) {
		message := "empty response"
		if response != nil && response.Error != "" {
			message = response.Error
		}
		err = fmt.Errorf("object pull failed: %s", message)
	}
	if err == nil && response.Snapshot == nil {
		err = errors.New("object pull returned empty snapshot")
	}
	if err == nil && response.Snapshot.Zone != action.Zone {
		err = fmt.Errorf("object pull returned zone %s for request %s", response.Snapshot.Zone, action.Zone)
	}
	completion.Err = err
	completion.Addr = addr
	completion.Bytes = responseBytes
	completion.Unreachable = isGossipObjectPullUnreachable(err)
	if err == nil {
		completion.Snapshot = response.Snapshot
	}
	return completion
}

func (executor *GossipObjectPullExecutor) acquirePeer(peerID string) (func(), error) {
	executor.peerMu.Lock()
	defer executor.peerMu.Unlock()
	if executor.peers[peerID] >= executor.config.PerPeerLimit {
		return nil, fmt.Errorf("object pull per-peer inflight limit reached for %s (%d)", peerID, executor.config.PerPeerLimit)
	}
	executor.peers[peerID]++
	return func() {
		executor.peerMu.Lock()
		defer executor.peerMu.Unlock()
		executor.peers[peerID]--
		if executor.peers[peerID] <= 0 {
			delete(executor.peers, peerID)
		}
	}, nil
}

func (executor *GossipObjectPullExecutor) allowQuota(peerID string, bytes int64, now time.Time) error {
	executor.quotaMu.Lock()
	defer executor.quotaMu.Unlock()
	return executor.quotas.Allow(peerID, bytes, 1, now)
}

func encodedObjectPullResponseSize(response *gossip.ObjectPullResponse) int {
	if response == nil {
		return 0
	}
	data, err := gossip.EncodeObjectPullResponse(response)
	if err != nil {
		return 0
	}
	return len(data)
}

func isGossipObjectPullUnreachable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
