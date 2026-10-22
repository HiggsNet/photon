package host

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
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
	addrMu  sync.Mutex
	addrs   map[objectPullAddress]objectPullAddressHealth
}

type objectPullAddress struct{ peer, address string }
type objectPullAddressHealth struct{ success, failure time.Time }

const (
	objectPullAddressTTL     = 2 * time.Minute
	objectPullAddressBackoff = 30 * time.Second
)

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
		addrs:  make(map[objectPullAddress]objectPullAddressHealth),
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
	addresses := executor.orderAddresses(action.PeerID, ResolveGossipObjectPullAddresses(input, action.PeerID, now), now)
	if len(addresses) == 0 {
		completion.Err = fmt.Errorf("no TCP address for peer %s", action.PeerID)
		completion.Unreachable = true
		return completion
	}
	release, err := executor.acquirePeer(action.PeerID)
	if err != nil {
		completion.Err = err
		return completion
	}
	defer release()
	if ctx == nil {
		ctx = context.Background()
	}
	// All candidates share one budget. Reserve time for the remaining ones so
	// a blackholed first address cannot consume the entire fallback window.
	ctx, cancel := context.WithTimeout(ctx, gossip.ObjectPullBudget)
	defer cancel()
	request := &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: action.Zone}
	requestBytes, err := gossip.EncodeObjectPullRequest(request)
	if err != nil {
		completion.Err = err
		return completion
	}
	for i, addr := range addresses {
		if err := ctx.Err(); err != nil {
			completion.Err = err
			break
		}
		if err := executor.allowQuota(action.PeerID, int64(len(requestBytes)), executor.config.Now()); err != nil {
			completion.Err = err
			break
		}
		completion.Addr = addr
		deadline, _ := ctx.Deadline()
		attempt, stop := context.WithTimeout(ctx, time.Until(deadline)/time.Duration(len(addresses)-i))
		response, err := executor.config.Client.Exchange(attempt, addr, request)
		stop()
		responseBytes := encodedObjectPullResponseSize(response)
		completion.Bytes += responseBytes
		if err != nil {
			completion.Err = err
			if ctx.Err() != nil {
				completion.Err = ctx.Err()
				break
			}
			if !isGossipObjectPullUnreachable(err) {
				break
			}
			executor.recordAddress(action.PeerID, addr, false)
			continue
		}
		// A completed exchange establishes TCP reachability. Semantic and quota
		// failures do not justify replaying the request at another address.
		executor.recordAddress(action.PeerID, addr, true)
		err = executor.allowQuota(action.PeerID, int64(responseBytes), executor.config.Now())
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
		if err == nil {
			completion.Snapshot = response.Snapshot
		}
		break
	}
	completion.Unreachable = isGossipObjectPullUnreachable(completion.Err)
	return completion
}

// TCP quality is kept independently of UDP and expires with idle addresses.
func (executor *GossipObjectPullExecutor) orderAddresses(peer string, addresses []string, now time.Time) []string {
	executor.addrMu.Lock()
	defer executor.addrMu.Unlock()
	for key, health := range executor.addrs {
		if now.Sub(health.success) >= objectPullAddressTTL && now.Sub(health.failure) >= objectPullAddressTTL {
			delete(executor.addrs, key)
		}
	}
	rank := func(addr string) int {
		health := executor.addrs[objectPullAddress{peer, addr}]
		if !health.failure.IsZero() && now.Sub(health.failure) < objectPullAddressBackoff {
			return 2
		}
		if !health.success.IsZero() && now.Sub(health.success) < objectPullAddressTTL {
			return 0
		}
		return 1
	}
	sort.SliceStable(addresses, func(i, j int) bool { return rank(addresses[i]) < rank(addresses[j]) })
	return addresses
}

func (executor *GossipObjectPullExecutor) recordAddress(peer, address string, success bool) {
	executor.addrMu.Lock()
	defer executor.addrMu.Unlock()
	key := objectPullAddress{peer, address}
	health := executor.addrs[key]
	if success {
		health.success = executor.config.Now()
		health.failure = time.Time{}
	} else {
		health.failure = executor.config.Now()
		health.success = time.Time{}
	}
	executor.addrs[key] = health
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
