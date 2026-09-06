package photonlinux

import (
	"context"
	"net"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

const (
	DefaultGossipObjectPullDialTimeout = 1500 * time.Millisecond
	DefaultGossipObjectPullIOTimeout   = 3 * time.Second
)

// GossipObjectPullClient performs one Linux TCP exchange. GossipDriver owns
// queueing, concurrency, peer limits, quota, address policy and completion.
type GossipObjectPullClient struct {
	DialTimeout time.Duration
	IOTimeout   time.Duration
}

func (client GossipObjectPullClient) Exchange(ctx context.Context, addr string, request *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	dialTimeout := client.DialTimeout
	if dialTimeout <= 0 {
		dialTimeout = DefaultGossipObjectPullDialTimeout
	}
	ioTimeout := client.IOTimeout
	if ioTimeout <= 0 {
		ioTimeout = DefaultGossipObjectPullIOTimeout
	}
	conn, err := (&net.Dialer{Timeout: dialTimeout}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	deadline := time.Now().Add(ioTimeout)
	if contextDeadline, ok := ctx.Deadline(); ok && contextDeadline.Before(deadline) {
		deadline = contextDeadline
	}
	if err := conn.SetDeadline(deadline); err != nil {
		return nil, err
	}
	return gossip.ExchangeObjectPull(conn, request)
}
