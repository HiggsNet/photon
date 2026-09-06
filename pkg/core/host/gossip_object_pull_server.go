package host

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

const (
	DefaultGossipObjectPullServerConnections  = 16
	DefaultGossipObjectPullConnectionDeadline = 10 * time.Second
)

var (
	ErrGossipObjectPullListenerRequired = errors.New("gossip object-pull listener is required")
	ErrGossipObjectPullLookupRequired   = errors.New("gossip object-pull lookup is required")
	ErrGossipObjectPullServerStarted    = errors.New("gossip object-pull server is already started")
)

// StartGossipObjectPullServer transfers listener ownership to GossipDriver and
// starts its only bounded object-pull accept loop.
func (driver *GossipDriver) StartGossipObjectPullServer(
	ctx context.Context,
	listener net.Listener,
	lookup func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse,
	maxConnections int,
	connectionDeadline time.Duration,
) error {
	if driver == nil {
		return ErrGossipDriverStopped
	}
	if listener == nil {
		return ErrGossipObjectPullListenerRequired
	}
	if lookup == nil {
		return ErrGossipObjectPullLookupRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if maxConnections <= 0 {
		maxConnections = DefaultGossipObjectPullServerConnections
	}
	if connectionDeadline <= 0 {
		connectionDeadline = DefaultGossipObjectPullConnectionDeadline
	}

	serverCtx, cancel := context.WithCancel(ctx)
	driver.mu.Lock()
	if driver.stopped {
		driver.mu.Unlock()
		cancel()
		return ErrGossipDriverStopped
	}
	if driver.objectPullServerListener != nil {
		driver.mu.Unlock()
		cancel()
		return ErrGossipObjectPullServerStarted
	}
	driver.objectPullServerCancel = cancel
	driver.objectPullServerListener = listener
	driver.objectPullServerWG.Add(1)
	driver.mu.Unlock()

	go driver.runGossipObjectPullServer(serverCtx, listener, lookup, maxConnections, connectionDeadline)
	return nil
}

func (driver *GossipDriver) runGossipObjectPullServer(
	ctx context.Context,
	listener net.Listener,
	lookup func(*gossip.ObjectPullRequest) *gossip.ObjectPullResponse,
	maxConnections int,
	connectionDeadline time.Duration,
) {
	defer driver.objectPullServerWG.Done()
	var closeOnce sync.Once
	closeListener := func() { closeOnce.Do(func() { _ = listener.Close() }) }
	stopClose := context.AfterFunc(ctx, closeListener)
	defer stopClose()
	defer closeListener()

	slots := make(chan struct{}, maxConnections)
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		select {
		case slots <- struct{}{}:
		case <-ctx.Done():
			_ = conn.Close()
			return
		default:
			_ = conn.Close()
			continue
		}
		driver.objectPullServerWG.Add(1)
		go func() {
			defer driver.objectPullServerWG.Done()
			defer func() { <-slots }()
			defer conn.Close()
			stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
			defer stopClose()
			_ = conn.SetDeadline(time.Now().Add(connectionDeadline))
			_ = gossip.ServeObjectPull(conn, lookup)
		}()
	}
}
