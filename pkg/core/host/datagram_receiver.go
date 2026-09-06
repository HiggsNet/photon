package host

import (
	"context"
	"errors"
	"net"
	"sync"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

var (
	ErrDatagramReceiverRequired = errors.New("gossip datagram receiver is required")
	ErrDatagramReceiverStarted  = errors.New("gossip datagram receiver is already started")
	ErrGossipTransportRequired  = errors.New("gossip transport is required")
)

// BindGossipTransport installs the common UDP transport used by GossipDriver for
// send, reply routing and its rebuildable peer address book. Composition may
// replace it before the receive loop starts, for example after config reload.
func (driver *GossipDriver) BindGossipTransport(transport *gossip.Transport) error {
	if driver == nil {
		return ErrGossipDriverStopped
	}
	if transport == nil {
		return ErrGossipTransportRequired
	}
	driver.mu.Lock()
	defer driver.mu.Unlock()
	if driver.stopped {
		return ErrGossipDriverStopped
	}
	if driver.datagramReceiver != nil && driver.gossipTransport != transport {
		return ErrDatagramReceiverStarted
	}
	driver.gossipTransport = transport
	return nil
}

// StartGossipTransport binds the concrete common transport and starts its
// single driver-owned receive loop.
func (driver *GossipDriver) StartGossipTransport(ctx context.Context, transport *gossip.Transport, onError func(error)) error {
	if err := driver.BindGossipTransport(transport); err != nil {
		return err
	}
	return driver.startGossipDatagramReceiver(ctx, transport, onError)
}

func (driver *GossipDriver) gossipTransportForRead() *gossip.Transport {
	if driver == nil {
		return nil
	}
	driver.mu.RLock()
	defer driver.mu.RUnlock()
	return driver.gossipTransport
}

// Transport returns the common gossip transport owned by GossipDriver. Callers may
// inspect or update its address book, but must not keep a second transport
// pointer as an independent source of truth.
func (driver *GossipDriver) Transport() *gossip.Transport {
	return driver.gossipTransportForRead()
}

// datagramReceiver is the receive/close capability owned by GossipDriver.
// Protocol decoding and peer validation may still live in the adapter; the
// common driver owns the single blocking receive goroutine, event-queue
// backpressure and shutdown ordering.
type datagramReceiver interface {
	Receive() (*gossip.Packet, error)
	Close() error
}

// startGossipDatagramReceiver starts the driver-owned, bounded receive loop.
// GossipDriver.Stop cancels the loop, closes the injected receiver to unblock a
// blocking Receive call, and waits for the receive goroutine to exit.
func (driver *GossipDriver) startGossipDatagramReceiver(
	ctx context.Context,
	receiver datagramReceiver,
	onError func(error),
) error {
	if driver == nil {
		return ErrGossipDriverStopped
	}
	if receiver == nil {
		return ErrDatagramReceiverRequired
	}
	if ctx == nil {
		ctx = context.Background()
	}
	receiveCtx, cancel := context.WithCancel(ctx)
	driver.mu.Lock()
	if driver.stopped {
		driver.mu.Unlock()
		cancel()
		return ErrGossipDriverStopped
	}
	if driver.datagramReceiver != nil {
		driver.mu.Unlock()
		cancel()
		return ErrDatagramReceiverStarted
	}
	driver.datagramReceiver = receiver
	driver.datagramCancel = cancel
	driver.datagramWG.Add(1)
	driver.mu.Unlock()

	go driver.runGossipDatagramReceiver(receiveCtx, receiver, onError)
	return nil
}

func (driver *GossipDriver) runGossipDatagramReceiver(
	ctx context.Context,
	receiver datagramReceiver,
	onError func(error),
) {
	defer driver.datagramWG.Done()
	var closeOnce sync.Once
	closeReceiver := func() { closeOnce.Do(func() { _ = receiver.Close() }) }
	stopClose := context.AfterFunc(ctx, closeReceiver)
	defer stopClose()
	defer closeReceiver()

	for {
		packet, err := receiver.Receive()
		if err != nil {
			if isRoutineDatagramReceiveError(err) {
				select {
				case <-ctx.Done():
					return
				default:
					continue
				}
			}
			if onError != nil {
				onError(err)
			}
			select {
			case <-ctx.Done():
				return
			default:
				continue
			}
		}
		select {
		case driver.events <- GossipPacketReceived{Packet: packet}:
		case <-ctx.Done():
			return
		}
	}
}

func isRoutineDatagramReceiveError(err error) bool {
	if errors.Is(err, net.ErrClosed) {
		return true
	}
	var netErr net.Error
	return errors.As(err, &netErr) && netErr.Timeout()
}
