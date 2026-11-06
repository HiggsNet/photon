package photonwindows

import (
	"context"
	"errors"
	"net/netip"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows retains the callback context until cancellation completes. Pin a
// pointer-free token, and keep Go channels on the Go side of the boundary.
type networkSubscription struct {
	changes chan struct{}
	raw     chan struct{}
	initial atomic.Bool
	pin     runtime.Pinner
}

var networkSubscriptions sync.Map // *byte -> *networkSubscription
var networkChangeCallback = windows.NewCallback(func(token *byte, _ uintptr, kind uint32) uintptr {
	if value, ok := networkSubscriptions.Load(token); ok {
		subscription := value.(*networkSubscription)
		if kind == 3 {
			subscription.initial.Store(true)
		} // MibInitialNotification
		select {
		case subscription.raw <- struct{}{}:
		default:
		}
	}
	return 0
})

func watchNetworkChanges(ctx context.Context) (<-chan struct{}, func() error, error) {
	return watchNetworkSnapshot(ctx, underlaySnapshot, func(previous, current [32]byte) bool {
		return previous != current
	})
}

func watchNetworkChangesForTargets(ctx context.Context, targets func() []netip.Addr) (<-chan struct{}, func() error, error) {
	type snapshot struct {
		underlay [32]byte
		paths    map[netip.Addr]string
	}
	return watchNetworkSnapshot(ctx, func() (snapshot, error) {
		addresses := targets()
		if len(addresses) == 0 {
			value, err := underlaySnapshot()
			return snapshot{underlay: value}, err
		}
		value, err := outboundRouteSnapshot(addresses)
		return snapshot{paths: value}, err
	}, func(previous, current snapshot) bool {
		if previous.paths == nil && current.paths == nil {
			return previous.underlay != current.underlay
		}
		return outboundPathsChanged(previous.paths, current.paths)
	})
}

func watchNetworkSnapshot[T any](ctx context.Context, snapshot func() (T, error), pathChanged func(T, T) bool) (<-chan struct{}, func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	changes := make(chan struct{}, 1)
	previous, err := snapshot()
	if err != nil {
		return nil, nil, err
	}
	observerCtx, stopObserver := context.WithCancel(ctx)
	done := make(chan struct{})
	started := false
	token := new(byte)
	subscription := &networkSubscription{changes: changes, raw: make(chan struct{}, 1)}
	subscription.pin.Pin(token)
	networkSubscriptions.Store(token, subscription)
	var handles []windows.Handle
	var once sync.Once
	var closeErr error
	closeSubscription := func() error {
		once.Do(func() {
			stopObserver()
			// Cancel waits for callbacks. Never call it from a callback or while
			// holding a resource a callback needs (Microsoft's API contract).
			for _, handle := range handles {
				closeErr = errors.Join(closeErr, windows.CancelMibChangeNotify2(handle))
			}
			if closeErr == nil {
				networkSubscriptions.Delete(token)
				subscription.pin.Unpin()
			}
			if started {
				<-done
			}
		})
		return closeErr
	}
	for _, register := range []func(uint16, uintptr, unsafe.Pointer, bool, *windows.Handle) error{
		windows.NotifyIpInterfaceChange, windows.NotifyUnicastIpAddressChange, windows.NotifyRouteChange2,
	} {
		var handle windows.Handle
		if err := register(windows.AF_UNSPEC, networkChangeCallback, unsafe.Pointer(token), false, &handle); err != nil {
			return nil, nil, errors.Join(err, closeSubscription())
		}
		handles = append(handles, handle)
	}
	started = true
	go func() {
		defer close(done)
		for {
			select {
			case <-observerCtx.Done():
				return
			case <-subscription.raw:
			}
			// Route installation can publish an incomplete path before the rest
			// of the same update reaches IP Helper.
			timer := time.NewTimer(250 * time.Millisecond)
			select {
			case <-observerCtx.Done():
				timer.Stop()
				return
			case <-timer.C:
			}
			select {
			case <-subscription.raw:
			default:
			}
			changed := subscription.initial.Swap(false)
			if current, err := snapshot(); err == nil {
				changed = changed || pathChanged(previous, current)
				previous = current
			}
			if changed {
				select {
				case changes <- struct{}{}:
				default:
				}
			}
		}
	}()
	// Recheck after registration so changes in the startup gap are not lost.
	select {
	case subscription.raw <- struct{}{}:
	default:
	}
	return changes, closeSubscription, nil
}
