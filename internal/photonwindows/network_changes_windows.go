package photonwindows

import (
	"context"
	"errors"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// Windows retains the callback context until cancellation completes. Pin a
// pointer-free token, and keep Go channels on the Go side of the boundary.
type networkSubscription struct {
	changes chan struct{}
	pin     runtime.Pinner
}

var networkSubscriptions sync.Map // *byte -> *networkSubscription
var networkChangeCallback = windows.NewCallback(func(token *byte, _ uintptr, _ uint32) uintptr {
	if value, ok := networkSubscriptions.Load(token); ok {
		select {
		case value.(*networkSubscription).changes <- struct{}{}:
		default:
		}
	}
	return 0
})

func watchNetworkChanges(ctx context.Context) (<-chan struct{}, func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	changes := make(chan struct{}, 1)
	token := new(byte)
	subscription := &networkSubscription{changes: changes}
	subscription.pin.Pin(token)
	networkSubscriptions.Store(token, subscription)
	var handles []windows.Handle
	var once sync.Once
	var closeErr error
	close := func() error {
		once.Do(func() {
			// Cancel waits for callbacks. Never call it from a callback or while
			// holding a resource a callback needs (Microsoft's API contract).
			for _, handle := range handles {
				closeErr = errors.Join(closeErr, windows.CancelMibChangeNotify2(handle))
			}
			if closeErr == nil {
				networkSubscriptions.Delete(token)
				subscription.pin.Unpin()
			}
		})
		return closeErr
	}
	for _, register := range []func(uint16, uintptr, unsafe.Pointer, bool, *windows.Handle) error{
		windows.NotifyIpInterfaceChange, windows.NotifyUnicastIpAddressChange, windows.NotifyRouteChange2,
	} {
		var handle windows.Handle
		if err := register(windows.AF_UNSPEC, networkChangeCallback, unsafe.Pointer(token), false, &handle); err != nil {
			return nil, nil, errors.Join(err, close())
		}
		handles = append(handles, handle)
	}
	return changes, close, nil
}
