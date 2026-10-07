package photonwindows

import (
	"context"
	"runtime"
	"sync"
	"sync/atomic"
	"unsafe"

	"golang.org/x/sys/windows"
)

const (
	deviceNotifyCallback  = 2
	pbtAPMResumeAutomatic = 18
)

// DEVICE_NOTIFY_SUBSCRIBE_PARAMETERS contains two pointer-sized fields. Context
// is an opaque integer token, never a pointer into Go memory.
type powerSubscribeParameters struct{ callback, token uintptr }
type powerSubscription struct {
	ctx        context.Context
	changes    chan struct{}
	closed     atomic.Bool
	parameters powerSubscribeParameters
	pin        runtime.Pinner
}

var powerSubscriptions sync.Map // uintptr -> *powerSubscription
// Monotonically allocated tokens are not reused during an amd64 process lifetime.
// A late callback can therefore never target a later daemon subscription.
var powerSubscriptionID atomic.Uint64
var powerCallback = windows.NewCallback(func(token uintptr, kind uint32, _ uintptr) uintptr {
	if value, ok := powerSubscriptions.Load(token); ok {
		s := value.(*powerSubscription)
		// Automatic resume also covers unattended wake. The subsequent interactive
		// RESUMESUSPEND notification must not tear down the newly established tunnel.
		if kind == pbtAPMResumeAutomatic && !s.closed.Load() && s.ctx.Err() == nil {
			select {
			case s.changes <- struct{}{}:
			default:
			}
		}
	}
	return 0
})
var powerDLL = windows.NewLazySystemDLL("powrprof.dll")
var registerPowerResume = powerDLL.NewProc("PowerRegisterSuspendResumeNotification")
var unregisterPowerResume = powerDLL.NewProc("PowerUnregisterSuspendResumeNotification")

func watchPowerResume(ctx context.Context) (<-chan struct{}, func() error, error) {
	return subscribePowerResume(ctx, func(p *powerSubscribeParameters, handle *windows.Handle) error {
		if err := registerPowerResume.Find(); err != nil {
			return err
		}
		result, _, _ := registerPowerResume.Call(deviceNotifyCallback, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(handle)))
		if result != 0 {
			return windows.Errno(result)
		}
		return nil
	}, func(handle windows.Handle) error {
		if err := unregisterPowerResume.Find(); err != nil {
			return err
		}
		result, _, _ := unregisterPowerResume.Call(uintptr(handle))
		if result != 0 {
			return windows.Errno(result)
		}
		return nil
	})
}

func subscribePowerResume(ctx context.Context, register func(*powerSubscribeParameters, *windows.Handle) error, unregister func(windows.Handle) error) (<-chan struct{}, func() error, error) {
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	token := uintptr(powerSubscriptionID.Add(1))
	s := &powerSubscription{ctx: ctx, changes: make(chan struct{}, 1), parameters: powerSubscribeParameters{callback: powerCallback, token: token}}
	s.pin.Pin(&s.parameters)
	powerSubscriptions.Store(token, s)
	var handle windows.Handle
	if err := register(&s.parameters, &handle); err != nil {
		s.closed.Store(true)
		powerSubscriptions.Delete(token)
		s.pin.Unpin()
		return nil, nil, err
	}
	var once sync.Once
	var closeErr error
	closeSubscription := func() error {
		once.Do(func() {
			s.closed.Store(true)
			closeErr = unregister(handle)
			if closeErr == nil {
				powerSubscriptions.Delete(token)
				s.pin.Unpin()
			}
			// Failed unregister retains the pinned registration and inert callback
			// context. Never free memory still potentially owned by Windows. The
			// channel stays open so already dispatched callbacks cannot panic.
		})
		return closeErr
	}
	return s.changes, closeSubscription, nil
}
