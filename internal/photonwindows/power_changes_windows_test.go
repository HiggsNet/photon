package photonwindows

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"golang.org/x/sys/windows"
)

func TestWindowsPowerResumeSubscription(t *testing.T) {
	for _, failClose := range []bool{false, true} {
		t.Run(map[bool]string{false: "close", true: "failed_close"}[failClose], func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			var params powerSubscribeParameters
			calls := 0
			changes, closeSubscription, err := subscribePowerResume(ctx, func(p *powerSubscribeParameters, h *windows.Handle) error { params = *p; *h = 123; return nil }, func(h windows.Handle) error {
				calls++
				if h != 123 {
					t.Fatal(h)
				}
				if failClose {
					return windows.ERROR_ACCESS_DENIED
				}
				return nil
			})
			if err != nil {
				t.Fatal(err)
			}
			emit := func(kind uintptr) { syscall.SyscallN(params.callback, params.token, kind, 0) }
			emit(4)
			emit(7)
			select {
			case <-changes:
				t.Fatal("non automatic resume delivered")
			default:
			}
			emit(18)
			emit(18)
			select {
			case <-changes:
			default:
				t.Fatal("resume missing")
			}
			select {
			case <-changes:
				t.Fatal("burst not coalesced")
			default:
			}
			cancel()
			emit(18)
			select {
			case <-changes:
				t.Fatal("callback after cancellation")
			default:
			}
			err = closeSubscription()
			if failClose != errors.Is(err, windows.ERROR_ACCESS_DENIED) {
				t.Fatalf("close error %v", err)
			}
			_ = closeSubscription()
			if calls != 1 {
				t.Fatalf("unregister called %d times", calls)
			}
			emit(18)
			select {
			case <-changes:
				t.Fatal("callback after close")
			default:
			}
			value, retained := powerSubscriptions.Load(params.token)
			if retained != failClose {
				t.Fatalf("registration retention %v", retained)
			}
			if retained { // Fake API owns nothing; reclaim the intentional failure retention.
				powerSubscriptions.Delete(params.token)
				value.(*powerSubscription).pin.Unpin()
			}
		})
	}
}

func TestWindowsPowerResumeRegistrationFailure(t *testing.T) {
	var token uintptr
	_, closeSubscription, err := subscribePowerResume(t.Context(), func(p *powerSubscribeParameters, _ *windows.Handle) error {
		token = p.token
		return windows.ERROR_ACCESS_DENIED
	}, func(windows.Handle) error { t.Fatal("unregister on unsuccessful registration"); return nil })
	if !errors.Is(err, windows.ERROR_ACCESS_DENIED) || closeSubscription != nil {
		t.Fatalf("registration failure: %v", err)
	}
	if _, ok := powerSubscriptions.Load(token); ok {
		t.Fatal("failed registration retained")
	}
}

func TestWindowsPowerResumeNativeRegistration(t *testing.T) {
	changes, closeSubscription, err := watchPowerResume(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if changes == nil {
		t.Fatal("nil subscription")
	}
	if err := closeSubscription(); err != nil {
		t.Fatal(err)
	}
	// This exercises the real register/unregister API, not physical sleep.
}

// The subscription is native, but delivery is synthetic: this is not a system
// sleep test and does not alter the host's power state or network configuration.
func TestWindowsPowerResumeCallbackRebindsDaemon(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"}
	logs := resumeLog{consoleLog: consoleLog{ready: make(chan string, 1)}, rebound: make(chan struct{}, 1)}
	d := NewDaemon(config, slog.New(slog.NewJSONHandler(logs, nil)))
	var token uintptr
	d.watchResume = func(ctx context.Context) (<-chan struct{}, func() error, error) {
		changes, stop, err := watchPowerResume(ctx)
		if err == nil {
			powerSubscriptions.Range(func(key, value any) bool {
				if value.(*powerSubscription).ctx == ctx {
					token = key.(uintptr)
					return false
				}
				return true
			})
		}
		return changes, stop, err
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- d.Run(ctx) }()
	defer func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("stop timeout")
		}
		if _, ok := powerSubscriptions.Load(token); ok {
			t.Error("native subscription survived daemon stop")
		}
	}()
	var address string
	select {
	case address = <-logs.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("startup timeout")
	}
	if token == 0 {
		t.Fatal("native registration absent")
	}
	syscall.SyscallN(powerCallback, token, pbtAPMResumeAutomatic, 0)
	select {
	case <-logs.rebound:
	case <-time.After(2 * time.Second):
		t.Fatal("native callback did not rebind")
	}
	response, err := (objectPullClient{}).Exchange(t.Context(), address, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a.catofes."})
	if err != nil || !response.OK {
		t.Fatalf("same-address object pull: %v %v", response, err)
	}
}

func TestWindowsPowerResumeConcurrentClose(t *testing.T) {
	var params powerSubscribeParameters
	entered, release := make(chan struct{}), make(chan struct{})
	changes, stop, err := subscribePowerResume(t.Context(), func(p *powerSubscribeParameters, h *windows.Handle) error { params = *p; *h = 123; return nil }, func(windows.Handle) error { close(entered); <-release; return nil })
	if err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for range 4 {
		workers.Go(func() {
			for range 100 {
				syscall.SyscallN(params.callback, params.token, pbtAPMResumeAutomatic, 0)
			}
		})
	}
	stopped := make(chan error, 1)
	go func() { stopped <- stop() }()
	<-entered // closed is set before the native unregister starts.
	workers.Wait()
	select {
	case <-changes:
	default:
	} // A pre-close event is allowed to be queued.
	for range 100 {
		syscall.SyscallN(params.callback, params.token, pbtAPMResumeAutomatic, 0)
	}
	select {
	case <-changes:
		t.Fatal("callback delivered while unregistering")
	default:
	}
	close(release)
	if err := <-stopped; err != nil {
		t.Fatal(err)
	}
	syscall.SyscallN(params.callback, params.token, pbtAPMResumeAutomatic, 0)
	if _, ok := powerSubscriptions.Load(params.token); ok {
		t.Fatal("subscription retained")
	}
}
