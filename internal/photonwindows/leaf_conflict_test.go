package photonwindows

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"
)

func TestLeafRuntimeConflictRequiresCurrentAuthorization(t *testing.T) {
	for _, stale := range []string{"current", "request", "revision", "generation", "attachment", "authorization"} {
		t.Run(stale, func(t *testing.T) {
			f := runtimeFixture(t)
			partial := newRuntimeDevice()
			runtime := newLeafRuntime(func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
				return partial, errPacketDeviceConflict
			})
			t.Cleanup(func() {
				if err := runtime.close(); err != nil {
					t.Error(err)
				}
			})
			if err := runtime.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now); err != nil {
				t.Fatal(err)
			}
			result := runtimeOpenResult(t, runtime)
			switch stale {
			case "request":
				if err := runtime.stop(); err != nil {
					t.Fatal(err)
				}
			case "revision":
				f.view.Revision++
			case "generation":
				f.p.tunnel.generation++
			case "attachment":
				result.want.local = netip.MustParseAddr("fe80::dead")
			case "authorization":
				f.p.tunnel.phase = 0
			}
			err := runtime.complete(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now, result)
			if fatal := errors.Is(err, errPacketDeviceConflict); fatal != (stale == "current") {
				t.Fatalf("fatal=%v error=%v", fatal, err)
			}
			select {
			case <-partial.closed:
			default:
				t.Fatal("partial or stale adapter leaked")
			}
			if runtime.pending || runtime.device != nil || runtime.pipeline != nil {
				t.Fatal("failed adapter attached or left pending")
			}
		})
	}
}

func TestLeafRuntimeTransientFailureRetriesAfterBackoff(t *testing.T) {
	f := runtimeFixture(t)
	transient := errors.New("temporary platform failure")
	first, next := newRuntimeDevice(), newRuntimeDevice()
	var calls atomic.Int32
	runtime := newLeafRuntime(func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
		if calls.Add(1) == 1 {
			return first, transient
		}
		return next, nil
	})
	t.Cleanup(func() {
		if err := runtime.close(); err != nil {
			t.Error(err)
		}
	})
	reconcile := func(now time.Time) {
		t.Helper()
		if err := runtime.reconcile(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, now); err != nil {
			t.Fatal(err)
		}
	}
	reconcile(f.now)
	result := runtimeOpenResult(t, runtime)
	err := runtime.complete(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, f.now, result)
	if !errors.Is(err, transient) || errors.Is(err, errPacketDeviceConflict) {
		t.Fatalf("transient classified fatal: %v", err)
	}
	select {
	case <-first.closed:
	default:
		t.Fatal("partial adapter not cleaned")
	}
	reconcile(f.now.Add(time.Second))
	if calls.Load() != 1 || runtime.pending {
		t.Fatal("ignored retry backoff")
	}
	later := f.now.Add(6 * time.Second)
	reconcile(later)
	result = runtimeOpenResult(t, runtime)
	if err := runtime.complete(t.Context(), f.config, f.view, f.plan, f.p.tunnel, f.p.routerID, later, result); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 || runtime.device != next || runtime.pipeline == nil {
		t.Fatal("transient failure did not recover")
	}
	if err := runtime.close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-next.closed:
	default:
		t.Fatal("replacement adapter not closed")
	}
}
