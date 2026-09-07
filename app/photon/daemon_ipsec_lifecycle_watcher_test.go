package main

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type fakeLifecycleDriver struct {
	subscribe func(ctx context.Context) (<-chan ipsec.VICIEvent, func(), error)
}

func (f *fakeLifecycleDriver) LoadConnection(context.Context, ipsec.TransportLinkSpec) error {
	return nil
}
func (f *fakeLifecycleDriver) UnloadConnection(context.Context, string) error { return nil }
func (f *fakeLifecycleDriver) TerminateSA(context.Context, string) error      { return nil }
func (f *fakeLifecycleDriver) ListSAs(context.Context) ([]ipsec.SAState, error) {
	return nil, nil
}
func (f *fakeLifecycleDriver) LoadPrivateKey(context.Context, string, []byte, string) error {
	return nil
}
func (f *fakeLifecycleDriver) UnloadPrivateKey(context.Context, string) error { return nil }
func (f *fakeLifecycleDriver) SubscribeLifecycleEvents(ctx context.Context) (<-chan ipsec.VICIEvent, func(), error) {
	return f.subscribe(ctx)
}

// A wedged VICI daemon that accepts the connection but never answers must not
// block daemon startup: the subscribe runs in a background goroutine with a
// bounded timeout and is retried later.
func TestStartIPsecLifecycleEventWatcherDoesNotBlockStartup(t *testing.T) {
	release := make(chan struct{})
	var calls atomic.Int32
	driver := &fakeLifecycleDriver{subscribe: func(ctx context.Context) (<-chan ipsec.VICIEvent, func(), error) {
		calls.Add(1)
		select {
		case <-release:
			return nil, nil, errors.New("vici wedged")
		case <-ctx.Done():
			return nil, nil, ctx.Err()
		}
	}}
	d := &Daemon{Events: make(chan daemonEvent, 4)}
	installTestIPsecDrivers(d, driver, &ipsec.DryRunDriver{})

	start := time.Now()
	stop := d.startIPsecLifecycleEventWatcher(context.Background())
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("startIPsecLifecycleEventWatcher blocked for %s", elapsed)
	}
	// The first attempt is in flight in the background; release it and let the
	// watcher schedule a retry, then shut everything down.
	close(release)
	deadline := time.After(2 * time.Second)
	for calls.Load() == 0 {
		select {
		case <-deadline:
			t.Fatal("watcher never attempted to subscribe")
		default:
			time.Sleep(5 * time.Millisecond)
		}
	}
	stop()
}

func TestStartIPsecLifecycleEventWatcherForwardsEvents(t *testing.T) {
	stream := make(chan ipsec.VICIEvent, 1)
	stopStarted := make(chan struct{})
	releaseStop := make(chan struct{})
	driver := &fakeLifecycleDriver{subscribe: func(ctx context.Context) (<-chan ipsec.VICIEvent, func(), error) {
		return stream, func() {
			close(stopStarted)
			<-releaseStop
		}, nil
	}}
	d := &Daemon{Events: make(chan daemonEvent, 4)}
	installTestIPsecDrivers(d, driver, &ipsec.DryRunDriver{})

	ctx, cancel := context.WithCancel(context.Background())
	stop := d.startIPsecLifecycleEventWatcher(ctx)
	stream <- ipsec.VICIEvent{Name: "child-updown", Connection: "ipsec-main-ab", Up: true}
	select {
	case ev := <-d.Events:
		if ev.Type != daemonEventIPsecLifecycle || ev.VICIEvent.Connection != "ipsec-main-ab" {
			t.Fatalf("event = %+v", ev)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("lifecycle event was not forwarded to the daemon event loop")
	}

	cancel()
	stopReturned := make(chan struct{})
	go func() {
		stop()
		close(stopReturned)
	}()
	select {
	case <-stopStarted:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher stop function was not called on shutdown")
	}
	select {
	case <-stopReturned:
		t.Fatal("watcher stop returned before the subscription was closed")
	default:
	}
	close(releaseStop)
	select {
	case <-stopReturned:
	case <-time.After(2 * time.Second):
		t.Fatal("watcher did not finish after the subscription stopped")
	}
}
