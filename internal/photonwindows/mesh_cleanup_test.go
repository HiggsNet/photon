package photonwindows

import (
	"context"
	"errors"
	"net/netip"
	"sync"
	"testing"
	"time"
)

type slowCleanupDevice struct {
	*runtimePacketDevice
	entered chan struct{}
	release chan struct{}
	err     error
	once    sync.Once
}

func (d *slowCleanupDevice) Close() error {
	d.once.Do(func() {
		close(d.entered)
		<-d.release
		_ = d.runtimePacketDevice.Close()
	})
	return d.err
}

func TestMeshSlowDeviceCleanupDoesNotBlockHealthyPeer(t *testing.T) {
	m, f := meshRouteFixture(t)
	p := m.ordered()[0]
	want := errors.New("platform cleanup failed")
	device := &slowCleanupDevice{runtimePacketDevice: newRuntimeDevice(), entered: make(chan struct{}), release: make(chan struct{}), err: want}
	var release sync.Once
	t.Cleanup(func() { release.Do(func() { close(device.release) }) })
	m.device.factory = func(context.Context, string, []netip.Prefix, []netip.Prefix, uint32, uint32) (ownedPacketDevice, error) {
		return device, nil
	}
	lease, err := m.device.acquire(t.Context(), "mesh", nil, nil, 1400, 100)
	if err != nil {
		t.Fatal(err)
	}
	p.leaf.device = lease
	p.leaf.pipeline.device = lease
	stopped := make(chan struct{})
	go func() {
		m.stateMu.Lock()
		m.stopPeer(p, "test revocation")
		m.stateMu.Unlock()
		close(stopped)
	}()
	select {
	case <-stopped:
	case <-time.After(time.Second):
		t.Fatal("revocation waited for platform cleanup under stateMu")
	}
	<-device.entered
	if p.leaf.pipeline != nil || p.tunnel.data.active != nil {
		t.Fatal("revoked peer remained usable during cleanup")
	}
	// Another peer still has an authorized route while the platform close is
	// deliberately stalled. Its packet turn must be able to acquire stateMu.
	packet := dataplanePacket(true)
	copy(packet[12:16], []byte{10, 9, 0, 1})
	copy(packet[16:20], []byte{10, 2, 1, 1})
	m.stateMu.Lock()
	choice := m.selectRoute(packet, f.view, f.now)
	m.stateMu.Unlock()
	if choice.peer == nil || choice.peer == p {
		t.Fatal("revoking one peer disabled the healthy peer")
	}
	done := make(chan error, 1)
	go func() { done <- m.close() }()
	select {
	case err := <-done:
		t.Fatalf("shutdown returned before platform cleanup: %v", err)
	default:
	}
	release.Do(func() { close(device.release) })
	select {
	case err := <-done:
		if !errors.Is(err, want) {
			t.Fatalf("shutdown lost cleanup error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown did not join platform cleanup")
	}
}

func TestMeshRemovedPeerOpenJoinsBeforeFinalCompletionDrain(t *testing.T) {
	m, _ := meshRouteFixture(t)
	p := m.ordered()[0]
	ctx, cancel := context.WithCancel(t.Context())
	p.leaf.cancelOpen = cancel
	p.leaf.pending = true
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	late := newRuntimeDevice()
	p.leaf.openWG.Go(func() {
		<-ctx.Done()
		<-release
		// A completion send can win its select against concurrent cancellation.
		m.opened <- leafOpenResult{owner: p.leaf, device: late}
	})
	removed := make(chan struct{})
	go func() {
		m.stateMu.Lock()
		m.update(GatewayPlan{})
		m.stateMu.Unlock()
		close(removed)
	}()
	select {
	case <-removed:
	case <-time.After(time.Second):
		t.Fatal("peer removal waited for a platform opener under stateMu")
	}
	if ctx.Err() == nil || len(m.peers) != 0 {
		t.Fatal("removed peer retained its open request or live state")
	}
	done := make(chan error, 1)
	go func() { done <- m.close() }()
	once.Do(func() { close(release) })
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("shutdown failed to join removed peer's opener")
	}
	select {
	case <-late.closed:
	default:
		t.Fatal("completion arriving during shutdown leaked its device")
	}
}
