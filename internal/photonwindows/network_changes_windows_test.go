package photonwindows

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"
	"unsafe"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"golang.org/x/sys/windows"
)

func TestWindowsNetworkNotificationsAndCleanup(t *testing.T) {
	changes, close, err := watchNetworkChanges(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := close(); err != nil {
			t.Error(err)
		}
	})
	var token *byte
	networkSubscriptions.Range(func(key, value any) bool {
		if (<-chan struct{})(value.(*networkSubscription).changes) == changes {
			token = key.(*byte)
			return false
		}
		return true
	})
	if token == nil {
		t.Fatal("missing callback registration")
	}
	// Request a real initial OS callback without mutating the VM network.
	var handle windows.Handle
	if err := windows.NotifyIpInterfaceChange(windows.AF_UNSPEC, networkChangeCallback, unsafe.Pointer(token), true, &handle); err != nil {
		t.Fatal(err)
	}
	select {
	case <-changes:
	case <-time.After(2 * time.Second):
		t.Error("initial IP Helper callback was not delivered")
	}
	if err := windows.CancelMibChangeNotify2(handle); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	if err := close(); err != nil {
		t.Fatal(err)
	}
	if time.Since(started) > time.Second {
		t.Error("notification cleanup exceeded one second")
	}
	if _, ok := networkSubscriptions.Load(token); ok {
		t.Fatal("callback subscription leaked")
	}
	if err := close(); err != nil {
		t.Fatal(err)
	}
}

func TestWindowsNetworkNotificationsCancelledStartup(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, close, err := watchNetworkChanges(ctx); err == nil {
		_ = close()
		t.Fatal("cancelled context accepted")
	}
}

type networkDaemonLog struct {
	ready   chan string
	rebound chan struct{}
}

func (l networkDaemonLog) Write(data []byte) (int, error) {
	var record struct {
		Message string `json:"msg"`
		Address string `json:"address"`
	}
	if json.Unmarshal(data, &record) == nil {
		switch record.Message {
		case "gossip_started":
			l.ready <- record.Address
		case "gossip_rebound":
			select {
			case l.rebound <- struct{}{}:
			default:
			}
		}
	}
	return len(data), nil
}

func TestWindowsNetworkNotificationRebindsRunningDaemon(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"}
	logs := networkDaemonLog{ready: make(chan string, 1), rebound: make(chan struct{}, 1)}
	daemon := NewDaemon(config, slog.New(slog.NewJSONHandler(logs, nil)))
	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- daemon.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(2 * time.Second):
			t.Error("daemon did not stop")
		}
	})
	var address string
	select {
	case address = <-logs.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("daemon did not start")
	}
	var token *byte
	networkSubscriptions.Range(func(key, _ any) bool { token = key.(*byte); return false })
	if token == nil {
		t.Fatal("daemon did not subscribe to Windows notifications")
	}
	var handle windows.Handle
	started := time.Now()
	if err := windows.NotifyIpInterfaceChange(windows.AF_UNSPEC, networkChangeCallback, unsafe.Pointer(token), true, &handle); err != nil {
		t.Fatal(err)
	}
	// Cancel the extra test subscription before daemon cleanup can unpin token.
	defer func() {
		if err := windows.CancelMibChangeNotify2(handle); err != nil {
			t.Error(err)
		}
	}()
	select {
	case <-logs.rebound:
		t.Logf("Windows network notification to successful rebind: %s", time.Since(started))
	case <-time.After(time.Second):
		t.Fatal("Windows callback did not trigger rebind within one second")
	}
	// Windows may deliver interface/address/route notifications in a burst.
	// A second legitimate replacement can overlap the first post-notification
	// dial, so require bounded recovery rather than gap-free TCP availability.
	readCtx, stopRead := context.WithTimeout(t.Context(), time.Second)
	defer stopRead()
	waitForWindowsState(t, time.Second, func() bool {
		response, err := (objectPullClient{}).Exchange(readCtx, address, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a.catofes."})
		return err == nil && response.OK
	})
}
