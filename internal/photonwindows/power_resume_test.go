package photonwindows

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

type resumeLog struct {
	consoleLog
	rebound chan struct{}
}

func (l resumeLog) Write(p []byte) (int, error) {
	var record struct {
		Message string `json:"msg"`
	}
	if json.Unmarshal(p, &record) == nil && record.Message == "gossip_rebound" {
		select {
		case l.rebound <- struct{}{}:
		default:
		}
	}
	return l.consoleLog.Write(p)
}

func TestDaemonPowerResumeRebindsUnchangedAddress(t *testing.T) {
	fixture := newWindowsGossipFixture(t)
	config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"}
	logs := resumeLog{consoleLog: consoleLog{ready: make(chan string, 1)}, rebound: make(chan struct{}, 1)}
	d := NewDaemon(config, slog.New(slog.NewJSONHandler(logs, nil)))
	resumes := make(chan struct{}, 1)
	closed := make(chan struct{})
	d.watchResume = func(context.Context) (<-chan struct{}, func() error, error) {
		return resumes, func() error { close(closed); return nil }, nil
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
			t.Error("daemon stop timed out")
		}
	}()
	var address string
	select {
	case address = <-logs.ready:
	case <-time.After(5 * time.Second):
		t.Fatal("startup timed out")
	}
	resumes <- struct{}{}
	select {
	case <-logs.rebound:
	case <-time.After(2 * time.Second):
		t.Fatal("resume did not rebind")
	}
	response, err := (objectPullClient{}).Exchange(t.Context(), address, &gossip.ObjectPullRequest{Type: gossip.ObjectPullZone, Zone: "node-a.catofes."})
	if err != nil || !response.OK {
		t.Fatalf("same-address object pull after resume: %v %v", response, err)
	}
	cancel()
	select {
	case <-closed:
	case <-time.After(2 * time.Second):
		t.Fatal("observer not closed")
	}
}

func TestDaemonPowerObserverErrorsReleaseState(t *testing.T) {
	for _, startup := range []bool{true, false} {
		t.Run(map[bool]string{true: "register", false: "unregister"}[startup], func(t *testing.T) {
			fixture := newWindowsGossipFixture(t)
			config := &Config{State: StateConfig{Path: fixture.leftPath}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: fixture.rootPublic, GossipListen: "127.0.0.1:0"}
			d := NewDaemon(config, slog.Default())
			want := errors.New("power notification failure")
			d.watchResume = func(context.Context) (<-chan struct{}, func() error, error) {
				if startup {
					return nil, nil, want
				}
				return nil, func() error { return want }, nil
			}
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()
			done := make(chan error, 1)
			go func() { done <- d.Run(ctx) }()
			if !startup {
				select {
				case <-d.Started():
					cancel()
				case <-time.After(5 * time.Second):
					t.Fatal("startup timed out")
				}
			}
			select {
			case err := <-done:
				if !errors.Is(err, want) {
					t.Fatalf("lost power error: %v", err)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("shutdown timed out")
			}
			state := fixture.openState(t, fixture.leftPath, "node-a.catofes.")
			state.Close()
		})
	}
}
