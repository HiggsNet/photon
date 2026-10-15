package main

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func desktopRuntimeFixture(t *testing.T) (*desktopBackend, *photonwindows.Config) {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	text := desktopTestConfig(filepath.Join(dir, "state.db"))
	text = strings.Replace(text, "  allowed_zones: [gateway.]", "  allowed_zones: [gateway.]\n  bootstrap_hints:\n    - peer: gateway.\n      address: 127.0.0.1:1", 1)
	text += "gossip_listen: '127.0.0.1:0'\n"
	if err := os.WriteFile(path, []byte(text), 0600); err != nil {
		t.Fatal(err)
	}
	b, err := newDesktopBackend(desktopOptions{ConfigPath: path})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := b.Close(); err != nil {
			t.Errorf("desktop cleanup: %v", err)
		}
	})
	config, err := desktopParseConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	return b, config
}

func assertDesktopRuntime(t *testing.T, b *desktopBackend, state string) desktopSnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	got := b.Snapshot(ctx)
	if got.RuntimeState != state {
		t.Fatalf("runtime state: %+v, want %s", got, state)
	}
	if state == "running" && runtime.GOOS == "windows" {
		if got.Error != "" || got.Observation == nil || !got.Observation.Running || !got.Observation.Admission.Pending || got.Observation.TunnelReady || got.Observation.Wintun.Configured {
			t.Fatalf("owned pending runtime: %+v", got)
		}
	}
	if state != "running" && got.Observation != nil {
		t.Fatalf("inactive runtime retained observation: %+v", got)
	}
	return got
}

func assertDesktopStateReleased(t *testing.T, config *photonwindows.Config) {
	t.Helper()
	state, err := photonwindows.OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, 100*time.Millisecond)
	if err != nil {
		t.Fatalf("desktop did not release state: %v", err)
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestDesktopRuntimeKeepsRunningConfigUntilRestartAndJoinsStop(t *testing.T) {
	b, first := desktopRuntimeFixture(t)
	assertDesktopRuntime(t, b, "stopped")
	if err := b.Runtime("start"); err != nil {
		t.Fatal(err)
	}
	run := b.run
	assertDesktopRuntime(t, b, "running")
	if state, err := photonwindows.OpenState(first.State.Path, first.ManagedZone, first.TrustedRootPublicKey, 20*time.Millisecond); err == nil {
		state.Close()
		t.Fatal("running daemon did not own the exclusive database lock")
	}
	text, err := b.LoadConfigText()
	if err != nil {
		t.Fatal(err)
	}
	secondPath := filepath.Join(filepath.Dir(first.State.Path), "second.db")
	text = strings.ReplaceAll(text, first.State.Path, secondPath)
	if err := b.SaveConfigText(text); err != nil {
		t.Fatal(err)
	}
	if err := b.Runtime("start"); err != nil || b.run != run || b.run.statePath != first.State.Path {
		t.Fatalf("start/save replaced an owned runtime: %v", err)
	}
	if _, err := os.Stat(secondPath); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("saving configuration created a second identity")
	}
	if err := b.Runtime("restart"); err != nil {
		t.Fatal(err)
	}
	if b.run == run || b.run.statePath != secondPath {
		t.Fatal("restart did not apply saved state path")
	}
	select {
	case <-run.done:
	default:
		t.Fatal("restart returned before joining old runtime")
	}
	assertDesktopStateReleased(t, first)
	assertDesktopRuntime(t, b, "running")
	second, err := desktopParseConfig(text)
	if err != nil {
		t.Fatal(err)
	}
	if err := b.Runtime("stop"); err != nil {
		t.Fatal(err)
	}
	assertDesktopRuntime(t, b, "stopped")
	assertDesktopStateReleased(t, second)
	if err := b.Runtime("start"); err != nil {
		t.Fatalf("start after stop: %v", err)
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	assertDesktopStateReleased(t, second)
	if err := b.Close(); err != nil {
		t.Fatalf("repeated Close: %v", err)
	}
	if err := b.Runtime("start"); err == nil {
		t.Fatal("final Close allowed a new runtime")
	}
}

func TestDesktopRuntimeStartupFailureRemainsVisibleAndCanRetry(t *testing.T) {
	b, config := desktopRuntimeFixture(t)
	broken := []byte("not a Bolt database")
	if err := os.WriteFile(config.State.Path, broken, 0600); err != nil {
		t.Fatal(err)
	}
	startErr := b.Runtime("start")
	if startErr == nil {
		t.Fatal("corrupt database started")
	}
	snapshot := assertDesktopRuntime(t, b, "failed")
	if !strings.Contains(snapshot.Error, startErr.Error()) {
		t.Fatalf("startup error was lost: %+v, %v", snapshot, startErr)
	}
	if data, err := os.ReadFile(config.State.Path); err != nil || string(data) != string(broken) {
		t.Fatal("failed startup changed the corrupt database")
	}
	if err := b.Runtime("stop"); err != nil {
		t.Fatalf("historical failure blocked stop: %v", err)
	}
	if err := os.Remove(config.State.Path); err != nil {
		t.Fatal(err)
	}
	if err := b.Runtime("start"); err != nil {
		t.Fatalf("retry after repair: %v", err)
	}
	assertDesktopRuntime(t, b, "running")
}

func TestDesktopRuntimeFailedReadDoesNotBlockCloseOrAcceptSCMActions(t *testing.T) {
	b, _ := desktopRuntimeFixture(t)
	if err := os.Remove(b.options.ConfigPath); err != nil {
		t.Fatal(err)
	}
	if err := b.Runtime("start"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("missing config startup: %v", err)
	}
	assertDesktopRuntime(t, b, "failed")
	if err := b.Runtime("install"); err == nil {
		t.Fatal("desktop retained an SCM action")
	}
	if err := b.Close(); err != nil {
		t.Fatalf("failed start trapped desktop during exit: %v", err)
	}
}

func TestDesktopRuntimeConcurrentCloseAndSnapshotsJoinOnce(t *testing.T) {
	b, config := desktopRuntimeFixture(t)
	if err := b.Runtime("start"); err != nil {
		t.Fatal(err)
	}
	var workers sync.WaitGroup
	for i := 0; i < 4; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			for i := 0; i < 3; i++ {
				b.Snapshot(context.Background())
			}
		}()
	}
	for i := 0; i < 2; i++ {
		workers.Add(1)
		go func() {
			defer workers.Done()
			if err := b.Close(); err != nil {
				t.Errorf("concurrent Close: %v", err)
			}
		}()
	}
	workers.Wait()
	assertDesktopRuntime(t, b, "stopped")
	assertDesktopStateReleased(t, config)
}
