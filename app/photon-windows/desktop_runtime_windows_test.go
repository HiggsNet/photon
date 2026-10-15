//go:build windows

package main

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
	"golang.org/x/sys/windows"
)

func TestDesktopWindowsRuntimeOwnsPipeAndRefusesCompetingRun(t *testing.T) {
	owner, config := desktopRuntimeFixture(t)
	if err := owner.Runtime("start"); err != nil {
		t.Fatal(err)
	}
	before := assertDesktopRuntime(t, owner, "running")
	request := before.Observation.Admission.JoinRequestB64
	if request == "" {
		t.Fatal("pending runtime did not expose its public join request")
	}
	// This second backend even shares our PID. Its own readiness must never
	// be inferred from the privileged pipe belonging to the first daemon.
	other, err := newDesktopBackend(desktopOptions{ConfigPath: owner.options.ConfigPath})
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := other.Runtime("start"); (!errors.Is(err, windows.ERROR_ACCESS_DENIED) && !errors.Is(err, windows.ERROR_PIPE_BUSY)) || !strings.Contains(err.Error(), "可能已有 Photon 托盘或旧 Windows 服务占用同一数据库") || !strings.Contains(err.Error(), "不会接管") {
		t.Fatalf("competing runtime lacked the preserved native error and occupancy hint: %v", err)
	}
	assertDesktopRuntime(t, other, "failed")
	if err := other.Runtime("stop"); err != nil {
		t.Fatalf("failed competitor stop: %v", err)
	}
	if err := other.Close(); err != nil {
		t.Fatalf("historical endpoint error prevented GUI exit: %v", err)
	}
	if got := assertDesktopRuntime(t, owner, "running"); got.Observation.Admission.JoinRequestB64 != request {
		t.Fatal("stopping the failed competitor changed the real owner")
	}
	// The public control path must bind to the desktop process, not SCM.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	if _, err := photonwindows.CallControlForProcess(ctx, config.State.Path, "status", uint32(os.Getpid())); err != nil {
		cancel()
		t.Fatalf("desktop process did not own its pipe: %v", err)
	}
	cancel()
	if err := owner.Runtime("stop"); err != nil {
		t.Fatal(err)
	}
	assertDesktopRuntime(t, owner, "stopped")
	assertDesktopStateReleased(t, config)
	ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
	if _, err := photonwindows.CallControlForProcess(ctx, config.State.Path, "status", uint32(os.Getpid())); err == nil {
		cancel()
		t.Fatal("joined runtime retained its pipe")
	}
	cancel()
	if err := owner.Runtime("start"); err != nil {
		t.Fatalf("restart after releasing endpoint: %v", err)
	}
	if got := assertDesktopRuntime(t, owner, "running"); got.Observation.Admission.JoinRequestB64 != request {
		t.Fatal("restart replaced the persisted pending identity")
	}
	if err := owner.Close(); err != nil {
		t.Fatal(err)
	}
	assertDesktopStateReleased(t, config)
}
