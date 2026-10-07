package photonwindows

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestServiceWaitsForInitializationAndJoinsStop(t *testing.T) {
	started := make(chan struct{})
	commands := make(chan serviceCommand)
	reports := make(chan servicePhase, 8)
	cleanup := make(chan struct{})
	joined := make(chan struct{})
	result := make(chan error, 1)
	go func() {
		result <- serveDaemon(func(ctx context.Context) error {
			<-ctx.Done()
			<-cleanup
			close(joined)
			return nil
		}, started, commands, func(s servicePhase) { reports <- s }, time.Second)
	}()
	if got := <-reports; got != serviceStarting {
		t.Fatalf("initial phase %v", got)
	}
	commands <- serviceInterrogate
	if got := <-reports; got != serviceStarting {
		t.Fatalf("running before init: %v", got)
	}
	close(started)
	if got := <-reports; got != serviceRunning {
		t.Fatalf("initialized phase %v", got)
	}
	commands <- serviceStop
	if got := <-reports; got != serviceStopping {
		t.Fatalf("stop phase %v", got)
	}
	select {
	case err := <-result:
		t.Fatalf("returned before cleanup: %v", err)
	default:
	}
	close(cleanup)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
	select {
	case <-joined:
	default:
		t.Fatal("daemon not joined")
	}
}

func TestServiceInitializationFailureNeverRunning(t *testing.T) {
	want := errors.New("state initialization failed")
	var reports []servicePhase
	err := serveDaemon(func(context.Context) error { return want }, make(chan struct{}), make(chan serviceCommand), func(s servicePhase) { reports = append(reports, s) }, time.Second)
	if !errors.Is(err, want) {
		t.Fatalf("error %v", err)
	}
	if len(reports) != 1 || reports[0] != serviceStarting {
		t.Fatalf("reports %v", reports)
	}
}

func TestServiceStopDuringInitialization(t *testing.T) {
	commands := make(chan serviceCommand, 1)
	commands <- serviceStop
	started := make(chan struct{})
	var reports []servicePhase
	err := serveDaemon(func(ctx context.Context) error { <-ctx.Done(); close(started); return nil }, started, commands, func(s servicePhase) { reports = append(reports, s) }, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	for _, phase := range reports {
		if phase == serviceRunning {
			t.Fatal("Running after stop")
		}
	}
}

func TestServiceStopTimeoutIsFailure(t *testing.T) {
	commands := make(chan serviceCommand, 1)
	commands <- serviceStop
	release := make(chan struct{})
	joined := make(chan struct{})
	err := serveDaemon(func(context.Context) error { defer close(joined); <-release; return nil }, make(chan struct{}), commands, func(servicePhase) {}, 10*time.Millisecond)
	close(release)
	<-joined
	if err == nil || !strings.Contains(err.Error(), "did not stop") {
		t.Fatalf("timeout %v", err)
	}
}

func TestServiceCleanupFailureIsFailure(t *testing.T) {
	commands := make(chan serviceCommand, 1)
	commands <- serviceStop
	want := errors.New("route cleanup failed")
	err := serveDaemon(func(ctx context.Context) error { <-ctx.Done(); return want }, make(chan struct{}), commands, func(servicePhase) {}, time.Second)
	if !errors.Is(err, want) {
		t.Fatalf("cleanup %v", err)
	}
}

func TestServiceDaemonStopThroughControlIsClean(t *testing.T) {
	started := make(chan struct{})
	stop := make(chan struct{})
	reports := make(chan servicePhase, 2)
	result := make(chan error, 1)
	go func() {
		result <- serveDaemon(func(context.Context) error {
			close(started)
			<-stop // The production IPC calls Daemon.Stop, independently of SCM.
			return nil
		}, started, make(chan serviceCommand), func(s servicePhase) { reports <- s }, time.Second)
	}()
	<-reports
	if phase := <-reports; phase != serviceRunning {
		t.Fatalf("phase %v", phase)
	}
	close(stop)
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
