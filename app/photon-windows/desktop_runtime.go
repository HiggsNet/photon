package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

// One run owns the production daemon and its logger until done closes. Config
// edits cannot retarget this run's pipe, state database or transport settings.
type desktopRun struct {
	statePath string
	ctx       context.Context
	cancel    context.CancelFunc
	ready     <-chan struct{}
	done      chan struct{}
	err       error // Published by closing done; read only after receiving done.
}

// Runtime changes only the composition started by this desktop. It never
// queries SCM or sends a stop request to a different process's control pipe.
func (b *desktopBackend) Runtime(action string) error {
	b.runtimeMu.Lock()
	defer b.runtimeMu.Unlock()
	switch action {
	case "start":
		return b.startRuntime()
	case "stop":
		return b.stopRuntime()
	case "restart":
		if err := b.stopRuntime(); err != nil {
			return err
		}
		return b.startRuntime()
	default:
		return fmt.Errorf("unsupported desktop runtime action %q", action)
	}
}

func (b *desktopBackend) startRuntime() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return errors.New("desktop runtime is closed")
	}
	if run := b.run; run != nil {
		select {
		case <-run.done:
		default:
			b.mu.Unlock()
			return nil
		}
	}
	b.mu.Unlock()
	fail := func(err error) error {
		b.mu.Lock()
		b.runtimeErr = err
		b.mu.Unlock()
		return err
	}
	text, _, err := desktopReadConfig(b.options.ConfigPath)
	if err != nil {
		return fail(err)
	}
	config, err := desktopParseConfig(string(text))
	if err != nil {
		return fail(err)
	}
	logger, closer, err := photonwindows.NewRuntimeLogger(config, nil, "")
	if err != nil {
		return fail(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	daemon := photonwindows.NewDaemon(config, logger)
	run := &desktopRun{statePath: config.State.Path, ctx: ctx, cancel: cancel, ready: daemon.Started(), done: make(chan struct{})}
	b.mu.Lock()
	b.run, b.runtimeErr = run, nil
	b.mu.Unlock()
	go func() {
		err := photonwindows.RunControlled(ctx, daemon, config.State.Path)
		cancel()
		if err != nil {
			logger.Error("runtime_stopped", "error", err)
		} else {
			logger.Info("runtime_stopped")
		}
		run.err = errors.Join(err, closer.Close())
		close(run.done)
	}()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	select {
	case <-run.ready:
		select {
		case <-run.done:
		default:
			logger.Info("runtime_started", "mode", "desktop")
			return nil
		}
	case <-run.done:
	case <-timer.C:
		cancel()
		<-run.done // Never leave a timed-out start running behind the UI.
		return fail(errors.Join(errors.New("Photon startup timed out"), run.err))
	}
	if run.err != nil {
		return run.err
	}
	return fail(errors.New("Photon exited before startup completed"))
}

func (b *desktopBackend) stopRuntime() error {
	b.mu.Lock()
	run := b.run
	b.mu.Unlock()
	if run == nil {
		return nil
	}
	select {
	case <-run.done:
		// An old startup/runtime error remains visible in Snapshot, but there
		// is no live ownership left for Stop or Close to release again.
		return nil
	default:
	}
	run.cancel()
	<-run.done
	return run.err
}

// Close is the final cancellation/join barrier, including abnormal UI teardown.
// Repeating it after a completed cleanup succeeds even if that run had failed.
func (b *desktopBackend) Close() error {
	b.runtimeMu.Lock()
	defer b.runtimeMu.Unlock()
	b.mu.Lock()
	b.closed = true
	b.mu.Unlock()
	return b.stopRuntime()
}

func (b *desktopBackend) Snapshot(ctx context.Context) desktopSnapshot {
	b.mu.Lock()
	run, lastErr := b.run, b.runtimeErr
	b.mu.Unlock()
	out := desktopSnapshot{RuntimeState: "stopped"}
	if lastErr != nil {
		out.RuntimeState, out.Error = "failed", lastErr.Error()
	}
	if run == nil {
		return out
	}
	finished := func() bool {
		select {
		case <-run.done:
			out.RuntimeState = "stopped"
			if lastErr != nil {
				out.RuntimeState, out.Error = "failed", lastErr.Error()
			} else if run.err != nil {
				out.RuntimeState, out.Error = "failed", run.err.Error()
			}
			return true
		default:
			return false
		}
	}
	if finished() {
		return out
	}
	if run.ctx.Err() != nil {
		out.RuntimeState = "stopping"
		return out
	}
	select {
	case <-run.ready:
		out.RuntimeState = "running"
	default:
		out.RuntimeState = "starting"
		return out
	}
	if lastErr != nil {
		return out
	}
	response, err := photonwindows.CallControlForProcess(ctx, run.statePath, "status", uint32(os.Getpid()))
	if err != nil {
		out.Error = "live status unavailable: " + err.Error()
		return out
	}
	observation, err := desktopObservation(response)
	if err != nil {
		out.Error = err.Error()
		return out
	}
	b.mu.Lock()
	sameRun := b.run == run
	b.mu.Unlock()
	if !sameRun || finished() || run.ctx.Err() != nil {
		if !sameRun {
			out.RuntimeState, out.Error = "stopped", "Photon changed while reading live status"
		} else if run.ctx.Err() != nil && out.RuntimeState == "running" {
			out.RuntimeState = "stopping"
		}
		return out
	}
	out.Observation = observation
	return out
}
