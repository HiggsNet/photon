package main

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

type desktopControlStream struct {
	io.ReadCloser
	io.WriteCloser
	once sync.Once
}

func (s *desktopControlStream) Close() error {
	var err error
	s.once.Do(func() { err = errors.Join(s.ReadCloser.Close(), s.WriteCloser.Close()) })
	return err
}

// A run owns a child process and private IPC, never the daemon or its database.
type desktopRun struct {
	statePath string
	process   *exec.Cmd
	stream    *desktopControlStream
	requests  chan struct{}
	ctx       context.Context
	cancel    context.CancelFunc
	ready     chan struct{}
	done      chan struct{}
	err       error
}

func (r *desktopRun) call(ctx context.Context, method string) (photonwindows.ControlResponse, error) {
	select {
	case r.requests <- struct{}{}:
	case <-ctx.Done():
		return photonwindows.ControlResponse{}, ctx.Err()
	case <-r.done:
		return photonwindows.ControlResponse{}, errors.New("backend process exited")
	}
	type result struct {
		response photonwindows.ControlResponse
		err      error
	}
	completed := make(chan result, 1)
	go func() {
		// A caller may abandon a query; its reply still has to be drained before
		// another request uses the stream. Only a stuck transport poisons the run.
		timer := time.AfterFunc(10*time.Second, func() { _ = r.stream.Close() })
		response, err := photonwindows.ExchangeControl(r.stream, method)
		timer.Stop()
		<-r.requests
		completed <- result{response, err}
	}()
	select {
	case result := <-completed:
		return result.response, result.err
	case <-ctx.Done():
		return photonwindows.ControlResponse{}, ctx.Err()
	}
}

func (r *desktopRun) join() error {
	_ = r.stream.Close()
	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
	select {
	case <-r.done:
		return r.err
	case <-timer.C:
		killErr := r.process.Process.Kill()
		<-r.done
		return errors.Join(errors.New("backend cleanup timed out; owned process was terminated"), killErr, r.err)
	}
}

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
	executable := b.options.BackendPath
	if executable == "" {
		own, err := os.Executable()
		if err != nil {
			return fail(err)
		}
		name := "photon-windows"
		if runtime.GOOS == "windows" {
			name += ".exe"
		}
		executable = filepath.Join(filepath.Dir(own), name)
	}
	command := exec.Command(executable, "run", "--stdio", "--config", b.options.ConfigPath)
	desktopConfigureCommand(command)
	childInput, input, err := os.Pipe()
	if err != nil {
		return fail(err)
	}
	output, childOutput, err := os.Pipe()
	if err != nil {
		childInput.Close()
		input.Close()
		return fail(err)
	}
	command.Stdin, command.Stdout = childInput, childOutput
	stream := &desktopControlStream{ReadCloser: output, WriteCloser: input}
	err = command.Start()
	childInput.Close()
	childOutput.Close()
	if err != nil {
		stream.Close()
		return fail(fmt.Errorf("start Photon backend: %w", err))
	}
	ctx, cancel := context.WithCancel(context.Background())
	run := &desktopRun{statePath: config.State.Path, process: command, stream: stream, requests: make(chan struct{}, 1), ctx: ctx, cancel: cancel, ready: make(chan struct{}), done: make(chan struct{})}
	b.mu.Lock()
	b.run, b.runtimeErr = run, nil
	b.mu.Unlock()
	go func() { run.err = command.Wait(); close(run.done) }()
	type startup struct {
		ready photonwindows.ControlReady
		err   error
	}
	completed := make(chan startup, 1)
	go func() { ready, err := photonwindows.ReadControlReady(stream); completed <- startup{ready, err} }()
	timer := time.NewTimer(30 * time.Second)
	defer timer.Stop()
	startupRead := false
	select {
	case result := <-completed:
		startupRead = true
		err = result.err
		if err == nil && (result.ready.PID != command.Process.Pid || result.ready.StatePath != config.State.Path || result.ready.ConfigSHA256 != fmt.Sprintf("%x", sha256.Sum256(text))) {
			err = errors.New("backend startup does not match the owned process and configuration")
		}
		if err == nil {
			close(run.ready)
			select {
			case <-run.done:
				err = errors.New("backend exited after initialization")
			default:
				return nil
			}
		}
	case <-timer.C:
		err = errors.New("Photon backend startup timed out")
	}
	cancel()
	cleanupErr := run.join()
	if !startupRead {
		<-completed
	}
	return fail(errors.Join(err, cleanupErr))
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
		return nil
	default:
	}
	run.cancel()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	_, err := run.call(ctx, "stop")
	return errors.Join(err, run.join())
}

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
			out.Observation = nil
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
	response, err := run.call(ctx, "status")
	var observation *photonwindows.Observation
	if err == nil {
		observation, err = desktopObservation(response)
	}
	if err != nil {
		out.Error = "live status unavailable: " + err.Error()
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
