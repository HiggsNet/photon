package photonwindows

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync/atomic"
	"syscall"
	"time"
)

type ControlReady struct {
	PID          int    `json:"pid"`
	StatePath    string `json:"state_path"`
	ConfigSHA256 string `json:"config_sha256"`
}

func WriteControlReady(w io.Writer, ready ControlReady, startupErr error) error {
	response := ControlResponse{Version: ControlVersion, Method: "ready"}
	if startupErr != nil {
		response.Error = &ControlError{Code: "startup_failed", Message: startupErr.Error()}
		var native syscall.Errno
		if errors.As(startupErr, &native) {
			response.Error.NativeCode = uint32(native)
		}
	} else {
		response.Result, _ = json.Marshal(ready)
	}
	body, err := json.Marshal(response)
	if err != nil {
		return err
	}
	return writeControlFrame(w, body)
}

func ReadControlReady(r io.Reader) (ControlReady, error) {
	var ready ControlReady
	body, err := readControlFrame(r, controlMaxFrame)
	if err != nil {
		return ready, err
	}
	var response ControlResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return ready, err
	}
	if response.Version != ControlVersion || response.Method != "ready" || (response.Error == nil) == (len(response.Result) == 0) {
		return ready, errors.New("invalid backend startup response")
	}
	if response.Error != nil {
		return ready, response.Error
	}
	if err := json.Unmarshal(response.Result, &ready); err != nil {
		return ready, err
	}
	if ready.PID <= 0 || ready.StatePath == "" || len(ready.ConfigSHA256) != 64 {
		return ready, errors.New("incomplete backend startup response")
	}
	return ready, nil
}

type streamControlDaemon struct {
	*Daemon
	stopped atomic.Bool
}

func (d *streamControlDaemon) Stop(ctx context.Context) error {
	err := d.Daemon.Stop(ctx)
	if err == nil {
		d.stopped.Store(true)
	}
	return err
}

// The inherited stream is private to one frontend and its backend. Losing it
// cancels the owned run; the existing Windows control pipe remains available.
func RunControlStream(ctx context.Context, daemon *Daemon, configSHA256 string, stream io.ReadWriteCloser) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	defer stream.Close()
	// Cover startup writes as well as request reads. The stream may have been
	// created with a different context, so cancellation must close it explicitly.
	stopClose := context.AfterFunc(ctx, func() { _ = stream.Close() })
	defer stopClose()
	running := make(chan error, 1)
	go func() { running <- RunControlled(ctx, daemon, daemon.config.State.Path) }()
	var startupErr error
	select {
	case <-daemon.Started():
	case startupErr = <-running:
		if startupErr == nil {
			startupErr = errors.New("backend exited during startup")
		}
		_ = WriteControlReady(stream, ControlReady{}, startupErr)
		return startupErr
	case <-ctx.Done():
		_ = stream.Close()
		return errors.Join(ctx.Err(), <-running)
	}
	ready := ControlReady{PID: os.Getpid(), StatePath: daemon.config.State.Path, ConfigSHA256: configSHA256}
	if err := WriteControlReady(stream, ready, nil); err != nil {
		cancel()
		return errors.Join(err, <-running)
	}
	requests := make(chan error, 1)
	owner := &streamControlDaemon{Daemon: daemon}
	go func() {
		for {
			err := serveControlRequest(ctx, stream, owner)
			if err != nil || owner.stopped.Load() {
				requests <- err
				return
			}
		}
	}()
	select {
	case err := <-requests:
		cancel()
		if errors.Is(err, io.EOF) {
			err = nil
		}
		return errors.Join(err, <-running)
	case err := <-running:
		// A stop response must reach the caller after cleanup, before closing I/O.
		timer := time.AfterFunc(controlTimeout, func() { _ = stream.Close() })
		defer timer.Stop()
		_ = <-requests
		return err
	case <-ctx.Done():
		_ = stream.Close()
		<-requests
		return errors.Join(ctx.Err(), <-running)
	}
}
