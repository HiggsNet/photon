package photonwindows

import (
	"context"
	"fmt"
	"time"
)

const DefaultServiceName = "PhotonWindows"

type servicePhase uint8

const (
	serviceStarting servicePhase = iota
	serviceRunning
	serviceStopping
)

type serviceCommand uint8

const (
	serviceInterrogate serviceCommand = iota
	serviceStop
)

// serveDaemon owns exactly one Run invocation. Returning nil means Run joined
// successfully; a timeout is a failed stop, never a clean shutdown.
func serveDaemon(run func(context.Context) error, started <-chan struct{}, commands <-chan serviceCommand, report func(servicePhase), stopTimeout time.Duration) error {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	report(serviceStarting)
	go func() { done <- run(ctx) }()
	phase := serviceStarting
	var timeout <-chan time.Time
	var timer *time.Timer
	defer func() {
		if timer != nil {
			timer.Stop()
		}
	}()
	for {
		select {
		case err := <-done:
			if err != nil {
				return err
			}
			return nil
		case <-started:
			started = nil
			if phase == serviceStarting {
				// Prefer an already completed initialization failure over Running.
				select {
				case err := <-done:
					return err
				default:
				}
				phase = serviceRunning
				report(phase)
			}
		case cmd, ok := <-commands:
			if !ok {
				cmd = serviceStop
				commands = nil
			}
			if cmd == serviceStop && phase != serviceStopping {
				phase = serviceStopping
				report(phase)
				cancel()
				timer = time.NewTimer(stopTimeout)
				timeout = timer.C
			} else {
				report(phase)
			}
		case <-timeout:
			return fmt.Errorf("Windows daemon did not stop within %s", stopTimeout)
		}
	}
}
