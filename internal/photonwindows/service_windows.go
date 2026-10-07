//go:build windows

package photonwindows

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"golang.org/x/sys/windows/svc"
)

// RunService connects this process to SCM. Running means daemon initialization
// completed, independently of gateway authorization or tunnel readiness.
func RunService(name string, config *Config, logger *slog.Logger) error {
	if config == nil {
		return errors.New("Windows config is required")
	}
	if logger == nil {
		logger = slog.Default()
	}
	handler := &daemonService{daemon: NewDaemon(config, logger), logger: logger}
	if err := svc.Run(name, handler); err != nil {
		return err
	}
	return handler.err
}

type daemonService struct {
	daemon *Daemon
	logger *slog.Logger
	err    error
}

func (h *daemonService) Execute(_ []string, requests <-chan svc.ChangeRequest, statuses chan<- svc.Status) (bool, uint32) {
	commands := make(chan serviceCommand)
	quit := make(chan struct{})
	defer close(quit)
	go func() {
		defer close(commands)
		for {
			select {
			case <-quit:
				return
			case request, ok := <-requests:
				if !ok {
					return
				}
				command := serviceInterrogate
				switch request.Cmd {
				case svc.Stop, svc.Shutdown:
					command = serviceStop
				case svc.Interrogate:
				default:
					continue
				}
				select {
				case commands <- command:
				case <-quit:
					return
				}
			}
		}
	}()
	didStart := false
	h.err = serveDaemon(func(ctx context.Context) error {
		return RunControlled(ctx, h.daemon, h.daemon.config.State.Path)
	}, h.daemon.Started(), commands, func(phase servicePhase) {
		status := svc.Status{}
		switch phase {
		case serviceStarting:
			status.State = svc.StartPending
			status.WaitHint = 10000
		case serviceRunning:
			if !didStart {
				didStart = true
				h.logger.Info("runtime_started", "mode", "service")
			}
			status.State = svc.Running
			status.Accepts = svc.AcceptStop | svc.AcceptShutdown
		case serviceStopping:
			status.State = svc.StopPending
			status.WaitHint = 10000
		}
		if status.State != svc.Running {
			status.CheckPoint = 1
		}
		statuses <- status
	}, 10*time.Second)
	if h.err != nil {
		event := "runtime_start_failed"
		if didStart {
			event = "runtime_stop_failed"
		}
		h.logger.Error(event, "error", h.err)
		return true, 1
	}
	h.logger.Info("runtime_stopped", "mode", "service")
	return false, 0
}

var _ svc.Handler = (*daemonService)(nil)
