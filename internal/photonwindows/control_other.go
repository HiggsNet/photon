//go:build !windows

package photonwindows

import (
	"context"
	"errors"
)

func CallControl(context.Context, string, string) (ControlResponse, error) {
	return ControlResponse{}, errors.New("local control requires Windows")
}

func CallControlForProcess(context.Context, string, string, uint32) (ControlResponse, error) {
	return ControlResponse{}, errors.New("local control requires Windows")
}

// Portable composition tests exercise Daemon directly without a Windows pipe.
func RunControlled(ctx context.Context, daemon *Daemon, _ string) error { return daemon.Run(ctx) }
