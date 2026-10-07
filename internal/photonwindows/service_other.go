//go:build !windows

package photonwindows

import (
	"errors"
	"log/slog"
)

func RunService(string, *Config, *slog.Logger) error {
	return errors.New("SCM service mode is only available on Windows")
}
