//go:build windows && photon_profile

package main

// This file is only linked into explicitly tagged validation binaries. It does
// not add a product CLI option, listener, or a control-protocol method.
import (
	"fmt"
	"os"
	"path/filepath"
	"runtime/pprof"
	"slices"
	"time"
)

func init() {
	if len(os.Args) < 2 || os.Args[1] != "run" || !slices.Contains(os.Args[2:], "--service") {
		return
	}
	executable, err := os.Executable()
	if err != nil {
		return
	}
	prefix := filepath.Join(filepath.Dir(executable), fmt.Sprintf("profile-%d", os.Getpid()))
	// A request left by an earlier process with a recycled PID is never accepted.
	started := time.Now()
	go func() {
		deadline := time.Now().Add(5 * time.Minute)
		ticker := time.NewTicker(100 * time.Millisecond)
		defer ticker.Stop()
		for range ticker.C {
			if time.Now().After(deadline) {
				return
			}
			info, err := os.Stat(prefix + ".request")
			if err != nil || info.Size() != 6 || info.ModTime().Before(started) {
				continue
			}
			request, err := os.ReadFile(prefix + ".request")
			if err != nil || string(request) != "start\n" {
				continue
			}
			if err := captureFixtureCPU(prefix, 30*time.Second); err != nil {
				_ = writeFixtureProfileMarker(prefix+".error", err.Error())
			}
			return // At most one bounded profile per service process.
		}
	}()
}

func captureFixtureCPU(prefix string, limit time.Duration) error {
	file, err := os.OpenFile(prefix+".pprof", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	if err = pprof.StartCPUProfile(file); err != nil {
		file.Close()
		return err
	}
	stopped := false
	defer func() {
		if !stopped {
			pprof.StopCPUProfile()
			file.Close()
		}
	}()
	if err = writeFixtureProfileMarker(prefix+".started", "started\n"); err != nil {
		return err
	}
	ticker := time.NewTicker(50 * time.Millisecond)
	defer ticker.Stop()
	timer := time.NewTimer(limit)
	defer timer.Stop()
	reason := "limit\n"
loop:
	for {
		select {
		case <-timer.C:
			break loop
		case <-ticker.C:
			if _, err := os.Stat(prefix + ".stop"); err == nil {
				reason = "stopped\n"
				break loop
			}
		}
	}
	pprof.StopCPUProfile()
	err = file.Close()
	stopped = true
	if err != nil {
		return err
	}
	return writeFixtureProfileMarker(prefix+".done", reason)
}

func writeFixtureProfileMarker(path, value string) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = file.WriteString(value)
	closeErr := file.Close()
	if err != nil {
		return err
	}
	return closeErr
}
