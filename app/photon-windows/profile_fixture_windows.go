//go:build windows && photon_profile

package main

// This file is only linked into explicitly tagged validation binaries. It does
// not add a product CLI option, listener, or a control-protocol method.
import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime/pprof"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
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
	timingMode, err := readFixturePacketTimingMode(filepath.Dir(prefix))
	if err != nil {
		return err
	}
	file, err := os.OpenFile(prefix+".pprof", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	dropsFile, err := os.OpenFile(prefix+".packet-drops.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		file.Close()
		return err
	}
	defer dropsFile.Close()
	var timingFile *os.File
	if timingMode != "" {
		timingFile, err = os.OpenFile(prefix+".packet-timing.json", os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
		if err != nil {
			file.Close()
			return err
		}
		defer timingFile.Close()
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
	timingStarted := false
	if timingMode != "" {
		if err := photonwindows.StartFixturePacketTiming(timingMode == "on"); err != nil {
			return err
		}
		timingStarted = true
	}
	defer func() {
		if timingStarted {
			photonwindows.StopFixturePacketTiming()
		}
	}()
	baseline := photonwindows.ReadFixturePacketDrops()
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
	end := photonwindows.ReadFixturePacketDrops()
	var timing photonwindows.FixturePacketTiming
	if timingStarted {
		timing = photonwindows.StopFixturePacketTiming()
		timingStarted = false
	}
	pprof.StopCPUProfile()
	err = file.Close()
	stopped = true
	if err != nil {
		return err
	}
	report, err := fixturePacketDropDelta(baseline, end)
	if err != nil {
		return err
	}
	if err = json.NewEncoder(dropsFile).Encode(report); err != nil {
		return err
	}
	if err = dropsFile.Close(); err != nil {
		return err
	}
	if timingFile != nil {
		if err := json.NewEncoder(timingFile).Encode(timing); err != nil {
			return err
		}
		if err := timingFile.Close(); err != nil {
			return err
		}
	}
	return writeFixtureProfileMarker(prefix+".done", reason)
}

// This marker is private to the isolated profiling fixture. Bound reads and
// reject malformed modes before opening artifacts or enabling any probe.
func readFixturePacketTimingMode(directory string) (string, error) {
	file, err := os.Open(filepath.Join(directory, "fixture-packet-timing-profile"))
	if os.IsNotExist(err) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return "", err
	}
	if !info.Mode().IsRegular() || info.Size() > 32 {
		return "", fmt.Errorf("invalid fixture packet timing marker")
	}
	raw, err := io.ReadAll(io.LimitReader(file, 33))
	if err != nil {
		return "", err
	}
	switch string(raw) {
	case "on:f1-w64-IPv4\n", "on:f4-w64-IPv4\n":
		return "on", nil
	case "off:f1-w64-IPv4\n", "off:f4-w64-IPv4\n":
		return "off", nil
	default:
		return "", fmt.Errorf("invalid fixture packet timing marker")
	}
}

type fixturePacketDropReport struct {
	SchemaVersion int    `json:"schema_version"`
	RawIngress    uint64 `json:"raw_ingress_drops"`
	LeafIngress   uint64 `json:"leaf_ingress_drops"`
	ESPIngress    uint64 `json:"esp_ingress_drops"`
}

func fixturePacketDropDelta(baseline, end photonwindows.FixturePacketDrops) (fixturePacketDropReport, error) {
	if end.RawIngress < baseline.RawIngress || end.LeafIngress < baseline.LeafIngress || end.ESPIngress < baseline.ESPIngress {
		return fixturePacketDropReport{}, fmt.Errorf("fixture packet drop counters moved backwards")
	}
	return fixturePacketDropReport{SchemaVersion: 1, RawIngress: end.RawIngress - baseline.RawIngress,
		LeafIngress: end.LeafIngress - baseline.LeafIngress, ESPIngress: end.ESPIngress - baseline.ESPIngress}, nil
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
