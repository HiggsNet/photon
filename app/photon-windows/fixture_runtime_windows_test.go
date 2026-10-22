//go:build windows && photon_profile

package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func fixtureRuntimeChild(t *testing.T, directory, mode string) *fixtureRuntimeReport {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, executable, "-test.run=^TestFixtureRuntimeChild$", "-test.v")
	cmd.Env = append(os.Environ(), "GOMAXPROCS=3", "PHOTON_FIXTURE_RUNTIME_CHILD_DIRECTORY="+directory, "PHOTON_FIXTURE_RUNTIME_CHILD_MODE="+mode)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("runtime child: %v\n%s", err, output)
	}
	files, err := filepath.Glob(filepath.Join(directory, "runtime-*.json"))
	if err != nil {
		t.Fatal(err)
	}
	if mode != "success" {
		if mode != "existing" && len(files) != 0 {
			t.Fatal("rejected request created a runtime report")
		}
		return nil
	}
	if len(files) != 1 {
		t.Fatalf("runtime reports: %v", files)
	}
	file, err := os.Open(files[0])
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	var report fixtureRuntimeReport
	decoder := json.NewDecoder(file)
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&report); err != nil {
		t.Fatal(err)
	}
	if report.SchemaVersion != 1 || report.PID <= 0 || report.GoVersion != runtime.Version() || report.NumCPU <= 0 || report.StartedUTC.IsZero() || report.StartedUTC.After(time.Now()) {
		t.Fatalf("invalid process identity: %+v", report)
	}
	if filepath.Base(files[0]) != fmt.Sprintf("runtime-%d.json", report.PID) {
		t.Fatal("artifact PID does not match recorded child")
	}
	return &report
}

// Setters run exclusively in this short-lived child, never in the test runner.
func TestFixtureRuntimeChild(t *testing.T) {
	directory := os.Getenv("PHOTON_FIXTURE_RUNTIME_CHILD_DIRECTORY")
	if directory == "" {
		return
	}
	mode := os.Getenv("PHOTON_FIXTURE_RUNTIME_CHILD_MODE")
	beforeP := runtime.GOMAXPROCS(0)
	beforeMask, _, err := fixtureProcessAffinity()
	if err != nil {
		t.Fatal(err)
	}
	if mode == "insufficient" {
		single, err := fixtureAffinitySubset(beforeMask, 1)
		if err != nil {
			t.Fatal(err)
		}
		ok, _, err := fixtureSetProcessAffinity.Call(uintptr(^uintptr(0)), uintptr(single))
		if ok == 0 {
			t.Fatalf("prepare restricted child: %v", err)
		}
		beforeMask = single
	}
	if mode == "existing" {
		path := filepath.Join(directory, fmt.Sprintf("runtime-%d.json", os.Getpid()))
		if err := os.WriteFile(path, []byte("existing artifact\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	err = captureFixtureRuntime(directory)
	if mode != "success" {
		if err == nil {
			t.Fatal("invalid/stale/insufficient request succeeded")
		}
		afterMask, _, queryErr := fixtureProcessAffinity()
		if queryErr != nil || afterMask != beforeMask || runtime.GOMAXPROCS(0) != beforeP {
			t.Fatal("rejected request changed runtime or process affinity")
		}
		if mode == "existing" {
			raw, err := os.ReadFile(filepath.Join(directory, fmt.Sprintf("runtime-%d.json", os.Getpid())))
			if err != nil || string(raw) != "existing artifact\n" {
				t.Fatal("overwrote existing runtime artifact")
			}
		}
		return
	}
	if err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(filepath.Join(directory, fmt.Sprintf("runtime-%d.json", os.Getpid())))
	if err != nil {
		t.Fatal(err)
	}
	var report fixtureRuntimeReport
	if err := json.Unmarshal(raw, &report); err != nil {
		t.Fatal(err)
	}
	afterMask, _, err := fixtureProcessAffinity()
	if err != nil || report.PID != os.Getpid() || report.GOMAXPROCSBefore != beforeP || report.GOMAXPROCSActual != runtime.GOMAXPROCS(0) || report.ProcessorAffinityBefore != beforeMask || report.ProcessorAffinityActual != afterMask {
		t.Fatal("report differs from actual child runtime")
	}
}

func TestFixtureRuntimeDefault(t *testing.T) {
	report := fixtureRuntimeChild(t, t.TempDir(), "success")
	if report.Explicit || report.GOMAXPROCSRequested != 0 || report.GOMAXPROCSBefore != 3 || report.GOMAXPROCSActual != 3 || report.ExplicitAffinity || report.RequestedCPUCount != 0 || report.ProcessorAffinityBefore != report.ProcessorAffinityActual || report.AvailableCPUCountBefore != report.AvailableCPUCountActual {
		t.Fatalf("default changed inherited settings: %+v", report)
	}
}

func TestFixtureRuntimeAppliedValues(t *testing.T) {
	for _, count := range []int{1, 2, 4, 8} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			directory := t.TempDir()
			if err := os.WriteFile(filepath.Join(directory, "fixture-gomaxprocs"), []byte(fmt.Sprintf("%d\n", count)), 0600); err != nil {
				t.Fatal(err)
			}
			report := fixtureRuntimeChild(t, directory, "success")
			if !report.Explicit || report.GOMAXPROCSBefore != 3 || report.GOMAXPROCSRequested != count || report.GOMAXPROCSActual != count || report.ExplicitAffinity || report.ProcessorAffinityBefore != report.ProcessorAffinityActual {
				t.Fatalf("P-only request changed wrong setting: %+v", report)
			}
		})
	}
}

func TestFixtureRuntimeAffinityValues(t *testing.T) {
	available, _, err := fixtureProcessAffinity()
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []int{1, 2, 4, 8} {
		t.Run(strconv.Itoa(count), func(t *testing.T) {
			directory := t.TempDir()
			for name, value := range map[string]int{"fixture-gomaxprocs": 8, "fixture-cpu-affinity": count} {
				if err := os.WriteFile(filepath.Join(directory, name), []byte(fmt.Sprintf("%d\n", value)), 0600); err != nil {
					t.Fatal(err)
				}
			}
			if count > bits.OnesCount64(available) {
				fixtureRuntimeChild(t, directory, "invalid")
				return
			}
			report := fixtureRuntimeChild(t, directory, "success")
			if !report.ExplicitAffinity || report.RequestedCPUCount != count || report.AvailableCPUCountActual != count || bits.OnesCount64(report.ProcessorAffinityActual) != count || report.ProcessorAffinityActual & ^report.ProcessorAffinityBefore != 0 || report.ProcessorAffinityActual & ^report.SystemMask != 0 || report.GOMAXPROCSActual != 8 {
				t.Fatalf("affinity sweep did not retain P8/subset: %+v", report)
			}
		})
	}
}

func TestFixtureRuntimeRejectsInvalidAndInsufficient(t *testing.T) {
	for _, value := range []string{"1", "1\r\n", " 1\n", "01\n", "3\n", "0\n", "16\n", "-1\n", "8\n\n", strings.Repeat("8", 4096)} {
		for _, marker := range []string{"fixture-gomaxprocs", "fixture-cpu-affinity"} {
			t.Run(marker+"/"+fmt.Sprintf("%q", value[:min(len(value), 8)]), func(t *testing.T) {
				directory := t.TempDir()
				// A valid other marker must not be applied before invalid validation.
				for _, name := range []string{"fixture-gomaxprocs", "fixture-cpu-affinity"} {
					data := "1\n"
					if name == marker {
						data = value
					}
					if err := os.WriteFile(filepath.Join(directory, name), []byte(data), 0600); err != nil {
						t.Fatal(err)
					}
				}
				fixtureRuntimeChild(t, directory, "invalid")
			})
		}
	}
	t.Run("insufficient-original-affinity", func(t *testing.T) {
		directory := t.TempDir()
		for name, value := range map[string]string{"fixture-gomaxprocs": "8\n", "fixture-cpu-affinity": "2\n"} {
			if err := os.WriteFile(filepath.Join(directory, name), []byte(value), 0600); err != nil {
				t.Fatal(err)
			}
		}
		fixtureRuntimeChild(t, directory, "insufficient")
	})
}

func TestFixtureRuntimeDoesNotOverwrite(t *testing.T) {
	directory := t.TempDir()
	for _, name := range []string{"fixture-gomaxprocs", "fixture-cpu-affinity"} {
		if err := os.WriteFile(filepath.Join(directory, name), []byte("1\n"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	fixtureRuntimeChild(t, directory, "existing")
}

func TestFixtureRuntimeStartupScopeAndFailure(t *testing.T) {
	for _, args := range [][]string{nil, {"version"}, {"service", "start"}, {"config", "validate", "--service"}, {"run", "--console", "--config", "--service"}} {
		if fixtureRuntimeServiceArgs(args) {
			t.Fatalf("fixture activated outside SCM run: %v", args)
		}
	}
	if !fixtureRuntimeServiceArgs([]string{"run", "--service", "--name", "fixture", "--config", "test.yml"}) {
		t.Fatal("fixture did not recognize actual SCM command")
	}
	// Exercise the real init failure in a separate executable directory, before
	// config loading or test dispatch, so SCM cannot silently start with wrong P.
	directory := t.TempDir()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	source, err := os.Open(executable)
	if err != nil {
		t.Fatal(err)
	}
	defer source.Close()
	copyPath := filepath.Join(directory, "runtime-startup.test.exe")
	destination, err := os.OpenFile(copyPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0700)
	if err != nil {
		t.Fatal(err)
	}
	_, copyErr := io.Copy(destination, source)
	closeErr := destination.Close()
	if copyErr != nil || closeErr != nil {
		t.Fatalf("copy child: %v %v", copyErr, closeErr)
	}
	if err := os.WriteFile(filepath.Join(directory, "fixture-gomaxprocs"), []byte("3\n"), 0600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	output, err := exec.CommandContext(ctx, copyPath, "run", "--service").CombinedOutput()
	exit, ok := err.(*exec.ExitError)
	if !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), "Photon fixture runtime setup failed") {
		t.Fatalf("invalid startup was not explicit failure: %v %s", err, output)
	}
	errors, err := filepath.Glob(filepath.Join(directory, "runtime-*.error"))
	if err != nil || len(errors) != 1 {
		t.Fatalf("missing SCM-readable error artifact: %v %v", errors, err)
	}
	if files, _ := filepath.Glob(filepath.Join(directory, "runtime-*.json")); len(files) != 0 {
		t.Fatal("invalid startup advertised an applied runtime")
	}
}
