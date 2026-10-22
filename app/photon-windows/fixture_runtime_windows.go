//go:build windows && photon_profile

package main

// Startup-only controls for isolated validation services. Neither this file nor
// its markers are present in ordinary product builds.
import (
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"os"
	"path/filepath"
	"runtime"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	fixtureKernel32           = windows.NewLazySystemDLL("kernel32.dll")
	fixtureGetProcessAffinity = fixtureKernel32.NewProc("GetProcessAffinityMask")
	fixtureSetProcessAffinity = fixtureKernel32.NewProc("SetProcessAffinityMask")
	fixtureProcessorGroups    = fixtureKernel32.NewProc("GetActiveProcessorGroupCount")
)

type fixtureRuntimeReport struct {
	SchemaVersion           int
	PID                     int
	StartedUTC              time.Time // OS process creation time, not observation time.
	GoVersion               string
	NumCPU                  int // Go's cached startup count, not the narrowed mask count.
	GOMAXPROCSBefore        int
	GOMAXPROCSRequested     int // Zero means no marker and no setter call.
	GOMAXPROCSActual        int
	Explicit                bool
	ProcessorAffinityBefore uint64
	ProcessorAffinityActual uint64
	SystemMask              uint64
	RequestedCPUCount       int // Logical CPUs, not physical cores; zero means unchanged.
	AvailableCPUCountBefore int
	AvailableCPUCountActual int
	ExplicitAffinity        bool
}

func init() {
	if !fixtureRuntimeServiceArgs(os.Args[1:]) {
		return
	}
	executable, err := os.Executable()
	if err == nil {
		err = captureFixtureRuntime(filepath.Dir(executable))
	}
	if err != nil {
		message := fmt.Sprintf("Photon fixture runtime setup failed: %v", err)
		fmt.Fprintln(os.Stderr, message)
		if executable != "" {
			_ = writeFixtureProfileMarker(filepath.Join(filepath.Dir(executable), fmt.Sprintf("runtime-%d.error", os.Getpid())), message+"\n")
		}
		os.Exit(1)
	}
}

func fixtureRuntimeServiceArgs(args []string) bool {
	// This is the exact prefix installed by manageService. In particular, an
	// arbitrary --service string in a console/config/admin command is not enough.
	return len(args) >= 2 && args[0] == "run" && args[1] == "--service"
}

func readFixtureRuntimeCount(path string) (int, error) {
	file, err := os.Open(path)
	if os.IsNotExist(err) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return 0, err
	}
	if !info.Mode().IsRegular() || info.Size() != 2 {
		return 0, fmt.Errorf("%s must contain exactly 1, 2, 4, or 8 followed by LF", filepath.Base(path))
	}
	// Bound the read even if a writer changes the file after Stat.
	raw, err := io.ReadAll(io.LimitReader(file, 3))
	if err != nil {
		return 0, err
	}
	switch string(raw) {
	case "1\n":
		return 1, nil
	case "2\n":
		return 2, nil
	case "4\n":
		return 4, nil
	case "8\n":
		return 8, nil
	default:
		return 0, fmt.Errorf("%s must contain exactly 1, 2, 4, or 8 followed by LF", filepath.Base(path))
	}
}

func fixtureProcessAffinity() (uint64, uint64, error) {
	if err := fixtureProcessorGroups.Find(); err != nil {
		return 0, 0, err
	}
	groups, _, _ := fixtureProcessorGroups.Call()
	if groups != 1 {
		return 0, 0, fmt.Errorf("fixture requires one active processor group, got %d", groups)
	}
	if err := fixtureGetProcessAffinity.Find(); err != nil {
		return 0, 0, err
	}
	var process, system uintptr
	ok, _, err := fixtureGetProcessAffinity.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&process)), uintptr(unsafe.Pointer(&system)))
	if ok == 0 {
		return 0, 0, fmt.Errorf("GetProcessAffinityMask: %w", err)
	}
	if process == 0 || system == 0 || process & ^system != 0 {
		return 0, 0, fmt.Errorf("invalid process/system affinity masks")
	}
	return uint64(process), uint64(system), nil
}

func fixtureAffinitySubset(available uint64, count int) (uint64, error) {
	if count > bits.OnesCount64(available) {
		return 0, fmt.Errorf("requested %d logical CPUs but original process affinity allows only %d", count, bits.OnesCount64(available))
	}
	var selected uint64
	for range count {
		lowest := available & -available
		selected |= lowest
		available &^= lowest
	}
	return selected, nil
}

func captureFixtureRuntime(directory string) error {
	requestedP, err := readFixtureRuntimeCount(filepath.Join(directory, "fixture-gomaxprocs"))
	if err != nil {
		return err
	}
	requestedCPUs, err := readFixtureRuntimeCount(filepath.Join(directory, "fixture-cpu-affinity"))
	if err != nil {
		return err
	}
	beforeAffinity, system, err := fixtureProcessAffinity()
	if err != nil {
		return err
	}
	selected := beforeAffinity
	if requestedCPUs != 0 {
		selected, err = fixtureAffinitySubset(beforeAffinity, requestedCPUs)
		if err != nil {
			return err
		}
		if err := fixtureSetProcessAffinity.Find(); err != nil {
			return err
		}
	}
	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(windows.CurrentProcess(), &created, &exited, &kernel, &user); err != nil {
		return err
	}
	report := fixtureRuntimeReport{SchemaVersion: 1, PID: os.Getpid(), StartedUTC: time.Unix(0, created.Nanoseconds()).UTC(),
		GoVersion: runtime.Version(), NumCPU: runtime.NumCPU(), GOMAXPROCSBefore: runtime.GOMAXPROCS(0),
		GOMAXPROCSRequested: requestedP, Explicit: requestedP != 0, ProcessorAffinityBefore: beforeAffinity,
		SystemMask: system, RequestedCPUCount: requestedCPUs, AvailableCPUCountBefore: bits.OnesCount64(beforeAffinity), ExplicitAffinity: requestedCPUs != 0}
	// Validate every request/API and reserve the exclusive artifact before either
	// setter. A stale artifact must not alter this process's runtime or CPU mask.
	file, err := os.OpenFile(filepath.Join(directory, fmt.Sprintf("runtime-%d.json", report.PID)), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return err
	}
	defer file.Close()
	if requestedCPUs != 0 {
		ok, _, err := fixtureSetProcessAffinity.Call(uintptr(windows.CurrentProcess()), uintptr(selected))
		if ok == 0 {
			return fmt.Errorf("SetProcessAffinityMask: %w", err)
		}
	}
	if requestedP != 0 {
		runtime.GOMAXPROCS(requestedP)
	}
	report.GOMAXPROCSActual = runtime.GOMAXPROCS(0)
	report.ProcessorAffinityActual, _, err = fixtureProcessAffinity()
	if err != nil {
		return err
	}
	report.AvailableCPUCountActual = bits.OnesCount64(report.ProcessorAffinityActual)
	if requestedP != 0 && report.GOMAXPROCSActual != requestedP || report.ProcessorAffinityActual != selected {
		return fmt.Errorf("runtime/affinity request did not take effect")
	}
	if err := json.NewEncoder(file).Encode(report); err != nil {
		return err
	}
	return file.Close()
}
