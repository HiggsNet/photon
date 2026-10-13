package main

import (
	"errors"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

type processSample struct {
	Seconds, CPUSeconds           float64
	PrivateBytes, WorkingSetBytes uint64
	StartToken                    uint64
}

func filetimeValue(t windows.Filetime) uint64 {
	return uint64(t.HighDateTime)<<32 | uint64(t.LowDateTime)
}
func processTimes(h windows.Handle) (cpu float64, start uint64, err error) {
	var creation, exit, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return
	}
	if filetimeValue(exit) != 0 {
		err = errors.New("service process exited")
		return
	}
	return float64(filetimeValue(kernel)+filetimeValue(user)) / 1e7, filetimeValue(creation), nil
}
func currentCPUSeconds() (float64, error) {
	cpu, _, err := processTimes(windows.CurrentProcess())
	return cpu, err
}

var getProcessMemoryInfo = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo")

type memoryCounters struct {
	Size, PageFaults                                                                                                                                         uint32
	PeakWorkingSet, WorkingSet, QuotaPeakPagedPool, QuotaPagedPool, QuotaPeakNonPagedPool, QuotaNonPagedPool, PagefileUsage, PeakPagefileUsage, PrivateUsage uintptr
}

func sampleProcess(pid int, start time.Time) (processSample, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ, false, uint32(pid))
	if err != nil {
		return processSample{}, err
	}
	defer windows.CloseHandle(h)
	cpu, token, err := processTimes(h)
	if err != nil {
		return processSample{}, err
	}
	memory := memoryCounters{}
	memory.Size = uint32(unsafe.Sizeof(memory))
	ok, _, err := getProcessMemoryInfo.Call(uintptr(h), uintptr(unsafe.Pointer(&memory)), uintptr(memory.Size))
	if ok == 0 {
		return processSample{}, err
	}
	return processSample{Seconds: time.Since(start).Seconds(), CPUSeconds: cpu, StartToken: token, PrivateBytes: uint64(memory.PrivateUsage), WorkingSetBytes: uint64(memory.WorkingSet)}, nil
}
