package main

import (
	"errors"
	"fmt"
	"math/bits"
	"sort"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func filetimeValue(t windows.Filetime) uint64 {
	return uint64(t.HighDateTime)<<32 | uint64(t.LowDateTime)
}
func processTimes(h windows.Handle) (cpu float64, start uint64, err error) {
	state, waitErr := windows.WaitForSingleObject(h, 0)
	if waitErr != nil {
		return 0, 0, waitErr
	}
	if state != uint32(windows.WAIT_TIMEOUT) {
		return 0, 0, errors.New("service process exited or has invalid wait state")
	}
	var creation, exit, kernel, user windows.Filetime
	if err = windows.GetProcessTimes(h, &creation, &exit, &kernel, &user); err != nil {
		return
	}
	return float64(filetimeValue(kernel)+filetimeValue(user)) / 1e7, filetimeValue(creation), nil
}
func currentCPUSeconds() (float64, error) {
	cpu, _, err := processTimes(windows.CurrentProcess())
	return cpu, err
}

var (
	getProcessMemoryInfo         = windows.NewLazySystemDLL("psapi.dll").NewProc("GetProcessMemoryInfo")
	kernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	getThreadTimes               = kernel32.NewProc("GetThreadTimes")
	getProcessIDOfThread         = kernel32.NewProc("GetProcessIdOfThread")
	getProcessAffinityMask       = kernel32.NewProc("GetProcessAffinityMask")
	getActiveProcessorGroupCount = kernel32.NewProc("GetActiveProcessorGroupCount")
	getProcessGroupAffinity      = kernel32.NewProc("GetProcessGroupAffinity")
)

type memoryCounters struct {
	Size, PageFaults                                                                                                                                         uint32
	PeakWorkingSet, WorkingSet, QuotaPeakPagedPool, QuotaPagedPool, QuotaPeakNonPagedPool, QuotaNonPagedPool, PagefileUsage, PeakPagefileUsage, PrivateUsage uintptr
}

func sampleProcess(pid int, start time.Time) (processSample, error) {
	return sampleProcessMode(pid, start, false)
}

func sampleProcessMode(pid int, start time.Time, threads bool) (processSample, error) {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ|windows.SYNCHRONIZE, false, uint32(pid))
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
	r := processSample{Seconds: time.Since(start).Seconds(), CPUSeconds: cpu, StartToken: token, PrivateBytes: uint64(memory.PrivateUsage), WorkingSetBytes: uint64(memory.WorkingSet)}
	if threads {
		affinity := processAffinity(h)
		r.Affinity = &affinity
		observation := observeThreads(uint32(pid), start)
		r.Threads = &observation
		// Do not report a live sample if the process exited while enumerating.
		_, afterToken, err := processTimes(h)
		if err != nil {
			return r, err
		}
		if afterToken != token {
			return r, errors.New("process identity changed during thread sampling")
		}
	}
	return r, nil
}

func currentAffinity() affinitySample { return processAffinity(windows.CurrentProcess()) }

func processAffinity(h windows.Handle) affinitySample {
	var processMask, systemMask uintptr
	r := affinitySample{}
	groups, _, groupErr := getActiveProcessorGroupCount.Call()
	if groups == 0 {
		r.Error = fmt.Sprintf("GetActiveProcessorGroupCount failed: %v", groupErr)
		return r
	}
	r.SystemGroupCount = int(groups)
	var groupIDs [64]uint16
	groupCount := uint16(len(groupIDs))
	ok, _, err := getProcessGroupAffinity.Call(uintptr(h), uintptr(unsafe.Pointer(&groupCount)), uintptr(unsafe.Pointer(&groupIDs[0])))
	if ok == 0 || groupCount == 0 || int(groupCount) > len(groupIDs) {
		r.Error = fmt.Sprintf("GetProcessGroupAffinity failed or exceeded group limit: %v", err)
		return r
	}
	r.ProcessGroupIDs = append([]uint16(nil), groupIDs[:groupCount]...)
	r.ProcessGroupCount = int(groupCount)
	ok, _, err = getProcessAffinityMask.Call(uintptr(h), uintptr(unsafe.Pointer(&processMask)), uintptr(unsafe.Pointer(&systemMask)))
	if ok == 0 {
		r.Error = fmt.Sprintf("GetProcessAffinityMask failed: %v", err)
		return r
	}
	r.ProcessMask, r.SystemMask = fmt.Sprintf("0x%x", processMask), fmt.Sprintf("0x%x", systemMask)
	r.CPUCountLowerBound = bits.OnesCount64(uint64(processMask))
	if groupCount != 1 || groups != 1 {
		// A single mask cannot establish the complete multi-group affinity.
		r.CPUCountUpperBound = int(groups) * 64
		r.Error = "multi-processor-group affinity is incomplete with GetProcessAffinityMask"
		return r
	}
	if processMask == 0 || processMask & ^systemMask != 0 {
		r.Error = "invalid single-group process/system affinity masks"
		return r
	}
	r.CPUCountUpperBound, r.Complete = r.CPUCountLowerBound, true
	return r
}

func observeThreads(pid uint32, start time.Time) threadObservation {
	r := threadObservation{Limit: 1024, Threads: make([]threadSample, 0)}
	snapshot, err := windows.CreateToolhelp32Snapshot(windows.TH32CS_SNAPTHREAD, 0)
	if err != nil {
		r.Errors = append(r.Errors, "CreateToolhelp32Snapshot: "+err.Error())
		return r
	}
	defer windows.CloseHandle(snapshot)
	entry := windows.ThreadEntry32{Size: uint32(unsafe.Sizeof(windows.ThreadEntry32{}))}
	err = windows.Thread32First(snapshot, &entry)
	for err == nil {
		if entry.OwnerProcessID == pid {
			if r.Enumerated == r.Limit {
				r.Errors = append(r.Errors, "target thread enumeration exceeded limit")
				return r
			}
			r.Enumerated++
			r.Threads = append(r.Threads, sampleThread(pid, entry.ThreadID, start))
		}
		err = windows.Thread32Next(snapshot, &entry)
	}
	if errors.Is(err, windows.ERROR_NO_MORE_FILES) || errors.Is(err, windows.ERROR_NO_MORE_ITEMS) {
		r.EnumerationComplete = true
	} else {
		r.Errors = append(r.Errors, "thread enumeration: "+err.Error())
	}
	if r.Enumerated == 0 {
		r.EnumerationComplete = false
		r.Errors = append(r.Errors, "no target threads observed")
	}
	sort.Slice(r.Threads, func(i, j int) bool { return r.Threads[i].TID < r.Threads[j].TID })
	return r
}

func sampleThread(pid, tid uint32, start time.Time) threadSample {
	r := threadSample{TID: tid}
	h, err := windows.OpenThread(windows.THREAD_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, tid)
	if err != nil {
		r.Error = "OpenThread (possibly exited): " + err.Error()
		r.ErrorCode = windowsErrorCode(err)
		return r
	}
	defer windows.CloseHandle(h)
	return readThreadHandle(h, pid, tid, start)
}

func readThreadHandle(h windows.Handle, pid, tid uint32, start time.Time) threadSample {
	r := threadSample{TID: tid}
	owner, _, err := getProcessIDOfThread.Call(uintptr(h))
	if owner == 0 || uint32(owner) != pid {
		r.Error = fmt.Sprintf("thread owner identity differs: got %d, expected %d (%v)", owner, pid, err)
		if owner == 0 {
			r.ErrorCode = windowsErrorCode(err)
		}
		return r
	}
	var creation, exit, kernel, user windows.Filetime
	ok, _, err := getThreadTimes.Call(uintptr(h), uintptr(unsafe.Pointer(&creation)), uintptr(unsafe.Pointer(&exit)), uintptr(unsafe.Pointer(&kernel)), uintptr(unsafe.Pointer(&user)))
	if ok == 0 {
		r.Error = "GetThreadTimes: " + err.Error()
		r.ErrorCode = windowsErrorCode(err)
		return r
	}
	r.StartToken = strconv.FormatUint(filetimeValue(creation), 10)
	r.UserSeconds, r.KernelSeconds = float64(filetimeValue(user))/1e7, float64(filetimeValue(kernel))/1e7
	r.CPUSeconds = r.UserSeconds + r.KernelSeconds
	r.ObservedSeconds = time.Since(start).Seconds()
	state, waitErr := windows.WaitForSingleObject(h, 0)
	if waitErr != nil || (state != uint32(windows.WAIT_TIMEOUT) && state != windows.WAIT_OBJECT_0) {
		r.Error = fmt.Sprintf("thread exit state unavailable: state=%d error=%v", state, waitErr)
		r.ErrorCode = windowsErrorCode(waitErr)
		return r
	}
	r.Exited = state == windows.WAIT_OBJECT_0
	if r.StartToken == "0" {
		r.Error = "thread creation identity was zero"
	}
	return r
}

func windowsErrorCode(err error) uint32 {
	var code syscall.Errno
	if errors.As(err, &code) {
		return uint32(code)
	}
	return 0
}
