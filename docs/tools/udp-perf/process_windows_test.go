package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/windows"
)

func TestCurrentProcessSamples(t *testing.T) {
	start := time.Now()
	one, err := sampleProcess(os.Getpid(), start)
	if err != nil {
		t.Fatal(err)
	}
	two, err := sampleProcess(os.Getpid(), start)
	if err != nil {
		t.Fatal(err)
	}
	if one.StartToken == 0 || two.StartToken != one.StartToken || two.CPUSeconds < one.CPUSeconds || one.PrivateBytes == 0 || one.WorkingSetBytes == 0 {
		t.Fatalf("invalid current process samples: %+v %+v", one, two)
	}
}

func TestThreadCPUSamplesObserveRealBusyThread(t *testing.T) {
	var stop atomic.Bool
	ready := make(chan uint32, 1)
	done := make(chan struct{})
	go func() {
		runtime.LockOSThread()
		defer close(done)
		ready <- windows.GetCurrentThreadId()
		// Exiting while locked terminates this actual OS thread.
		for !stop.Load() {
		}
	}()
	tid := <-ready
	defer func() { stop.Store(true); <-done }()
	retained, err := windows.OpenThread(windows.THREAD_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, tid)
	if err != nil {
		t.Fatal(err)
	}
	defer windows.CloseHandle(retained)
	start := time.Now()
	one, err := sampleProcessMode(os.Getpid(), start, true)
	if err != nil {
		t.Fatal(err)
	}
	first := sampleThread(uint32(os.Getpid()), tid, start)
	if first.Error != "" || first.Exited || first.StartToken == "" {
		t.Fatalf("busy thread not alive/identified: %+v", first)
	}
	deadline := time.Now().Add(2 * time.Second)
	var last threadSample
	for time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
		last = sampleThread(uint32(os.Getpid()), tid, start)
		if last.Error != "" || last.StartToken != first.StartToken || last.Exited {
			t.Fatalf("busy thread identity changed: %+v", last)
		}
		if last.CPUSeconds-first.CPUSeconds >= 0.015 {
			break
		}
	}
	two, err := sampleProcessMode(os.Getpid(), start, true)
	if err != nil {
		t.Fatal(err)
	}
	if last.CPUSeconds-first.CPUSeconds < 0.015 || two.CPUSeconds <= one.CPUSeconds || two.StartToken != one.StartToken {
		t.Fatal("real busy work not reflected in thread/process CPU")
	}
	if last.UserSeconds < first.UserSeconds || last.KernelSeconds < first.KernelSeconds || last.CPUSeconds != last.UserSeconds+last.KernelSeconds {
		t.Fatal("invalid user/kernel cumulative times")
	}
	if two.Affinity == nil || two.Affinity.Error != "" || !two.Affinity.Complete || two.Affinity.ProcessGroupCount != 1 || two.Affinity.CPUCountLowerBound < 1 {
		t.Fatalf("invalid native affinity: %+v", two.Affinity)
	}
	if two.Threads == nil || !two.Threads.EnumerationComplete || len(two.Threads.Threads) == 0 {
		t.Fatalf("missing real thread enumeration: %+v", two.Threads)
	}
	found := false
	for _, sample := range two.Threads.Threads {
		if sample.TID == tid && sample.StartToken == first.StartToken && sample.Error == "" {
			found = true
		}
	}
	if !found {
		t.Fatal("real busy thread absent from actual process snapshot")
	}
	// Another owner must never accept this real TID merely because it was enumerated.
	foreign := sampleThread(uint32(os.Getpid())+1, tid, start)
	if foreign.Error == "" || foreign.StartToken != "" {
		t.Fatal("foreign process thread accepted")
	}
	t.Logf("busy TID=%d creation=%s threadCPUdelta=%f processCPUdelta=%f affinity=%+v", tid, first.StartToken, last.CPUSeconds-first.CPUSeconds, two.CPUSeconds-one.CPUSeconds, *two.Affinity)
	stop.Store(true)
	<-done
	state, err := windows.WaitForSingleObject(retained, 5000)
	if err != nil || state != windows.WAIT_OBJECT_0 {
		t.Fatalf("actual locked worker thread did not exit: %d %v", state, err)
	}
	retired := readThreadHandle(retained, uint32(os.Getpid()), tid, start)
	if retired.Error != "" || !retired.Exited || retired.StartToken != first.StartToken || retired.CPUSeconds < last.CPUSeconds {
		t.Fatalf("retained exited thread identity/counters unavailable: %+v", retired)
	}
}

func TestProcessSamplingRejectsExitedChild(t *testing.T) {
	if os.Getenv("PHOTON_THREAD_SAMPLE_CHILD") == "1" {
		ready := os.Getenv("PHOTON_THREAD_SAMPLE_READY")
		if err := os.WriteFile(ready, []byte("ready\n"), 0600); err != nil {
			os.Exit(2)
		}
		for {
			if _, err := os.Stat(ready + ".stop"); err == nil {
				os.Exit(0)
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	ready := filepath.Join(t.TempDir(), "child.ready")
	child := exec.Command(exe, "-test.run=^TestProcessSamplingRejectsExitedChild$", "-test.count=1")
	child.Env = append(os.Environ(), "PHOTON_THREAD_SAMPLE_CHILD=1", "PHOTON_THREAD_SAMPLE_READY="+ready)
	if err := child.Start(); err != nil {
		t.Fatal(err)
	}
	waited := false
	defer func() {
		if !waited {
			_ = child.Process.Kill()
			_ = child.Wait()
		}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("native child did not become ready")
		}
		time.Sleep(10 * time.Millisecond)
	}
	live, err := sampleProcessMode(child.Process.Pid, time.Now(), true)
	if err != nil || live.StartToken == 0 || live.Threads == nil || len(live.Threads.Threads) == 0 {
		t.Fatalf("live child not sampled: %+v %v", live, err)
	}
	if err := os.WriteFile(ready+".stop", []byte("stop\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := child.Wait(); err != nil {
		t.Fatal(err)
	}
	waited = true
	if sample, err := sampleProcessMode(child.Process.Pid, time.Now(), true); err == nil {
		t.Fatalf("exited child accepted as zero/current CPU: %+v", sample)
	}
}
