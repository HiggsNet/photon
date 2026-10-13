package main

import (
	"errors"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

func currentCPUSeconds() (float64, error) {
	var usage syscall.Rusage
	err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6, err
}
func sampleProcess(pid int, start time.Time) (processSample, error) {
	return processSample{}, errors.New("service sampling is Windows-only")
}

func sampleProcessMode(pid int, start time.Time, threads bool) (processSample, error) {
	return sampleProcess(pid, start)
}

func currentAffinity() affinitySample {
	var cpus unix.CPUSet
	if err := unix.SchedGetaffinity(0, &cpus); err != nil {
		return affinitySample{Error: err.Error()}
	}
	r := affinitySample{Complete: true, ProcessGroupCount: 1, SystemGroupCount: 1}
	for cpu := 0; cpu < len(cpus)*64; cpu++ {
		if cpus.IsSet(cpu) {
			r.CPUs = append(r.CPUs, cpu)
		}
	}
	r.CPUCountLowerBound, r.CPUCountUpperBound = len(r.CPUs), len(r.CPUs)
	return r
}
