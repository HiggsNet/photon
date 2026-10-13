package main

import (
	"errors"
	"syscall"
	"time"
)

type processSample struct {
	Seconds, CPUSeconds           float64
	PrivateBytes, WorkingSetBytes uint64
	StartToken                    uint64
}

func currentCPUSeconds() (float64, error) {
	var usage syscall.Rusage
	err := syscall.Getrusage(syscall.RUSAGE_SELF, &usage)
	return float64(usage.Utime.Sec+usage.Stime.Sec) + float64(usage.Utime.Usec+usage.Stime.Usec)/1e6, err
}
func sampleProcess(pid int, start time.Time) (processSample, error) {
	return processSample{}, errors.New("service sampling is Windows-only")
}
