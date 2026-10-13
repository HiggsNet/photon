package main

import (
	"os"
	"testing"
	"time"
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
