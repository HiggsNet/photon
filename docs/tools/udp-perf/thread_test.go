package main

import (
	"runtime"
	"testing"
)

func TestThreadHistoryDoesNotMergeReusedIDsOrMissingCounters(t *testing.T) {
	var h threadHistory
	observe := func(threads ...threadSample) processSample {
		s := processSample{Threads: &threadObservation{Threads: threads, EnumerationComplete: true}}
		h.observe(&s)
		return s
	}
	one := observe(threadSample{TID: 7, StartToken: "134049600000000001", CPUSeconds: 10})
	if !one.Threads.Threads[0].FirstSeen {
		t.Fatal("first observation not marked")
	}
	two := observe(threadSample{TID: 7, StartToken: "134049600000000001", CPUSeconds: 11})
	if two.Threads.Threads[0].FirstSeen || len(two.Threads.Missing) != 0 {
		t.Fatal("same identity counted as new or missing")
	}
	three := observe(threadSample{TID: 7, StartToken: "134049600000000003", CPUSeconds: 0.01})
	if !three.Threads.Threads[0].FirstSeen || len(three.Threads.Missing) != 1 || three.Threads.Missing[0].StartToken != "134049600000000001" {
		t.Fatal("reused TID merged across creation tokens")
	}
	four := observe(threadSample{TID: 7, Error: "thread exited during OpenThread"})
	if len(four.Threads.Missing) != 1 || four.Threads.Threads[0].FirstSeen {
		t.Fatal("missing counter converted to a zero-CPU observation")
	}
	five := observe(threadSample{TID: 7, StartToken: "134049600000000003", CPUSeconds: 0.02})
	if five.Threads.Threads[0].FirstSeen {
		t.Fatal("previously observed identity treated as new after gap")
	}
}

func TestThreadSamplingOptInAndGeneratorMetadata(t *testing.T) {
	o := options{mode: "client", local: "127.0.0.1", remote: "127.0.0.1", port: 19100, flows: 1, window: 64, payload: 1200, seconds: 1, deadlineMS: 1000, maxPackets: 8000000, threadCPU: true}
	if o.validate() == nil {
		t.Fatal("thread sampling accepted without owned process PID")
	}
	o.pid = 1
	if err := o.validate(); err != nil {
		t.Fatal(err)
	}
	o.mode = "echo"
	if o.validate() == nil {
		t.Fatal("thread sampling accepted echo mode")
	}
	o.mode = "client"
	r := metadata(o)
	if r.GeneratorGOMAXPROCS != runtime.GOMAXPROCS(0) || r.LogicalCPUs != runtime.NumCPU() || r.SampleIntervalMS != 250 || !r.ThreadCPUSampling {
		t.Fatal("actual runtime metadata missing")
	}
	if r.GeneratorAffinity.Error == "" && (!r.GeneratorAffinity.Complete || r.GeneratorAffinity.CPUCountLowerBound <= 0 || r.GeneratorAffinity.CPUCountUpperBound < r.GeneratorAffinity.CPUCountLowerBound) {
		t.Fatal("invalid affinity without explicit error")
	}
}
