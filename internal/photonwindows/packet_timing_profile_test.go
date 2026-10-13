//go:build photon_profile

package photonwindows

import (
	"encoding/json"
	"math"
	"sync"
	"testing"
)

func startPacketTimingTest(t *testing.T, enabled bool) {
	t.Helper()
	if err := StartFixturePacketTiming(enabled); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { StopFixturePacketTiming() })
}

func finishPacketTimingBusiness(trace *fixturePacketTiming) {
	trace.Dequeue()
	trace.MarkAESBegin()
	trace.MarkAESEnd()
	// Classification intentionally follows crypto; prior stage observations must
	// also belong to business rather than pre-authentication unknown traffic.
	trace.Classify(fixturePacketTimingBusiness)
	trace.MarkDeliveryBegin()
	trace.MarkDeliveryEnd()
	trace.Finish(fixturePacketTimingDelivered)
}

func assertPacketTimingHist(t *testing.T, h FixturePacketTimingHistogram, count uint64) {
	t.Helper()
	var sum uint64
	for _, bucket := range h.Buckets {
		sum += bucket
	}
	if h.Count != count || sum != count || (count != 0 && (h.MinNS > h.MaxNS || h.SumNS < h.MaxNS)) {
		t.Fatalf("histogram count/bounds inconsistent: %+v", h)
	}
}

func TestFixturePacketTimingDisabledSchemaAndOverlap(t *testing.T) {
	startPacketTimingTest(t, false)
	if err := StartFixturePacketTiming(true); err == nil {
		t.Fatal("overlapping capture accepted")
	}
	for range 512 {
		trace := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
		finishPacketTimingBusiness(&trace)
	}
	report := StopFixturePacketTiming()
	if report.SchemaVersion != 1 || report.Enabled || report.Epoch == 0 || report.FrequencyHz == 0 || report.SampleEvery != 256 || report.HistogramUnit != "nanoseconds" || report.Clock == "" {
		t.Fatalf("disabled metadata missing: %+v", report)
	}
	for _, direction := range report.Directions {
		if direction.Selected != 0 || direction.Finished != 0 || direction.Unfinished != 0 {
			t.Fatal("disabled capture counted packets")
		}
		for _, class := range direction.Classes {
			if class.Outcomes != (FixturePacketTimingOutcomes{}) {
				t.Fatal("disabled capture counted outcomes")
			}
			for _, hist := range class.Stages.histograms() {
				assertPacketTimingHist(t, *hist, 0)
			}
		}
	}
	data, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	var decoded map[string]json.RawMessage
	if err := json.Unmarshal(data, &decoded); err != nil || len(decoded) != 11 || decoded["schema_version"] == nil || decoded["directions"] == nil {
		t.Fatal("JSON schema not fixed snake_case", string(data), err)
	}
}

func TestFixturePacketTimingSparseDirectionsAndLateClassification(t *testing.T) {
	startPacketTimingTest(t, true)
	for _, direction := range []fixturePacketTimingDirection{fixturePacketTimingOutbound, fixturePacketTimingInbound} {
		for range 512 {
			trace := beginFixturePacketTimingQueue(direction)
			finishPacketTimingBusiness(&trace)
			trace.Finish(fixturePacketTimingDelivered) // same owned trace is inert
		}
	}
	report := StopFixturePacketTiming()
	if !report.Enabled || report.ClockErrors != 0 || report.InvalidSamples != 0 {
		t.Fatal("valid sparse capture reported errors")
	}
	for _, direction := range report.Directions {
		if direction.Selected != 2 || direction.Finished != 2 || direction.Unfinished != 0 {
			t.Fatalf("wrong 1/256 direction selection: %+v", direction)
		}
		business := direction.Classes[fixturePacketTimingBusiness]
		if business.Outcomes.Delivered != 2 || direction.Classes[fixturePacketTimingUnknown].Outcomes != (FixturePacketTimingOutcomes{}) {
			t.Fatal("late class did not apply to all observations")
		}
		for _, h := range business.Stages.histograms() {
			assertPacketTimingHist(t, *h, 2)
		}
	}
}

func TestFixturePacketTimingEpochFreezeRejectsLateQueueAndOwner(t *testing.T) {
	startPacketTimingTest(t, true)
	oldQueued := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
	oldOwner := beginFixturePacketTimingQueue(fixturePacketTimingInbound)
	oldOwner.Dequeue()
	oldOwner.MarkAESBegin()
	frozen := StopFixturePacketTiming()
	if frozen.Directions[0].Unfinished != 1 || frozen.Directions[1].Unfinished != 1 {
		t.Fatal("selected in-flight observations not retained as unfinished")
	}
	before := frozen
	if err := StartFixturePacketTiming(true); err != nil {
		t.Fatal(err)
	}
	if oldQueued.Sampled() || oldOwner.Sampled() {
		t.Fatal("old sample considered current")
	}
	finishPacketTimingBusiness(&oldQueued)
	oldOwner.MarkAESEnd()
	oldOwner.Finish(fixturePacketTimingCryptoError)
	newTrace := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
	finishPacketTimingBusiness(&newTrace)
	next := StopFixturePacketTiming()
	if next.Epoch == frozen.Epoch || next.Directions[0].Finished != 1 || next.Directions[1].Selected != 0 || next.InvalidSamples != 0 || frozen != before {
		t.Fatal("late records changed frozen or next-epoch snapshot")
	}
}

func TestFixturePacketTimingFailureCoverageAndNoInventedQueueWait(t *testing.T) {
	startPacketTimingTest(t, true)
	for _, outcome := range []fixturePacketTimingOutcome{fixturePacketTimingQueueRejected, fixturePacketTimingCanceled, fixturePacketTimingRejected, fixturePacketTimingCryptoError, fixturePacketTimingDeliveryError} {
		run := activeFixturePacketTiming.Load()
		run.next[fixturePacketTimingInbound].Store(0)
		trace := beginFixturePacketTimingQueue(fixturePacketTimingInbound)
		trace.Classify(fixturePacketTimingControl)
		switch outcome {
		case fixturePacketTimingQueueRejected:
			trace.QueueRejected()
			continue
		case fixturePacketTimingCanceled:
			// A shutdown drain has never entered the owner.
		case fixturePacketTimingRejected:
			trace.Dequeue()
		case fixturePacketTimingCryptoError:
			trace.Dequeue()
			trace.MarkAESBegin()
			trace.MarkAESEnd()
		case fixturePacketTimingDeliveryError:
			trace.Dequeue()
			trace.MarkAESBegin()
			trace.MarkAESEnd()
			trace.MarkDeliveryBegin()
			trace.MarkDeliveryEnd()
		}
		trace.Finish(outcome)
	}
	report := StopFixturePacketTiming()
	d := report.Directions[fixturePacketTimingInbound]
	c := d.Classes[fixturePacketTimingControl]
	if d.Selected != 5 || d.Finished != 5 || d.Unfinished != 0 || c.Outcomes != (FixturePacketTimingOutcomes{Rejected: 1, CryptoError: 1, DeliveryError: 1, QueueRejected: 1, Canceled: 1}) || report.InvalidSamples != 0 {
		t.Fatalf("failure outcomes inconsistent: %+v", d)
	}
	assertPacketTimingHist(t, c.Stages.QueueWait, 3)
	assertPacketTimingHist(t, c.Stages.OwnerTotal, 3)
	assertPacketTimingHist(t, c.Stages.Precheck, 3)
	assertPacketTimingHist(t, c.Stages.AES, 2)
	assertPacketTimingHist(t, c.Stages.FreshGate, 2)
	assertPacketTimingHist(t, c.Stages.Delivery, 1)
}

func TestFixturePacketTimingInvalidClockAndOverflowCannotPartiallyRecord(t *testing.T) {
	startPacketTimingTest(t, true)
	run := activeFixturePacketTiming.Load()
	trace := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
	trace.queued = math.MaxInt64 // simulate an invalid cross-clock/regressing stamp
	trace.Dequeue()
	trace.Finish(fixturePacketTimingRejected)
	run.next[fixturePacketTimingOutbound].Store(0)
	trace = beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
	trace.Dequeue()
	trace.MarkAESBegin()
	trace.MarkAESEnd()
	trace.ticks[fixtureTimingAES] = math.MaxUint64
	run.clock.frequency = 1 // force conversion overflow on every platform
	trace.Finish(fixturePacketTimingCryptoError)
	report := StopFixturePacketTiming()
	d := report.Directions[0]
	if report.InvalidSamples != 2 || d.Selected != 2 || d.Finished != 0 || d.Unfinished != 2 {
		t.Fatalf("invalid samples hidden: %+v", report)
	}
	for _, class := range d.Classes {
		for _, h := range class.Stages.histograms() {
			assertPacketTimingHist(t, *h, 0)
		}
	}
}

func TestFixturePacketTimingConcurrentStopHasIndependentSnapshot(t *testing.T) {
	startPacketTimingTest(t, true)
	var wg sync.WaitGroup
	begin := make(chan struct{})
	ready := make(chan struct{}, 2)
	for _, direction := range []fixturePacketTimingDirection{fixturePacketTimingOutbound, fixturePacketTimingInbound} {
		wg.Add(1)
		go func(direction fixturePacketTimingDirection) {
			defer wg.Done()
			trace := beginFixturePacketTimingQueue(direction)
			trace.Dequeue()
			ready <- struct{}{}
			<-begin
			trace.MarkAESBegin()
			trace.MarkAESEnd()
			trace.Finish(fixturePacketTimingCryptoError)
			for range 1024 {
				trace := beginFixturePacketTimingQueue(direction)
				finishPacketTimingBusiness(&trace)
			}
		}(direction)
	}
	<-ready
	<-ready
	close(begin)
	frozen := StopFixturePacketTiming()
	copy := frozen
	if err := StartFixturePacketTiming(true); err != nil {
		t.Fatal(err)
	}
	wg.Wait()
	StopFixturePacketTiming()
	if frozen != copy {
		t.Fatal("returned snapshot contains mutable window references")
	}
	for _, d := range frozen.Directions {
		if d.Selected != d.Finished+d.Unfinished {
			t.Fatal("stop accounting is not conserved")
		}
	}
}

func TestFixturePacketTimingProbeAllocations(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		if err := StartFixturePacketTiming(enabled); err != nil {
			t.Fatal(err)
		}
		run := fixturePacketTimingState.current
		allocs := testing.AllocsPerRun(100, func() {
			run.next[fixturePacketTimingOutbound].Store(0) // exercise every sampled clock/record path
			trace := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
			finishPacketTimingBusiness(&trace)
		})
		report := StopFixturePacketTiming()
		if allocs != 0 || report.ClockErrors != 0 || report.InvalidSamples != 0 {
			t.Fatalf("enabled=%v: probe allocations=%v, clock/errors=%v/%v", enabled, allocs, report.ClockErrors, report.InvalidSamples)
		}
	}
}

func BenchmarkFixturePacketTimingClockRead(b *testing.B) {
	if err := StartFixturePacketTiming(true); err != nil {
		b.Fatal(err)
	}
	run := activeFixturePacketTiming.Load()
	b.Cleanup(func() { StopFixturePacketTiming() })
	b.ReportAllocs()
	var failed bool
	for b.Loop() {
		run.mu.Lock()
		_, ok := run.clock.read()
		run.mu.Unlock()
		failed = failed || !ok
	}
	if failed {
		b.Fatal("clock read failed")
	}
}

func BenchmarkFixturePacketTimingHooks(b *testing.B) {
	for _, mode := range []string{"off", "on_sampled", "on_sparse_256"} {
		b.Run(mode, func(b *testing.B) {
			if err := StartFixturePacketTiming(mode != "off"); err != nil {
				b.Fatal(err)
			}
			run := fixturePacketTimingState.current
			b.Cleanup(func() { StopFixturePacketTiming() })
			b.ReportAllocs()
			for b.Loop() {
				if mode == "on_sampled" {
					run.next[fixturePacketTimingOutbound].Store(0)
				}
				trace := beginFixturePacketTimingQueue(fixturePacketTimingOutbound)
				finishPacketTimingBusiness(&trace)
			}
		})
	}
}
