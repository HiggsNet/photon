//go:build photon_profile

package photonwindows

import (
	"errors"
	"math"
	"math/bits"
	"sync"
	"sync/atomic"
)

const fixturePacketTimingSampleEvery = 256

const (
	fixtureTimingQueue = iota
	fixtureTimingPrecheck
	fixtureTimingAES
	fixtureTimingFresh
	fixtureTimingDelivery
	fixtureTimingOwner
	fixtureTimingStageCount
)

const (
	fixtureTimingUDPWriter = iota
	fixtureTimingUDPValidation
	fixtureTimingUDPDeadline
	fixtureTimingUDPWrite
	fixtureTimingUDPStageCount
)

// A stamp contains only scalars. It borrows no packet, SA, address, or window
// pointer, and is invalid outside its originating capture epoch. Stage ticks
// remain local until Finish so late business/control classification applies to
// the queue and AES observations too.
type fixturePacketTiming struct {
	epoch     uint64
	queued    int64
	owner     int64
	mark      int64
	ticks     [fixtureTimingOwner]uint64
	udpMark   int64
	udpTicks  [fixtureTimingUDPStageCount]uint64
	direction fixturePacketTimingDirection
	class     fixturePacketTimingClass
	phase     uint8
	valid     uint8
	udpValid  uint8
}

// All durations are elapsed time, including sampled probe/scheduler waits;
// they are neither CPU time nor an estimate of uninstrumented packet latency.
type FixturePacketTimingHistogram struct {
	Count   uint64     `json:"count"`
	SumNS   uint64     `json:"sum_ns"`
	MinNS   uint64     `json:"min_ns"`
	MaxNS   uint64     `json:"max_ns"`
	Buckets [64]uint64 `json:"buckets"`
}

type FixturePacketTimingStages struct {
	QueueWait  FixturePacketTimingHistogram `json:"queue_wait"`
	Precheck   FixturePacketTimingHistogram `json:"precheck"`
	AES        FixturePacketTimingHistogram `json:"aes"`
	FreshGate  FixturePacketTimingHistogram `json:"fresh_gate"`
	Delivery   FixturePacketTimingHistogram `json:"delivery"`
	OwnerTotal FixturePacketTimingHistogram `json:"owner_total"`
}

type FixturePacketTimingOutcomes struct {
	Delivered     uint64 `json:"delivered"`
	Rejected      uint64 `json:"rejected"`
	CryptoError   uint64 `json:"crypto_error"`
	DeliveryError uint64 `json:"delivery_error"`
	QueueRejected uint64 `json:"queue_rejected"`
	Canceled      uint64 `json:"canceled"`
}

type FixturePacketTimingClassReport struct {
	Class       string                         `json:"class"`
	Outcomes    FixturePacketTimingOutcomes    `json:"outcomes"`
	Stages      FixturePacketTimingStages      `json:"stages"`
	UDPDelivery FixturePacketTimingUDPDelivery `json:"udp_delivery"`
}

// These sub-stages partition only the observed part inside sampled WriteTunnel.
// Parent delivery also includes the return/unlock tail. Wintun and control
// delivery leave these histograms empty.
type FixturePacketTimingUDPDelivery struct {
	WriterLockWait  FixturePacketTimingHistogram `json:"writer_lock_wait"`
	ValidationState FixturePacketTimingHistogram `json:"validation_state"`
	Deadline        FixturePacketTimingHistogram `json:"deadline"`
	UDPWrite        FixturePacketTimingHistogram `json:"udp_write"`
}

type FixturePacketTimingDirectionReport struct {
	Direction  string                            `json:"direction"`
	Selected   uint64                            `json:"selected"`
	Finished   uint64                            `json:"finished"`
	Unfinished uint64                            `json:"unfinished"`
	Classes    [3]FixturePacketTimingClassReport `json:"classes"`
}

// Arrays bound memory and make Stop's by-value result independent of all late
// producers/owners. No live maps, slices, or pointers are exported.
type FixturePacketTiming struct {
	SchemaVersion       int                                   `json:"schema_version"`
	Enabled             bool                                  `json:"enabled"`
	Epoch               uint64                                `json:"epoch"`
	Clock               string                                `json:"clock"`
	FrequencyHz         uint64                                `json:"frequency_hz"`
	SampleEvery         uint64                                `json:"sample_every"`
	HistogramUnit       string                                `json:"histogram_unit"`
	BucketUpperBoundsNS [64]uint64                            `json:"bucket_upper_bounds_ns"`
	Directions          [2]FixturePacketTimingDirectionReport `json:"directions"`
	ClockErrors         uint64                                `json:"clock_errors"`
	InvalidSamples      uint64                                `json:"invalid_samples"`
}

type fixturePacketTimingRun struct {
	mu     sync.Mutex // clock scratch and sampled records only
	closed bool
	clock  fixturePacketTimingClock
	next   [2]atomic.Uint64
	report FixturePacketTiming
}

var fixturePacketTimingState struct {
	mu      sync.Mutex
	epoch   uint64
	current *fixturePacketTimingRun // includes an explicitly disabled window
}
var activeFixturePacketTiming atomic.Pointer[fixturePacketTimingRun]

func newFixturePacketTimingReport(enabled bool, epoch uint64, clock *fixturePacketTimingClock) FixturePacketTiming {
	r := FixturePacketTiming{SchemaVersion: 2, Enabled: enabled, Epoch: epoch,
		Clock: clock.name(), FrequencyHz: clock.frequency,
		SampleEvery: fixturePacketTimingSampleEvery, HistogramUnit: "nanoseconds"}
	for i := range r.BucketUpperBoundsNS {
		r.BucketUpperBoundsNS[i] = uint64(1) << i
	}
	r.BucketUpperBoundsNS[63] = math.MaxUint64
	for i, direction := range [...]string{"outbound", "inbound"} {
		r.Directions[i].Direction = direction
		for j, class := range [...]string{"unknown", "business", "control"} {
			r.Directions[i].Classes[j].Class = class
		}
	}
	return r
}

// StartFixturePacketTiming reserves one capture window. Disabled captures still
// initialize clock/schema metadata, but publish no active packet probe state.
func StartFixturePacketTiming(enabled bool) error {
	fixturePacketTimingState.mu.Lock()
	defer fixturePacketTimingState.mu.Unlock()
	if fixturePacketTimingState.current != nil {
		return errors.New("fixture packet timing: capture already active")
	}
	clock, err := newFixturePacketTimingClock()
	if err != nil {
		return err
	}
	if fixturePacketTimingState.epoch == math.MaxUint64 {
		return errors.New("fixture packet timing: epoch exhausted")
	}
	fixturePacketTimingState.epoch++
	r := &fixturePacketTimingRun{clock: clock}
	r.report = newFixturePacketTimingReport(enabled, fixturePacketTimingState.epoch, &r.clock)
	fixturePacketTimingState.current = r
	if enabled {
		activeFixturePacketTiming.Store(r)
	}
	return nil
}

// StopFixturePacketTiming withdraws new probes before freezing sampled records.
// In-flight or queued selected samples that have not finished are Unfinished;
// old stamps cannot write to a later capture. A call without Start returns the
// zero value rather than inventing a clock/window.
func StopFixturePacketTiming() FixturePacketTiming {
	fixturePacketTimingState.mu.Lock()
	defer fixturePacketTimingState.mu.Unlock()
	r := fixturePacketTimingState.current
	if r == nil {
		return FixturePacketTiming{}
	}
	activeFixturePacketTiming.CompareAndSwap(r, nil)
	r.mu.Lock()
	r.closed = true
	for i := range r.report.Directions {
		d := &r.report.Directions[i]
		d.Unfinished = d.Selected - d.Finished
	}
	report := r.report
	r.mu.Unlock()
	fixturePacketTimingState.current = nil
	return report
}

// Source-side selection avoids QPC and sampled locking for 255 of 256 events.
// The stamp is made immediately before admission. QueueRejected records a
// selected failed admission without falsely adding a queue-wait measurement.
func beginFixturePacketTimingQueue(direction fixturePacketTimingDirection) fixturePacketTiming {
	r := activeFixturePacketTiming.Load()
	if r == nil || direction > fixturePacketTimingInbound || (r.next[direction].Add(1)-1)%fixturePacketTimingSampleEvery != 0 {
		return fixturePacketTiming{}
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return fixturePacketTiming{}
	}
	tick, ok := r.clock.read()
	if !ok {
		r.report.ClockErrors++
		return fixturePacketTiming{}
	}
	r.report.Directions[direction].Selected++
	return fixturePacketTiming{epoch: r.report.Epoch, queued: tick, direction: direction}
}

func (t fixturePacketTiming) Sampled() bool {
	if t.epoch == 0 {
		return false
	}
	r := activeFixturePacketTiming.Load()
	return r != nil && r.report.Epoch == t.epoch
}

func (t *fixturePacketTiming) Classify(class fixturePacketTimingClass) {
	if t.epoch != 0 && class <= fixturePacketTimingControl {
		t.class = class
	}
}

func (t *fixturePacketTiming) currentLocked() *fixturePacketTimingRun {
	if t.epoch == 0 {
		return nil
	}
	r := activeFixturePacketTiming.Load()
	if r == nil || r.report.Epoch != t.epoch {
		return nil
	}
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return nil
	}
	return r
}

func (t *fixturePacketTiming) failLocked(r *fixturePacketTimingRun) {
	r.report.InvalidSamples++
	t.epoch = 0
}

func (t *fixturePacketTiming) readLocked(r *fixturePacketTimingRun) (int64, bool) {
	tick, ok := r.clock.read()
	if !ok {
		r.report.ClockErrors++
		t.epoch = 0
	}
	return tick, ok
}

func (t *fixturePacketTiming) endStageLocked(r *fixturePacketTimingRun, stage int, tick int64) bool {
	if tick < t.mark || t.valid&(1<<stage) != 0 {
		t.failLocked(r)
		return false
	}
	t.ticks[stage] = uint64(tick) - uint64(t.mark)
	t.valid |= 1 << stage
	t.mark = tick
	return true
}

func (t *fixturePacketTiming) Dequeue() {
	r := t.currentLocked()
	if r == nil {
		return
	}
	defer r.mu.Unlock()
	if t.phase != 0 {
		t.failLocked(r)
		return
	}
	tick, ok := t.readLocked(r)
	if !ok {
		return
	}
	t.mark = t.queued
	if t.endStageLocked(r, fixtureTimingQueue, tick) {
		t.owner, t.phase = tick, fixtureTimingPrecheck
	}
}

func (t *fixturePacketTiming) advance(want, next uint8) {
	r := t.currentLocked()
	if r == nil {
		return
	}
	defer r.mu.Unlock()
	if t.phase != want {
		t.failLocked(r)
		return
	}
	tick, ok := t.readLocked(r)
	if ok && t.endStageLocked(r, int(want), tick) {
		t.phase = next
	}
}

func (t *fixturePacketTiming) MarkAESBegin() { t.advance(fixtureTimingPrecheck, fixtureTimingAES) }

// FreshGate starts at crypto completion and includes plaintext classification,
// the return to the owner, the current snapshot, and the final permission gate.
func (t *fixturePacketTiming) MarkAESEnd() { t.advance(fixtureTimingAES, fixtureTimingFresh) }
func (t *fixturePacketTiming) MarkDeliveryBegin() {
	t.advance(fixtureTimingFresh, fixtureTimingDelivery)
}
func (t *fixturePacketTiming) MarkDeliveryEnd() { t.advance(fixtureTimingDelivery, fixtureTimingOwner) }

// The first sub-stage reuses delivery's begin stamp, including the small call
// entry/defer prologue before writeMu is acquired. No extra entry clock is read.
// Only the synchronous business owner lends this trace to the socket writer.
func (t *fixturePacketTiming) markUDPStage(stage uint8) {
	r := t.currentLocked()
	if r == nil {
		return
	}
	defer r.mu.Unlock()
	if stage >= fixtureTimingUDPStageCount || t.phase != fixtureTimingDelivery || t.udpValid != (1<<stage)-1 {
		t.failLocked(r)
		return
	}
	tick, ok := t.readLocked(r)
	if !ok {
		return
	}
	mark := t.udpMark
	if stage == fixtureTimingUDPWriter {
		mark = t.mark
	}
	if tick < mark {
		t.failLocked(r)
		return
	}
	t.udpTicks[stage] = uint64(tick) - uint64(mark)
	t.udpMark = tick
	t.udpValid |= 1 << stage
}

func (t *fixturePacketTiming) MarkUDPWriterAcquired() { t.markUDPStage(fixtureTimingUDPWriter) }
func (t *fixturePacketTiming) MarkUDPValidationDone() { t.markUDPStage(fixtureTimingUDPValidation) }
func (t *fixturePacketTiming) MarkUDPDeadlineDone()   { t.markUDPStage(fixtureTimingUDPDeadline) }
func (t *fixturePacketTiming) MarkUDPWriteDone()      { t.markUDPStage(fixtureTimingUDPWrite) }

func (t *fixturePacketTiming) QueueRejected() { t.Finish(fixturePacketTimingQueueRejected) }

func fixtureTimingNanoseconds(ticks, frequency uint64) (uint64, bool) {
	if frequency == 0 {
		return 0, false
	}
	hi, lo := bits.Mul64(ticks, 1_000_000_000)
	if hi >= frequency {
		return 0, false
	}
	ns, _ := bits.Div64(hi, lo, frequency)
	return ns, true
}

func (h *FixturePacketTimingHistogram) add(ns uint64) {
	if h.Count == 0 || ns < h.MinNS {
		h.MinNS = ns
	}
	if ns > h.MaxNS {
		h.MaxNS = ns
	}
	h.Count++
	h.SumNS += ns
	var bucket int
	if ns == 0 {
		bucket = 0
	} else {
		bucket = bits.Len64(ns - 1)
	}
	if bucket > 63 {
		bucket = 63
	}
	h.Buckets[bucket]++
}

func (s *FixturePacketTimingStages) histograms() [fixtureTimingStageCount]*FixturePacketTimingHistogram {
	return [fixtureTimingStageCount]*FixturePacketTimingHistogram{&s.QueueWait, &s.Precheck, &s.AES, &s.FreshGate, &s.Delivery, &s.OwnerTotal}
}

func (s *FixturePacketTimingUDPDelivery) histograms() [fixtureTimingUDPStageCount]*FixturePacketTimingHistogram {
	return [fixtureTimingUDPStageCount]*FixturePacketTimingHistogram{&s.WriterLockWait, &s.ValidationState, &s.Deadline, &s.UDPWrite}
}

func (o *FixturePacketTimingOutcomes) increment(outcome fixturePacketTimingOutcome) {
	switch outcome {
	case fixturePacketTimingDelivered:
		o.Delivered++
	case fixturePacketTimingRejected:
		o.Rejected++
	case fixturePacketTimingCryptoError:
		o.CryptoError++
	case fixturePacketTimingDeliveryError:
		o.DeliveryError++
	case fixturePacketTimingQueueRejected:
		o.QueueRejected++
	case fixturePacketTimingCanceled:
		o.Canceled++
	}
}

func (t *fixturePacketTiming) Finish(outcome fixturePacketTimingOutcome) {
	r := t.currentLocked()
	if r == nil {
		return
	}
	defer r.mu.Unlock()
	if t.udpValid != 0 && (t.direction != fixturePacketTimingOutbound || t.class != fixturePacketTimingBusiness) {
		t.failLocked(r)
		return
	}
	if outcome > fixturePacketTimingCanceled || (t.phase == 0 && outcome != fixturePacketTimingQueueRejected && outcome != fixturePacketTimingCanceled) || (t.phase != 0 && outcome == fixturePacketTimingQueueRejected) {
		t.failLocked(r)
		return
	}
	var total uint64
	if t.phase != 0 {
		tick, ok := t.readLocked(r)
		if !ok {
			return
		}
		if tick < t.owner || tick < t.mark || (t.phase < fixtureTimingOwner && !t.endStageLocked(r, int(t.phase), tick)) {
			if t.epoch != 0 {
				t.failLocked(r)
			}
			return
		}
		total = uint64(tick) - uint64(t.owner)
	}
	series := &r.report.Directions[t.direction].Classes[t.class]
	hist := series.Stages.histograms()
	udpHist := series.UDPDelivery.histograms()
	var durations [fixtureTimingStageCount]uint64
	var udpDurations [fixtureTimingUDPStageCount]uint64
	valid := t.valid
	if t.phase != 0 {
		valid |= 1 << fixtureTimingOwner
	}
	for stage := range durations {
		if valid&(1<<stage) == 0 {
			continue
		}
		ticks := total
		if stage != fixtureTimingOwner {
			ticks = t.ticks[stage]
		}
		ns, ok := fixtureTimingNanoseconds(ticks, r.clock.frequency)
		if !ok || ns > math.MaxUint64-hist[stage].SumNS {
			t.failLocked(r)
			return
		}
		durations[stage] = ns
	}
	// Convert/check all child observations before recording any parent or child
	// histogram: a bad conversion or overflow cannot partly record the sample.
	for stage, ticks := range t.udpTicks {
		if t.udpValid&(1<<stage) == 0 {
			continue
		}
		ns, ok := fixtureTimingNanoseconds(ticks, r.clock.frequency)
		if !ok || ns > math.MaxUint64-udpHist[stage].SumNS {
			t.failLocked(r)
			return
		}
		udpDurations[stage] = ns
	}
	if t.udpValid != 0 {
		if valid&(1<<fixtureTimingDelivery) == 0 {
			t.failLocked(r)
			return
		}
		// A regressing parent clock can still be after delivery's begin but
		// before the last child end. Budget subtraction also rejects corrupted
		// child totals without ever overflowing an intermediate sum.
		remaining := durations[fixtureTimingDelivery]
		for stage, ns := range udpDurations {
			if t.udpValid&(1<<stage) == 0 {
				continue
			}
			if ns > remaining {
				t.failLocked(r)
				return
			}
			remaining -= ns
		}
	}
	for stage, ns := range durations {
		if valid&(1<<stage) != 0 {
			hist[stage].add(ns)
		}
	}
	series.Outcomes.increment(outcome)
	for stage, ns := range udpDurations {
		if t.udpValid&(1<<stage) != 0 {
			udpHist[stage].add(ns)
		}
	}
	r.report.Directions[t.direction].Finished++
	t.epoch = 0 // repeated Finish on this owned trace is inert
}
