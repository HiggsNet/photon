package health

import (
	"slices"
	"sync"
	"time"
)

// ewmaAlpha is the smoothing factor for EWMA RTT computation.
const ewmaAlpha = 0.3

// sample is a single probe result stored in the rolling window.
type sample struct {
	at       time.Time
	rtt      time.Duration
	sent     int
	received int
	lost     int
	success  bool
}

// RollingWindow keeps a bounded ring buffer of probe results and computes
// derived statistics (loss ratio, RTT percentiles, jitter, EWMA).
type RollingWindow struct {
	mu      sync.Mutex
	samples []sample
	head    int
	count   int
	cap     int
	ewma    time.Duration
	consec  int // consecutive failures
	lastOK  time.Time
	cached  WindowSnapshot
	valid   bool
}

// NewRollingWindow returns a rolling window with the given capacity.
func NewRollingWindow(capacity int) *RollingWindow {
	if capacity < 1 {
		capacity = 1
	}
	return &RollingWindow{
		samples: make([]sample, capacity),
		cap:     capacity,
	}
}

// Record inserts a legacy one-packet probe result into the window.
func (w *RollingWindow) Record(at time.Time, rtt time.Duration, success bool) {
	w.RecordProbe(at, ProbeResult{RTT: rtt, Success: success})
}

// RecordProbe inserts a packet-counted probe burst into the window.
func (w *RollingWindow) RecordProbe(at time.Time, result ProbeResult) {
	result = normalizeProbeResult(result)
	w.mu.Lock()
	defer w.mu.Unlock()
	w.valid = false
	w.samples[w.head] = sample{
		at:       at,
		rtt:      result.RTT,
		sent:     result.Sent,
		received: result.Received,
		lost:     result.Lost,
		success:  result.Success,
	}
	w.head = (w.head + 1) % w.cap
	if w.count < w.cap {
		w.count++
	}
	if result.Success {
		w.consec = 0
	} else {
		w.consec++
	}
	if result.Received > 0 {
		w.lastOK = at
		if result.RTT > 0 {
			if w.ewma == 0 {
				w.ewma = result.RTT
			} else {
				w.ewma = time.Duration(float64(w.ewma)*(1-ewmaAlpha) + float64(result.RTT)*ewmaAlpha)
			}
		}
	}
}

// Snapshot returns aggregate statistics by value. Only RecordProbe and Reset
// change the sample window, so unchanged reads can reuse the computed result.
func (w *RollingWindow) Snapshot() WindowSnapshot {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.valid {
		return w.cached
	}
	snap := WindowSnapshot{
		Bursts:           w.count,
		ConsecutiveFails: w.consec,
		EWMARTT:          w.ewma,
		LastSuccess:      w.lastOK,
	}
	if w.count == 0 {
		w.cached, w.valid = snap, true
		return snap
	}
	rtts := make([]time.Duration, 0, w.count)
	idx := (w.head - w.count + w.cap) % w.cap
	for i := 0; i < w.count; i++ {
		s := w.samples[(idx+i)%w.cap]
		snap.Sent += s.sent
		snap.Received += s.received
		snap.Lost += s.lost
		if s.received > 0 && s.rtt > 0 {
			rtts = append(rtts, s.rtt)
		}
	}
	// LastRTT should be the most recent sample's RTT (success or not).
	last := w.samples[(w.head-1+w.cap)%w.cap]
	if last.received > 0 {
		snap.LastRTT = last.rtt
	} else {
		snap.LastRTT = 0
	}
	if snap.Sent > 0 {
		snap.LossRatio = float64(snap.Lost) / float64(snap.Sent)
	}
	if len(rtts) > 0 {
		// Jitter needs chronological order; the detached scratch slice can
		// then be sorted in place for percentiles without another copy.
		snap.Jitter = computeJitter(rtts)
		slices.Sort(rtts)
		snap.MinRTT = rtts[0]
		snap.MaxRTT = rtts[len(rtts)-1]
		snap.P50RTT = percentile(rtts, 50)
		snap.P95RTT = percentile(rtts, 95)
		snap.P99RTT = percentile(rtts, 99)
	}
	w.cached, w.valid = snap, true
	return snap
}

// WindowSnapshot is the aggregate view of a RollingWindow.
type WindowSnapshot struct {
	Bursts           int
	Sent             int
	Received         int
	Lost             int
	LossRatio        float64
	LastRTT          time.Duration
	EWMARTT          time.Duration
	MinRTT           time.Duration
	MaxRTT           time.Duration
	P50RTT           time.Duration
	P95RTT           time.Duration
	P99RTT           time.Duration
	Jitter           time.Duration
	ConsecutiveFails int
	LastSuccess      time.Time
}

// Reset clears the window.
func (w *RollingWindow) Reset() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.head = 0
	w.count = 0
	w.ewma = 0
	w.consec = 0
	w.lastOK = time.Time{}
	w.valid = false
}

func percentile(sorted []time.Duration, pct int) time.Duration {
	if len(sorted) == 0 {
		return 0
	}
	idx := (len(sorted) - 1) * pct / 100
	return sorted[idx]
}

func computeJitter(ordered []time.Duration) time.Duration {
	if len(ordered) < 2 {
		return 0
	}
	// Mean absolute deviation of consecutive RTT samples.
	var sum time.Duration
	prev := ordered[0]
	for i := 1; i < len(ordered); i++ {
		d := ordered[i] - prev
		if d < 0 {
			d = -d
		}
		sum += d
		prev = ordered[i]
	}
	return sum / time.Duration(len(ordered)-1)
}
