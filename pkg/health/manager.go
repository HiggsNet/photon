package health

import (
	"context"
	"math/rand"
	"sort"
	"sync"
	"time"
)

// Manager owns the per-link rolling windows, state machine, scheduler, and
// produces coalesced health results. It is safe for concurrent use.
//
// The daemon event loop drives the Manager:
//   - SetTargets / RemoveTarget on link create/update/remove
//   - Tick periodically dispatches due probes
//   - Snapshot / HealthFor reads the current state
//
// Probe dispatch is bounded by MaxConcurrent to avoid amplification.
type Manager struct {
	mu sync.Mutex

	cfg         ProbeConfig
	hysteresis  HysteresisConfig
	prober      Prober
	windows     map[string]*RollingWindow
	states      *StateMachine
	targets     map[string]ProbeTarget
	lastError   map[string]string
	lastReason  map[string]string
	nextProbe   map[string]time.Time
	errorsTotal map[string]int
	babelObs    map[string]BabelObservation

	// inFlight tracks concurrent probe dispatch.
	inFlight    int
	inFlightIDs map[string]bool
	maxInflight int

	asyncOnce    sync.Once
	asyncJobs    chan probeDispatch
	asyncUpdates chan struct{}
	asyncWG      sync.WaitGroup
}

type probeDispatch struct {
	ctx    context.Context
	id     string
	target ProbeTarget
}

// NewManager creates a Manager. The Prober may be nil, in which case a no-op
// prober is used (all probes report probe_error).
func NewManager(cfg ProbeConfig, hyst HysteresisConfig, prober Prober) *Manager {
	if prober == nil {
		prober = nopProber{}
	}
	max := cfg.MaxConcurrent
	if max <= 0 {
		max = 8
	}
	return &Manager{
		cfg:         cfg,
		hysteresis:  hyst,
		prober:      prober,
		windows:     map[string]*RollingWindow{},
		states:      NewStateMachine(hyst),
		targets:     map[string]ProbeTarget{},
		lastError:   map[string]string{},
		lastReason:  map[string]string{},
		nextProbe:   map[string]time.Time{},
		errorsTotal: map[string]int{},
		babelObs:    map[string]BabelObservation{},
		inFlightIDs: map[string]bool{},
		maxInflight: max,
	}
}

// SetTargets replaces the full set of probe targets. Targets not present in
// the new set are removed (their state is reset).
func (m *Manager) SetTargets(targets []ProbeTarget, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	newMap := map[string]ProbeTarget{}
	for _, t := range targets {
		if !t.ShouldProbe() {
			continue
		}
		id := targetKey(t)
		newMap[id] = t
		if _, ok := m.targets[id]; !ok {
			m.windows[id] = NewRollingWindow(m.lossWindow())
			m.nextProbe[id] = now.Add(m.jitteredInterval())
		}
	}
	for id := range m.targets {
		if _, ok := newMap[id]; !ok {
			m.releaseInFlightLocked(id)
			delete(m.targets, id)
			delete(m.windows, id)
			delete(m.nextProbe, id)
			delete(m.lastError, id)
			delete(m.lastReason, id)
			delete(m.errorsTotal, id)
			delete(m.babelObs, id)
			m.states.Reset(id)
		}
	}
	m.targets = newMap
}

// UpsertTarget adds or updates a single target.
func (m *Manager) UpsertTarget(t ProbeTarget, now time.Time) {
	if !t.ShouldProbe() {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	id := targetKey(t)
	if _, ok := m.targets[id]; !ok {
		m.windows[id] = NewRollingWindow(m.lossWindow())
		m.nextProbe[id] = now.Add(m.jitteredInterval())
	}
	m.targets[id] = t
}

// RemoveTarget removes a target by probe ID and resets its state.
func (m *Manager) RemoveTarget(instanceID string) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.releaseInFlightLocked(instanceID)
	delete(m.targets, instanceID)
	delete(m.windows, instanceID)
	delete(m.nextProbe, instanceID)
	delete(m.lastError, instanceID)
	delete(m.lastReason, instanceID)
	delete(m.errorsTotal, instanceID)
	delete(m.babelObs, instanceID)
	m.states.Reset(instanceID)
}

// SetBabelObservation stores passive Babel data for a link.
func (m *Manager) SetBabelObservation(obs BabelObservation) {
	id := obs.ProbeID
	if id == "" {
		id = obs.InstanceID
	}
	if id == "" {
		return
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.babelObs[id] = obs
}

// Tick dispatches any probes that are due and waits for the selected batch.
// It remains useful to callers that need a synchronous result (notably tests
// and one-shot commands). Daemons should use TickAsync instead.
func (m *Manager) Tick(ctx context.Context, now time.Time) int {
	pending := m.reserveDue(ctx, now)
	if len(pending) == 0 {
		return 0
	}

	type outcome struct {
		id     string
		result ProbeResult
	}
	results := make(chan outcome, len(pending))
	var wg sync.WaitGroup
	for _, job := range pending {
		wg.Add(1)
		go func(job probeDispatch) {
			defer wg.Done()
			results <- outcome{id: job.id, result: m.prober.Probe(job.ctx, job.target, m.cfg)}
		}(job)
	}
	wg.Wait()
	close(results)
	byID := make(map[string]ProbeResult, len(pending))
	for result := range results {
		byID[result.id] = result.result
	}
	for _, job := range pending {
		id := job.id
		m.applyResult(id, byID[id], now)
		m.finishProbe(id, now)
	}
	return len(pending)
}

// StartAsync starts a bounded probe worker pool and returns a coalesced
// notification channel. The manager remains responsible for its state; the
// daemon uses the channel only to persist and publish completed updates.
func (m *Manager) StartAsync(ctx context.Context) <-chan struct{} {
	m.asyncOnce.Do(func() {
		m.asyncJobs = make(chan probeDispatch, m.maxInflight)
		m.asyncUpdates = make(chan struct{}, 1)
		for i := 0; i < m.maxInflight; i++ {
			m.asyncWG.Add(1)
			go m.runAsyncWorker(ctx)
		}
	})
	return m.asyncUpdates
}

// WaitAsync waits for the worker pool started by StartAsync. The caller must
// first cancel that method's context.
func (m *Manager) WaitAsync() {
	if m != nil {
		m.asyncWG.Wait()
	}
}

// TickAsync queues due probes for the worker pool and returns immediately.
// StartAsync must have been called first.
func (m *Manager) TickAsync(ctx context.Context, now time.Time) int {
	if m.asyncJobs == nil {
		return 0
	}
	pending := m.reserveDue(ctx, now)
	for _, job := range pending {
		m.asyncJobs <- job
	}
	return len(pending)
}

func (m *Manager) runAsyncWorker(ctx context.Context) {
	defer m.asyncWG.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case job := <-m.asyncJobs:
			result := m.runAsyncProbe(job)
			now := time.Now()
			m.applyResult(job.id, result, now)
			m.finishProbe(job.id, now)
			m.notifyAsyncUpdate()
		}
	}
}

const asyncProbeDeadlineGrace = 250 * time.Millisecond

// runAsyncProbe puts a hard upper bound around the Prober contract. Production
// probers honor context cancellation, while the buffered result channel also
// lets the worker move on if an implementation fails to return after cancel.
func (m *Manager) runAsyncProbe(job probeDispatch) ProbeResult {
	timeout := m.cfg.Timeout
	if timeout <= 0 {
		timeout = time.Second
	}
	burst := m.cfg.Burst
	if burst <= 0 {
		burst = 3
	}
	probeCtx, cancel := context.WithTimeout(job.ctx, timeout*time.Duration(burst)+asyncProbeDeadlineGrace)
	defer cancel()
	results := make(chan ProbeResult, 1)
	go func() {
		results <- m.prober.Probe(probeCtx, job.target, m.cfg)
	}()
	select {
	case result := <-results:
		return result
	case <-probeCtx.Done():
		return ProbeResult{
			InstanceID: job.target.InstanceID,
			Error:      "probe deadline exceeded: " + probeCtx.Err().Error(),
		}
	}
}

func (m *Manager) notifyAsyncUpdate() {
	select {
	case m.asyncUpdates <- struct{}{}:
	default:
	}
}

func (m *Manager) reserveDue(ctx context.Context, now time.Time) []probeDispatch {
	m.mu.Lock()
	defer m.mu.Unlock()
	if len(m.targets) == 0 || m.maxInflight-m.inFlight <= 0 {
		return nil
	}
	available := m.maxInflight - m.inFlight
	due := make([]string, 0, len(m.targets))
	for id, next := range m.nextProbe {
		if !m.inFlightIDs[id] && !next.IsZero() && !now.Before(next) {
			due = append(due, id)
		}
	}
	sort.Slice(due, func(i, j int) bool {
		left, right := m.nextProbe[due[i]], m.nextProbe[due[j]]
		if !left.Equal(right) {
			return left.Before(right)
		}
		return due[i] < due[j]
	})
	if len(due) > available {
		due = due[:available]
	}
	pending := make([]probeDispatch, 0, len(due))
	for _, id := range due {
		pending = append(pending, probeDispatch{ctx: ctx, id: id, target: m.targets[id]})
		m.inFlight++
		m.inFlightIDs[id] = true
	}
	return pending
}

func (m *Manager) finishProbe(id string, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.inFlightIDs[id] {
		return
	}
	m.releaseInFlightLocked(id)
	if _, ok := m.targets[id]; ok {
		m.nextProbe[id] = now.Add(m.jitteredInterval())
	}
}

func (m *Manager) releaseInFlightLocked(id string) {
	if !m.inFlightIDs[id] {
		return
	}
	delete(m.inFlightIDs, id)
	m.inFlight--
	if m.inFlight < 0 {
		m.inFlight = 0
	}
}

// NextDue returns the earliest next probe time across all targets, or the zero
// value if there are none. Used by the daemon to compute the next wake.
func (m *Manager) NextDue(now time.Time) (time.Time, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	var earliest time.Time
	for id, next := range m.nextProbe {
		if m.inFlightIDs[id] || next.IsZero() {
			continue
		}
		if earliest.IsZero() || next.Before(earliest) {
			earliest = next
		}
	}
	return earliest, !earliest.IsZero()
}

func (m *Manager) applyResult(instanceID string, result ProbeResult, now time.Time) {
	m.mu.Lock()
	window, ok := m.windows[instanceID]
	m.mu.Unlock()
	if !ok {
		return
	}
	window.RecordProbe(now, result)
	snap := window.Snapshot()

	m.mu.Lock()
	defer m.mu.Unlock()
	if _, ok := m.targets[instanceID]; !ok {
		return
	}
	if result.Error != "" {
		m.errorsTotal[instanceID]++
		m.lastError[instanceID] = result.Error
	} else {
		delete(m.lastError, instanceID)
	}
	_, reason := m.states.Evaluate(instanceID, snap, m.lastError[instanceID], now)
	if reason == "" {
		delete(m.lastReason, instanceID)
	} else {
		m.lastReason[instanceID] = reason
	}
}

// Snapshot returns the current health of all links.
func (m *Manager) Snapshot(now time.Time) []LinkHealth {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([]LinkHealth, 0, len(m.targets))
	for id, t := range m.targets {
		window := m.windows[id]
		var snap WindowSnapshot
		if window != nil {
			snap = window.Snapshot()
		}
		labels := MetricsLabels{
			LocalZone:  t.LocalZone,
			PeerZone:   t.PeerZone,
			Overlay:    t.Overlay,
			ProbeID:    id,
			InstanceID: t.InstanceID,
			NetNS:      t.NetNS,
			Generation: generationLabel(t.Generation),
			ProbeRole:  t.ProbeRole,
			ProbeType:  m.prober.Type(),
			Reason:     m.lastReason[id],
		}
		next := m.nextProbe[id]
		h := LinkHealth{
			ProbeID:         id,
			InstanceID:      t.InstanceID,
			ProbeRole:       t.ProbeRole,
			InterfaceName:   t.InterfaceName,
			State:           m.states.State(id),
			ProbeType:       m.prober.Type(),
			Sent:            snap.Sent,
			Received:        snap.Received,
			Lost:            snap.Lost,
			LossRatio:       snap.LossRatio,
			LastRTT:         snap.LastRTT,
			EWMARTT:         snap.EWMARTT,
			MinRTT:          snap.MinRTT,
			MaxRTT:          snap.MaxRTT,
			P50RTT:          snap.P50RTT,
			P95RTT:          snap.P95RTT,
			P99RTT:          snap.P99RTT,
			Jitter:          snap.Jitter,
			ConsecutiveFail: snap.ConsecutiveFails,
			LastSuccess:     snap.LastSuccess,
			LastError:       m.lastError[id],
			LastReason:      m.lastReason[id],
			NextProbeAt:     next,
			CutoverBlocking: t.Staged && m.cutoverBlockingLocked(id),
			Labels:          labels,
		}
		out = append(out, h)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].InstanceID != out[j].InstanceID {
			return out[i].InstanceID < out[j].InstanceID
		}
		return out[i].ProbeID < out[j].ProbeID
	})
	return out
}

// HealthFor returns the health for a single instance.
func (m *Manager) HealthFor(instanceID string, now time.Time) (LinkHealth, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	t, ok := m.targets[instanceID]
	if !ok {
		return LinkHealth{}, false
	}
	window := m.windows[instanceID]
	var snap WindowSnapshot
	if window != nil {
		snap = window.Snapshot()
	}
	labels := MetricsLabels{
		LocalZone:  t.LocalZone,
		PeerZone:   t.PeerZone,
		Overlay:    t.Overlay,
		ProbeID:    instanceID,
		InstanceID: t.InstanceID,
		NetNS:      t.NetNS,
		Generation: generationLabel(t.Generation),
		ProbeRole:  t.ProbeRole,
		ProbeType:  m.prober.Type(),
		Reason:     m.lastReason[instanceID],
	}
	return LinkHealth{
		ProbeID:         instanceID,
		InstanceID:      t.InstanceID,
		ProbeRole:       t.ProbeRole,
		InterfaceName:   t.InterfaceName,
		State:           m.states.State(instanceID),
		ProbeType:       m.prober.Type(),
		Sent:            snap.Sent,
		Received:        snap.Received,
		Lost:            snap.Lost,
		LossRatio:       snap.LossRatio,
		LastRTT:         snap.LastRTT,
		EWMARTT:         snap.EWMARTT,
		MinRTT:          snap.MinRTT,
		MaxRTT:          snap.MaxRTT,
		P50RTT:          snap.P50RTT,
		P95RTT:          snap.P95RTT,
		P99RTT:          snap.P99RTT,
		Jitter:          snap.Jitter,
		ConsecutiveFail: snap.ConsecutiveFails,
		LastSuccess:     snap.LastSuccess,
		LastError:       m.lastError[instanceID],
		LastReason:      m.lastReason[instanceID],
		NextProbeAt:     m.nextProbe[instanceID],
		CutoverBlocking: t.Staged && m.cutoverBlockingLocked(instanceID),
		Labels:          labels,
	}, true
}

// CutoverBlocking reports whether the health state for a staged/rotating link
// blocks IPsec rotate cutover (6.6.4). A link blocks cutover when its health is
// not healthy and not better-than-old.
func (m *Manager) CutoverBlocking(instanceID string) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	found := false
	for id, target := range m.targets {
		if target.InstanceID != instanceID || !target.Staged {
			continue
		}
		found = true
		if m.cutoverBlockingLocked(id) {
			return true
		}
	}
	return !found
}

// RotateCutoverReadiness returns a map suitable for ipsec.ReconcileInputs.RotateCutoverReady.
func (m *Manager) RotateCutoverReadiness() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for id := range m.targets {
		t := m.targets[id]
		if !t.Staged {
			continue
		}
		out[t.InstanceID] = !m.cutoverBlockingLocked(id)
	}
	return out
}

// RotateActivationReadiness reports whether a staged link is safe to make
// preferred. Unlike RotateCutoverReadiness, it deliberately does not require a
// Babel route learned through the staged interface: that route may only appear
// after routing has lowered the staged interface cost and raised the old cost.
func (m *Manager) RotateActivationReadiness() map[string]bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := map[string]bool{}
	for id := range m.targets {
		t := m.targets[id]
		if !t.Staged {
			continue
		}
		out[t.InstanceID] = !m.activationBlockingLocked(id)
	}
	return out
}

func (m *Manager) activationBlockingLocked(instanceID string) bool {
	state := m.states.State(instanceID)
	switch state {
	case HealthStateHealthy, HealthStateDegraded:
	default:
		return true
	}
	if obs, ok := m.babelObs[instanceID]; ok && !obs.Neighbor {
		return true
	}
	return false
}

func (m *Manager) cutoverBlockingLocked(instanceID string) bool {
	if m.activationBlockingLocked(instanceID) {
		return true
	}
	if obs, ok := m.babelObs[instanceID]; ok && (!obs.Neighbor || !obs.Route) {
		return true
	}
	return false
}

// ErrorsTotal returns the total probe errors counter for an instance.
func (m *Manager) ErrorsTotal(instanceID string) int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.errorsTotal[instanceID]
}

func (m *Manager) lossWindow() int {
	w := m.cfg.LossWindow
	if w <= 0 {
		w = 20
	}
	return w
}

func (m *Manager) jitteredInterval() time.Duration {
	if m.cfg.Jitter <= 0 {
		return m.cfg.Interval
	}
	delta := time.Duration(rand.Int63n(int64(m.cfg.Jitter*2))) - m.cfg.Jitter
	return m.cfg.Interval + delta
}

func generationLabel(g uint64) string {
	if g == 0 {
		return ""
	}
	return uint64ToString(g)
}

func uint64ToString(n uint64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

func targetKey(t ProbeTarget) string {
	if t.ProbeID != "" {
		return t.ProbeID
	}
	return t.InstanceID
}
