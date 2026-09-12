package health

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestProbeTargetJSONRoundTrip(t *testing.T) {
	target := ProbeTarget{
		ProbeID: "link-a#staged", InstanceID: "link-a", PeerZone: "node-a.example.",
		LocalTunnelAddr: netip.MustParseAddr("fd00::1"), PeerTunnelAddr: netip.MustParseAddr("fd00::2"),
		ProbeRole: "staged", Staged: true,
	}
	payload, err := json.Marshal(target)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if !strings.Contains(string(payload), `"local_tunnel_addr":"fd00::1"`) || strings.Contains(string(payload), "LocalTunnelAddr") {
		t.Fatalf("wire target = %s", payload)
	}
	var decoded ProbeTarget
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if decoded.LocalTunnelAddr != target.LocalTunnelAddr || decoded.PeerTunnelAddr != target.PeerTunnelAddr || decoded.ProbeRole != target.ProbeRole {
		t.Fatalf("decoded target = %#v", decoded)
	}

	empty, err := json.Marshal(ProbeTarget{InstanceID: "link-empty"})
	if err != nil {
		t.Fatalf("Marshal empty target: %v", err)
	}
	if strings.Contains(string(empty), "tunnel_addr") {
		t.Fatalf("empty target exposes zero addresses: %s", empty)
	}
}

func TestRollingWindowBasic(t *testing.T) {
	w := NewRollingWindow(5)
	now := time.Now()
	w.Record(now, 10*time.Millisecond, true)
	w.Record(now, 0, false)
	w.Record(now, 20*time.Millisecond, true)
	snap := w.Snapshot()
	if snap.Sent != 3 {
		t.Fatalf("sent = %d, want 3", snap.Sent)
	}
	if snap.Received != 2 {
		t.Fatalf("received = %d, want 2", snap.Received)
	}
	if snap.Lost != 1 {
		t.Fatalf("lost = %d, want 1", snap.Lost)
	}
	if snap.LossRatio < 0.33 || snap.LossRatio > 0.34 {
		t.Fatalf("loss ratio = %f, want ~0.333", snap.LossRatio)
	}
	if snap.MaxRTT != 20*time.Millisecond {
		t.Fatalf("max rtt = %v, want 20ms", snap.MaxRTT)
	}
	if snap.MinRTT != 10*time.Millisecond {
		t.Fatalf("min rtt = %v, want 10ms", snap.MinRTT)
	}
}

func TestRollingWindowEvicts(t *testing.T) {
	w := NewRollingWindow(3)
	now := time.Now()
	// Fill with 3 samples.
	w.Record(now, 10*time.Millisecond, true)
	w.Record(now, 20*time.Millisecond, true)
	w.Record(now, 30*time.Millisecond, true)
	// Add a 4th; the oldest should be evicted.
	w.Record(now, 40*time.Millisecond, true)
	snap := w.Snapshot()
	if snap.Sent != 3 {
		t.Fatalf("sent = %d, want 3 after eviction", snap.Sent)
	}
	if snap.MinRTT != 20*time.Millisecond {
		t.Fatalf("min rtt = %v, want 20ms (oldest evicted)", snap.MinRTT)
	}
	if snap.MaxRTT != 40*time.Millisecond {
		t.Fatalf("max rtt = %v, want 40ms", snap.MaxRTT)
	}
}

func TestRollingWindowCountsPacketsAcrossBursts(t *testing.T) {
	w := NewRollingWindow(3)
	now := time.Now()
	w.RecordProbe(now, ProbeResult{Sent: 3, Received: 3, RTT: 10 * time.Millisecond})
	w.RecordProbe(now.Add(time.Second), ProbeResult{Sent: 3, Received: 2, RTT: 20 * time.Millisecond})
	w.RecordProbe(now.Add(2*time.Second), ProbeResult{Sent: 3, Received: 1, RTT: 30 * time.Millisecond})
	snap := w.Snapshot()
	if snap.Bursts != 3 || snap.Sent != 9 || snap.Received != 6 || snap.Lost != 3 {
		t.Fatalf("three-burst snapshot = %+v, want bursts=3 packets=9/6/3", snap)
	}
	if snap.LossRatio < 0.33 || snap.LossRatio > 0.34 {
		t.Fatalf("loss ratio = %f, want one third", snap.LossRatio)
	}
	if snap.LastRTT != 30*time.Millisecond {
		t.Fatalf("last RTT = %v, want partial burst RTT 30ms", snap.LastRTT)
	}

	// Evict the 3/3 burst. The window remains three bursts, but its packet
	// totals now reflect 2/3 + 1/3 + 0/3 exactly.
	w.RecordProbe(now.Add(3*time.Second), ProbeResult{Sent: 3})
	snap = w.Snapshot()
	if snap.Bursts != 3 || snap.Sent != 9 || snap.Received != 3 || snap.Lost != 6 {
		t.Fatalf("evicted snapshot = %+v, want bursts=3 packets=9/3/6", snap)
	}
	if snap.LastRTT != 0 {
		t.Fatalf("last RTT after unanswered burst = %v, want zero", snap.LastRTT)
	}
}

func TestRollingWindowJitter(t *testing.T) {
	w := NewRollingWindow(10)
	now := time.Now()
	w.Record(now, 10*time.Millisecond, true)
	w.Record(now, 20*time.Millisecond, true)
	w.Record(now, 15*time.Millisecond, true)
	snap := w.Snapshot()
	// Jitter is mean abs deviation of consecutive samples: |20-10| + |15-20| = 15ms / 2 = 7.5ms
	if snap.Jitter <= 0 {
		t.Fatalf("jitter = %v, want > 0", snap.Jitter)
	}
}

func TestStateMachineHealthyToDegraded(t *testing.T) {
	cfg := HysteresisConfig{
		FailThresholdConsecutive: 3,
		LossThreshold:            0.2,
		DownLossThreshold:        0.6,
		RecoverConsecutive:       2,
	}
	m := NewStateMachine(cfg)
	now := time.Now()
	// Start healthy.
	for range 5 {
		m.Evaluate("link1", WindowSnapshot{Sent: 5, Received: 5, Lost: 0}, nil, now)
	}
	if state := m.State("link1"); state != HealthStateHealthy {
		t.Fatalf("state = %s, want healthy", state)
	}
	// Inject consecutive failures.
	for i := range 3 {
		m.Evaluate("link1", WindowSnapshot{Sent: 5, Received: 0, Lost: 5, LossRatio: 1.0, ConsecutiveFails: i + 1}, nil, now)
	}
	if state := m.State("link1"); state != HealthStateDown {
		t.Fatalf("state = %s, want down after consecutive failures", state)
	}
}

func TestStateMachineUnknownOnlyBeforeFirstObservation(t *testing.T) {
	cfg := HysteresisConfig{
		FailThresholdConsecutive: 3,
		LossThreshold:            0.2,
		DownLossThreshold:        0.6,
		RecoverConsecutive:       2,
	}
	m := NewStateMachine(cfg)
	now := time.Now()

	if state := m.State("link1"); state != HealthStateUnknown {
		t.Fatalf("initial state = %s, want unknown", state)
	}
	state, _ := m.Evaluate("link1", WindowSnapshot{
		Sent: 1, Lost: 1, LossRatio: 1, ConsecutiveFails: 1,
	}, nil, now)
	if state != HealthStateDegraded {
		t.Fatalf("state after first failed observation = %s, want degraded", state)
	}
}

func TestStateMachineLowLossIsHealthy(t *testing.T) {
	cfg := HysteresisConfig{
		FailThresholdConsecutive: 3,
		LossThreshold:            0.2,
		DownLossThreshold:        0.6,
		RecoverConsecutive:       2,
	}
	m := NewStateMachine(cfg)
	state, _ := m.Evaluate("link1", WindowSnapshot{
		Sent: 20, Received: 19, Lost: 1, LossRatio: 0.05,
	}, nil, time.Now())
	if state != HealthStateHealthy {
		t.Fatalf("state with loss below threshold = %s, want healthy", state)
	}
}

func TestStateMachineUsesPacketLossWithoutChangingBurstColdStart(t *testing.T) {
	cfg := HysteresisConfig{
		FailThresholdConsecutive: 3,
		LossThreshold:            0.2,
		DownLossThreshold:        0.6,
		RecoverConsecutive:       2,
	}
	tests := []struct {
		name     string
		received int
		want     string
	}{
		{name: "ten_percent", received: 9, want: HealthStateHealthy},
		{name: "thirty_percent", received: 7, want: HealthStateDegraded},
		{name: "seventy_percent", received: 3, want: HealthStateDown},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			window := NewRollingWindow(20)
			machine := NewStateMachine(cfg)
			var state string
			for burst := range 3 {
				window.RecordProbe(time.Now(), ProbeResult{Sent: 10, Received: tt.received})
				state, _ = machine.Evaluate("link1", window.Snapshot(), nil, time.Now())
				if tt.want == HealthStateDown && burst < 2 && state == HealthStateDown {
					t.Fatalf("state after burst %d = down; cold-start gate must remain burst-based", burst+1)
				}
			}
			if state != tt.want {
				t.Fatalf("state at %s loss = %s, want %s", tt.name, state, tt.want)
			}
		})
	}
}

func TestStateMachineExecutionErrorsRemainBurstBased(t *testing.T) {
	m := NewStateMachine(DefaultHysteresisConfig())
	w := NewRollingWindow(20)
	for burst := range 3 {
		w.RecordProbe(time.Now(), ProbeResult{Err: errors.New("permission denied")})
		state, reason := m.Evaluate("link1", w.Snapshot(), errors.New("permission denied"), time.Now())
		want := HealthStateDegraded
		if burst == 2 {
			want = HealthStateProbeError
		}
		if state != want || reason != "permission_denied" {
			t.Fatalf("burst %d state/reason = %s/%s, want %s/permission_denied", burst+1, state, reason, want)
		}
		if snap := w.Snapshot(); snap.Sent != 0 {
			t.Fatalf("execution error sent packets = %d, want 0", snap.Sent)
		} else if snap.LossRatio != 0 {
			t.Fatalf("execution error loss ratio = %v, want 0", snap.LossRatio)
		}
	}
}

func TestStateMachineColdStartFailuresConvergeToDown(t *testing.T) {
	cfg := HysteresisConfig{
		FailThresholdConsecutive: 3,
		LossThreshold:            0.2,
		DownLossThreshold:        0.6,
		RecoverConsecutive:       2,
	}
	m := NewStateMachine(cfg)
	now := time.Now()
	for failures := 1; failures <= 3; failures++ {
		state, _ := m.Evaluate("link1", WindowSnapshot{
			Sent:             failures,
			Lost:             failures,
			LossRatio:        1,
			ConsecutiveFails: failures,
		}, nil, now)
		want := HealthStateDegraded
		if failures == 3 {
			want = HealthStateDown
		}
		if state != want {
			t.Fatalf("state after %d failures = %s, want %s", failures, state, want)
		}
	}
}

func TestStateMachineEstablishedLinkGoesDownAtConsecutiveFailureThreshold(t *testing.T) {
	cfg := HysteresisConfig{
		FailThresholdConsecutive: 3,
		LossThreshold:            0.2,
		DownLossThreshold:        0.6,
		RecoverConsecutive:       2,
	}
	m := NewStateMachine(cfg)
	now := time.Now()
	m.Evaluate("link1", WindowSnapshot{Sent: 20, Received: 20}, nil, now)

	for failures := 1; failures <= 3; failures++ {
		state, _ := m.Evaluate("link1", WindowSnapshot{
			Sent:             20,
			Received:         20 - failures,
			Lost:             failures,
			LossRatio:        float64(failures) / 20,
			ConsecutiveFails: failures,
		}, nil, now)
		want := HealthStateHealthy
		if failures == 3 {
			want = HealthStateDown
		}
		if state != want {
			t.Fatalf("state after %d consecutive failures = %s, want %s", failures, state, want)
		}
	}
}

func TestStateMachineHysteresisRecovery(t *testing.T) {
	cfg := HysteresisConfig{
		FailThresholdConsecutive: 2,
		LossThreshold:            0.2,
		DownLossThreshold:        0.6,
		RecoverConsecutive:       3,
	}
	m := NewStateMachine(cfg)
	now := time.Now()
	// Force into degraded state.
	for i := range 3 {
		m.Evaluate("link1", WindowSnapshot{Sent: 5, Received: 0, Lost: 5, LossRatio: 1.0, ConsecutiveFails: i + 1}, nil, now)
	}
	if state := m.State("link1"); state != HealthStateDown {
		t.Fatalf("state = %s, want down", state)
	}
	// One success should not immediately recover (hysteresis).
	m.Evaluate("link1", WindowSnapshot{Sent: 1, Received: 1, Lost: 0}, nil, now)
	if state := m.State("link1"); state == HealthStateHealthy {
		t.Fatalf("state = %s, should not be healthy after single success (hysteresis)", state)
	}
	// After enough consecutive successes, recover.
	for range 4 {
		m.Evaluate("link1", WindowSnapshot{Sent: 1, Received: 1, Lost: 0}, nil, now)
	}
	if state := m.State("link1"); state != HealthStateHealthy {
		t.Fatalf("state = %s, want healthy after recovery window", state)
	}
}

func TestManagerTickAndSnapshot(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Second, Timeout: 100 * time.Millisecond, Burst: 1, LossWindow: 5, MaxConcurrent: 2}
	hyst := DefaultHysteresisConfig()
	prober := &fakeProber{rtt: 5 * time.Millisecond, success: true}
	m := NewManager(cfg, hyst, prober)
	now := time.Now()
	target := ProbeTarget{
		InstanceID:     "link1",
		PeerZone:       "peer.",
		Overlay:        "group1",
		InterfaceName:  "phx1",
		PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"),
		State:          "up",
	}
	m.UpsertTarget(target, now)
	// Force a probe by setting nextProbe to the past.
	m.mu.Lock()
	m.nextProbe["link1"] = now.Add(-time.Second)
	m.mu.Unlock()
	dispatched := m.Tick(context.Background(), now)
	if dispatched != 1 {
		t.Fatalf("dispatched = %d, want 1", dispatched)
	}
	snapshot := m.Snapshot(now)
	if len(snapshot) != 1 {
		t.Fatalf("snapshot len = %d, want 1", len(snapshot))
	}
	if snapshot[0].Sent != 1 {
		t.Fatalf("sent = %d, want 1", snapshot[0].Sent)
	}
	if snapshot[0].Received != 1 {
		t.Fatalf("received = %d, want 1", snapshot[0].Received)
	}
}

func TestManagerKeepsRawErrorSeparateFromStateReason(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Second, LossWindow: 5}
	m := NewManager(cfg, DefaultHysteresisConfig(), &fakeProber{})
	now := time.Now()
	m.UpsertTarget(ProbeTarget{InstanceID: "link1", State: "up"}, now)

	m.applyResult("link1", ProbeResult{Err: errors.New("netns interface missing: phx0")}, now)
	snapshot := m.Snapshot(now)
	if got := snapshot[0].LastFailure; got == nil || got.Error() != "netns interface missing: phx0" {
		t.Fatalf("last failure = %v, want raw probe failure", got)
	}
	if got := snapshot[0].LastReason; got != "netns_interface_missing" {
		t.Fatalf("last reason = %q, want stable reason", got)
	}

	m.applyResult("link1", ProbeResult{}, now.Add(time.Second))
	snapshot = m.Snapshot(now)
	if got := snapshot[0].LastFailure; got != nil {
		t.Fatalf("last failure after ordinary packet loss = %v, want nil", got)
	}
	if got := snapshot[0].LastReason; got != "probe_timeout" {
		t.Fatalf("last reason after ordinary packet loss = %q, want probe_timeout", got)
	}
}

func TestManagerTickCapsConcurrentProbes(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Hour, Timeout: time.Second, Burst: 1, LossWindow: 5, MaxConcurrent: 2}
	prober := newBlockingProber()
	m := NewManager(cfg, DefaultHysteresisConfig(), prober)
	now := time.Now()
	for _, id := range []string{"link-a", "link-b", "link-c"} {
		m.UpsertTarget(ProbeTarget{InstanceID: id, PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"), State: "up"}, now)
		m.mu.Lock()
		m.nextProbe[id] = now.Add(-time.Second)
		m.mu.Unlock()
	}

	done := make(chan int, 1)
	go func() { done <- m.Tick(context.Background(), now) }()
	for i := 0; i < cfg.MaxConcurrent; i++ {
		<-prober.started
	}
	if got := prober.maxActive(); got != cfg.MaxConcurrent {
		t.Fatalf("maximum active probes = %d, want %d", got, cfg.MaxConcurrent)
	}
	select {
	case <-prober.started:
		t.Fatal("started more probes than max concurrent")
	default:
	}
	close(prober.release)
	if got := <-done; got != cfg.MaxConcurrent {
		t.Fatalf("dispatched = %d, want %d", got, cfg.MaxConcurrent)
	}
}

func TestManagerReserveDuePrefersOldestDeadline(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Hour, Timeout: time.Second, Burst: 1, LossWindow: 5, MaxConcurrent: 2}
	m := NewManager(cfg, DefaultHysteresisConfig(), &fakeProber{})
	now := time.Now()
	for id, due := range map[string]time.Time{
		"link-a": now.Add(-time.Second),
		"link-b": now.Add(-5 * time.Second),
		"link-z": now.Add(-10 * time.Second),
	} {
		m.UpsertTarget(ProbeTarget{InstanceID: id, PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"), State: "up"}, now)
		m.mu.Lock()
		m.nextProbe[id] = due
		m.mu.Unlock()
	}

	pending := m.reserveDue(context.Background(), now)
	if len(pending) != 2 || pending[0].id != "link-z" || pending[1].id != "link-b" {
		t.Fatalf("reserved probes = %#v, want oldest deadlines link-z then link-b", pending)
	}
}

func TestManagerTickAsyncReturnsBeforeProbeCompletes(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Hour, Timeout: time.Second, Burst: 1, LossWindow: 5, MaxConcurrent: 1}
	prober := newBlockingProber()
	m := NewManager(cfg, DefaultHysteresisConfig(), prober)
	now := time.Now()
	m.UpsertTarget(ProbeTarget{InstanceID: "link-a", PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"), State: "up"}, now)
	m.mu.Lock()
	m.nextProbe["link-a"] = now.Add(-time.Second)
	m.mu.Unlock()

	ctx := t.Context()
	updates := m.StartAsync(ctx)
	if got := m.TickAsync(ctx, now); got != 1 {
		t.Fatalf("dispatched = %d, want 1", got)
	}
	<-prober.started
	if snapshot := m.Snapshot(now); snapshot[0].Sent != 0 {
		t.Fatalf("async probe completed before release: %+v", snapshot[0])
	}
	close(prober.release)
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for async probe completion")
	}
	if snapshot := m.Snapshot(time.Now()); snapshot[0].Received != 1 {
		t.Fatalf("received = %d, want 1", snapshot[0].Received)
	}
}

func TestManagerWaitAsyncReturnsAfterCancellation(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Hour, Timeout: time.Second, Burst: 1, LossWindow: 5, MaxConcurrent: 2}
	m := NewManager(cfg, DefaultHysteresisConfig(), &fakeProber{})
	ctx, cancel := context.WithCancel(context.Background())
	m.StartAsync(ctx)
	cancel()

	done := make(chan struct{})
	go func() {
		m.WaitAsync()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("async health workers did not stop after cancellation")
	}
}

func TestManagerAsyncProbeHardDeadlineReleasesWorker(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Hour, Timeout: 10 * time.Millisecond, Burst: 1, LossWindow: 5, MaxConcurrent: 1}
	prober := newStubbornProber()
	m := NewManager(cfg, DefaultHysteresisConfig(), prober)
	now := time.Now()
	m.UpsertTarget(ProbeTarget{InstanceID: "link-a", PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"), State: "up"}, now)
	m.mu.Lock()
	m.nextProbe["link-a"] = now.Add(-time.Second)
	m.mu.Unlock()

	updates := m.StartAsync(t.Context())
	if got := m.TickAsync(t.Context(), now); got != 1 {
		t.Fatalf("dispatched = %d, want 1", got)
	}
	<-prober.started
	select {
	case <-updates:
	case <-time.After(time.Second):
		close(prober.release)
		t.Fatal("hard deadline did not release async worker")
	}
	close(prober.release)
	snapshot := m.Snapshot(time.Now())
	if failure := snapshot[0].LastFailure; failure == nil || !strings.Contains(failure.Error(), "probe deadline exceeded") {
		t.Fatalf("last failure = %v, want hard deadline failure", failure)
	}
}

func TestManagerRotateCutoverReadiness(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Second, Timeout: 100 * time.Millisecond, Burst: 1, LossWindow: 5, MaxConcurrent: 2}
	hyst := DefaultHysteresisConfig()
	prober := &fakeProber{rtt: 5 * time.Millisecond, success: true}
	m := NewManager(cfg, hyst, prober)
	now := time.Now()
	// A staged link should be tracked for cutover readiness.
	target := ProbeTarget{
		InstanceID:     "staged-link",
		PeerZone:       "peer.",
		Overlay:        "group1",
		InterfaceName:  "phx2",
		PeerTunnelAddr: netip.MustParseAddr("10.0.0.3"),
		State:          "staged",
		Staged:         true,
	}
	m.UpsertTarget(target, now)
	m.mu.Lock()
	m.nextProbe["staged-link"] = now.Add(-time.Second)
	m.mu.Unlock()
	m.Tick(context.Background(), now)
	// After a successful probe, cutover should not be blocking for staged.
	readiness := m.RotateCutoverReadiness()
	ready, ok := readiness["staged-link"]
	if !ok {
		t.Fatalf("staged link not in readiness map")
	}
	if !ready {
		t.Fatalf("staged link cutover should be ready after successful probe")
	}
}

func TestManagerRotateCutoverReadinessRequiresBabelObservationWhenPresent(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Second, Timeout: 100 * time.Millisecond, Burst: 1, LossWindow: 5, MaxConcurrent: 2}
	hyst := DefaultHysteresisConfig()
	prober := &fakeProber{rtt: 5 * time.Millisecond, success: true}
	m := NewManager(cfg, hyst, prober)
	now := time.Now()
	target := ProbeTarget{
		ProbeID:        "link1#staged",
		InstanceID:     "link1",
		ProbeRole:      "staged",
		PeerZone:       "peer.",
		Overlay:        "group1",
		InterfaceName:  "phx-new",
		PeerTunnelAddr: netip.MustParseAddr("10.0.0.3"),
		State:          "up",
		Staged:         true,
	}
	m.UpsertTarget(target, now)
	m.mu.Lock()
	m.nextProbe["link1#staged"] = now.Add(-time.Second)
	m.mu.Unlock()
	m.Tick(context.Background(), now)
	if ready := m.RotateCutoverReadiness()["link1"]; !ready {
		t.Fatalf("staged link should be ready before BIRD observation is present")
	}

	m.SetBabelObservation(BabelObservation{ProbeID: "link1#staged", InstanceID: "link1", Neighbor: true, Route: false})
	if ready := m.RotateActivationReadiness()["link1"]; !ready {
		t.Fatalf("staged link should be activation-ready with health and Babel neighbor")
	}
	if ready := m.RotateCutoverReadiness()["link1"]; ready {
		t.Fatalf("staged link should not be ready while BIRD route is not converged")
	}

	m.SetBabelObservation(BabelObservation{ProbeID: "link1#staged", InstanceID: "link1", Neighbor: true, Route: true, Metric: 96})
	if ready := m.RotateCutoverReadiness()["link1"]; !ready {
		t.Fatalf("staged link should be ready after BIRD neighbor and route converge")
	}
}

func TestManagerKeepsRotateProbeTargetsSeparate(t *testing.T) {
	cfg := ProbeConfig{Interval: time.Second, Timeout: 100 * time.Millisecond, Burst: 1, LossWindow: 5, MaxConcurrent: 4}
	hyst := DefaultHysteresisConfig()
	prober := &fakeProber{rtt: 5 * time.Millisecond, success: true}
	m := NewManager(cfg, hyst, prober)
	now := time.Now()
	m.SetTargets([]ProbeTarget{
		{
			ProbeID:        "link1#old",
			InstanceID:     "link1",
			ProbeRole:      "old",
			InterfaceName:  "phx-old",
			PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"),
			State:          "up",
		},
		{
			ProbeID:        "link1#staged",
			InstanceID:     "link1",
			ProbeRole:      "staged",
			InterfaceName:  "phx-new",
			PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"),
			State:          "up",
			Staged:         true,
		},
	}, now)
	m.mu.Lock()
	m.nextProbe["link1#old"] = now.Add(-time.Second)
	m.nextProbe["link1#staged"] = now.Add(-time.Second)
	m.mu.Unlock()
	if dispatched := m.Tick(context.Background(), now); dispatched != 2 {
		t.Fatalf("dispatched = %d, want 2", dispatched)
	}
	snapshot := m.Snapshot(now)
	if len(snapshot) != 2 {
		t.Fatalf("snapshot len = %d, want 2", len(snapshot))
	}
	byRole := map[string]LinkHealth{}
	for _, h := range snapshot {
		byRole[h.ProbeRole] = h
	}
	if byRole["old"].InterfaceName != "phx-old" || byRole["staged"].InterfaceName != "phx-new" {
		t.Fatalf("snapshot by role = %#v, want old/new interfaces", byRole)
	}
	readiness := m.RotateCutoverReadiness()
	if ready, ok := readiness["link1"]; !ok || !ready {
		t.Fatalf("readiness = %#v, want base link ready", readiness)
	}
}

func TestManagerRemoveTarget(t *testing.T) {
	cfg := DefaultProbeConfig()
	hyst := DefaultHysteresisConfig()
	m := NewManager(cfg, hyst, nil)
	now := time.Now()
	target := ProbeTarget{
		InstanceID:     "link1",
		PeerZone:       "peer.",
		Overlay:        "group1",
		InterfaceName:  "phx1",
		PeerTunnelAddr: netip.MustParseAddr("10.0.0.2"),
		State:          "up",
	}
	m.UpsertTarget(target, now)
	m.RemoveTarget("link1")
	snapshot := m.Snapshot(now)
	if len(snapshot) != 0 {
		t.Fatalf("snapshot len = %d, want 0 after remove", len(snapshot))
	}
}

func TestProbeTargetShouldProbe(t *testing.T) {
	tests := []struct {
		state string
		want  bool
	}{
		{"up", true},
		{"connecting", true},
		{"degraded", true},
		{"staged", true},
		{"removing", false},
		{"down", false},
		{"", false},
	}
	for _, tt := range tests {
		target := ProbeTarget{State: tt.state}
		if got := target.ShouldProbe(); got != tt.want {
			t.Errorf("ShouldProbe(state=%q) = %v, want %v", tt.state, got, tt.want)
		}
	}
}

type fakeProber struct {
	rtt     time.Duration
	success bool
}

func (p *fakeProber) Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult {
	return ProbeResult{InstanceID: target.InstanceID, RTT: p.rtt, Success: p.success}
}

func (p *fakeProber) Type() string { return ProbeTypeICMP }

type blockingProber struct {
	started chan struct{}
	release chan struct{}
	mu      sync.Mutex
	active  int
	max     int
}

type stubbornProber struct {
	started chan struct{}
	release chan struct{}
}

func newStubbornProber() *stubbornProber {
	return &stubbornProber{started: make(chan struct{}, 1), release: make(chan struct{})}
}

func (p *stubbornProber) Probe(context.Context, ProbeTarget, ProbeConfig) ProbeResult {
	p.started <- struct{}{}
	<-p.release
	return ProbeResult{Success: true, RTT: time.Millisecond}
}

func (p *stubbornProber) Type() string { return ProbeTypeICMP }

func newBlockingProber() *blockingProber {
	return &blockingProber{started: make(chan struct{}, 3), release: make(chan struct{})}
}

func (p *blockingProber) Probe(context.Context, ProbeTarget, ProbeConfig) ProbeResult {
	p.mu.Lock()
	p.active++
	if p.active > p.max {
		p.max = p.active
	}
	p.mu.Unlock()
	p.started <- struct{}{}
	<-p.release
	p.mu.Lock()
	p.active--
	p.mu.Unlock()
	return ProbeResult{Success: true, RTT: time.Millisecond}
}

func (p *blockingProber) Type() string { return ProbeTypeICMP }

func (p *blockingProber) maxActive() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.max
}
