package health

import (
	"context"
	"fmt"
	"net/netip"
	"testing"
	"time"
)

type sizedProber struct{ calls []ProbeConfig }

func (p *sizedProber) Type() string { return ProbeTypeICMP }
func (p *sizedProber) Probe(_ context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult {
	p.calls = append(p.calls, cfg)
	if cfg.PacketSize > 0 {
		return ProbeResult{InstanceID: target.InstanceID, Sent: 1, Lost: 1}
	}
	return ProbeResult{InstanceID: target.InstanceID, Sent: cfg.Burst, Received: cfg.Burst, RTT: time.Millisecond}
}

func TestLargeProbesHaveIndependentCadenceAndLoss(t *testing.T) {
	cfg := DefaultProbeConfig()
	cfg.Jitter = 0
	cfg.Large.Enabled = true
	cfg.Large.Interval = 17 * time.Second
	p := &sizedProber{}
	m := NewManager(cfg, DefaultHysteresisConfig(), p)
	now := time.Unix(1000, 0)
	m.UpsertTarget(ProbeTarget{InstanceID: "link", State: "up"}, now)
	for _, offset := range []time.Duration{5, 10, 15, 17, 20} {
		if got := m.Tick(t.Context(), now.Add(offset*time.Second)); got != 1 {
			t.Fatalf("tick at %vs dispatched %d", offset, got)
		}
	}
	if len(p.calls) != 5 || p.calls[3].PacketSize != 1200 || p.calls[3].Burst != 1 || p.calls[4].PacketSize != 0 {
		t.Fatalf("unexpected probe configurations: %+v", p.calls)
	}
	h, ok := m.HealthFor("link", now.Add(20*time.Second))
	if !ok || h.Sent != 12 || h.Lost != 0 || h.State != HealthStateHealthy {
		t.Fatalf("large loss changed small health: %+v", h)
	}
	large := h.LargeProbe
	if large == nil || large.Sent != 1 || large.Lost != 1 || large.LossRatio != 1 || !large.NextProbeAt.Equal(now.Add(34*time.Second)) {
		t.Fatalf("large snapshot = %+v", large)
	}
	if next, ok := m.NextDue(now); !ok || !next.Equal(now.Add(25*time.Second)) {
		t.Fatalf("next due = %v %t", next, ok)
	}

	// Snapshot values must not alias manager-owned state.
	large.Lost = 999
	if m.Snapshot(now)[0].LargeProbe.Lost != 1 {
		t.Fatal("large snapshot aliases manager state")
	}
}

func TestLargeProbesAreOptInAndShareConcurrencyLimit(t *testing.T) {
	cfg := DefaultProbeConfig()
	cfg.Jitter = 0
	m := NewManager(cfg, DefaultHysteresisConfig(), nil)
	now := time.Unix(1000, 0)
	m.UpsertTarget(ProbeTarget{InstanceID: "link", State: "up"}, now)
	if m.Snapshot(now)[0].LargeProbe != nil {
		t.Fatal("large probes enabled by default")
	}
	cfg.Large.Enabled = true
	cfg.Large.Interval = cfg.Interval
	cfg.MaxConcurrent = 2
	m = NewManager(cfg, DefaultHysteresisConfig(), nil)
	for i := range 3 {
		m.UpsertTarget(ProbeTarget{InstanceID: fmt.Sprint(i), State: "up"}, now)
	}
	jobs := m.reserveDue(t.Context(), now.Add(5*time.Second))
	if len(jobs) != 2 || jobs[0].id == jobs[1].id || m.inFlight != 2 {
		t.Fatalf("shared budget violated: %+v", jobs)
	}
	if more := m.reserveDue(t.Context(), now.Add(time.Minute)); len(more) != 0 {
		t.Fatal("large probes bypassed concurrency limit")
	}
}

func TestLargeAsyncProbesUseConfiguredSizeAndOnePacket(t *testing.T) {
	cfg := DefaultProbeConfig()
	cfg.Interval = time.Hour
	cfg.Jitter = 0
	cfg.Large.Enabled = true
	cfg.Large.Interval = time.Second
	cfg.Large.PacketSize = 1300
	p := &sizedProber{}
	m := NewManager(cfg, DefaultHysteresisConfig(), p)
	ctx, cancel := context.WithCancel(t.Context())
	defer func() { cancel(); m.WaitAsync() }()
	updates := m.StartAsync(ctx)
	now := time.Now()
	m.UpsertTarget(ProbeTarget{InstanceID: "link", State: "up"}, now)
	if m.TickAsync(ctx, now.Add(2*time.Second)) != 1 {
		t.Fatal("large async probe was not dispatched")
	}
	select {
	case <-updates:
	case <-time.After(time.Second):
		t.Fatal("large async probe did not complete")
	}
	got := m.Snapshot(time.Now())[0]
	if len(p.calls) != 1 || p.calls[0].PacketSize != 1300 || p.calls[0].Burst != 1 || got.Sent != 0 || got.LargeProbe.Lost != 1 {
		t.Fatalf("async probe mixed streams: calls=%+v snapshot=%+v", p.calls, got)
	}
}

func TestLateLargeResultCannotContaminateReplacementOrRotation(t *testing.T) {
	cfg := DefaultProbeConfig()
	cfg.Large.Enabled = true
	m := NewManager(cfg, DefaultHysteresisConfig(), nil)
	now := time.Unix(1000, 0)
	target := ProbeTarget{ProbeID: "link#staged", InstanceID: "link", State: "staged", Staged: true, InterfaceName: "old", Generation: 1, PeerTunnelAddr: netip.MustParseAddr("fd00::2")}
	m.UpsertTarget(target, now)
	job := probeDispatch{id: target.ProbeID, window: m.windows[target.ProbeID], large: true}
	target.InterfaceName, target.Generation = "new", 2
	m.UpsertTarget(target, now)
	m.applyResult(job, ProbeResult{Sent: 1, Received: 1}, now)
	h := m.Snapshot(now)[0]
	if h.Sent != 0 || h.LargeProbe.Sent != 0 || m.RotateActivationReadiness()["link"] {
		t.Fatalf("stale large result leaked: %+v", h)
	}
	job.window = m.windows[target.ProbeID]
	m.applyResult(job, ProbeResult{Sent: 1, Received: 1}, now)
	if m.RotateActivationReadiness()["link"] {
		t.Fatal("large success opened small-probe rotation gate")
	}
}
