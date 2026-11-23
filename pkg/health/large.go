package health

import "time"

type largeProbe struct {
	window *RollingWindow
	next   time.Time
	last   time.Time
	err    error
}

// Called with the manager lock held; target identity and lifecycle are shared
// with the small stream, but samples and scheduling are independent.
func (m *Manager) installLargeProbe(id string, now time.Time) {
	if m.cfg.Large.Enabled {
		m.largeProbes[id] = &largeProbe{
			window: NewRollingWindow(m.cfg.Large.LossWindow),
			next:   now.Add(m.jitteredDuration(m.cfg.Large.Interval)),
		}
	}
}

func (m *Manager) probeConfig(job probeDispatch) ProbeConfig {
	cfg := m.cfg
	if job.large {
		cfg.Interval = cfg.Large.Interval
		cfg.PacketSize = cfg.Large.PacketSize
		cfg.Burst = 1
	}
	return cfg
}

func (m *Manager) applyLargeResult(job probeDispatch, result ProbeResult, now time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.windows[job.id] != job.window {
		return
	}
	probe := m.largeProbes[job.id]
	if probe == nil {
		return
	}
	probe.window.RecordProbe(now, result)
	probe.last, probe.err = now, result.Err
}

func (m *Manager) largeHealthLocked(id string) *LargeProbeHealth {
	probe := m.largeProbes[id]
	if probe == nil {
		return nil
	}
	snap := probe.window.Snapshot()
	return &LargeProbeHealth{
		PacketSize: m.cfg.Large.PacketSize,
		Interval:   m.cfg.Large.Interval,
		LossWindow: m.cfg.Large.LossWindow,
		Sent:       snap.Sent, Received: snap.Received, Lost: snap.Lost,
		LossRatio: snap.LossRatio, LastRTT: snap.LastRTT,
		LastProbeAt: probe.last, LastFailure: probe.err, NextProbeAt: probe.next,
	}
}
