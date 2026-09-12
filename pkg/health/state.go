package health

import "time"

// StateMachine evaluates rolling-window snapshots with hysteresis to derive
// the local LinkHealth state. It distinguishes failure reasons.
type StateMachine struct {
	cfg HysteresisConfig

	// current state per instance
	state         map[string]string
	consecRecover map[string]int
}

// NewStateMachine returns a state machine using the given config.
func NewStateMachine(cfg HysteresisConfig) *StateMachine {
	if cfg.FailThresholdConsecutive <= 0 {
		cfg.FailThresholdConsecutive = 3
	}
	if cfg.LossThreshold <= 0 {
		cfg.LossThreshold = 0.2
	}
	if cfg.DownLossThreshold <= 0 {
		cfg.DownLossThreshold = 0.6
	}
	if cfg.RecoverConsecutive <= 0 {
		cfg.RecoverConsecutive = 5
	}
	return &StateMachine{
		cfg:           cfg,
		state:         map[string]string{},
		consecRecover: map[string]int{},
	}
}

// Evaluate applies a window snapshot and returns the new health state and a
// failure reason (if the state is degraded/down/probe_error). now is the
// evaluation time (usually the probe time).
func (m *StateMachine) Evaluate(instanceID string, snap WindowSnapshot, lastFailure error, now time.Time) (state string, reason string) {
	prev := m.state[instanceID]
	if prev == "" {
		prev = HealthStateUnknown
	}

	// Unknown means that no observation exists. Once a probe has completed,
	// report what that observation says instead of falling back to unknown for
	// low-but-nonzero loss or while failure hysteresis is pending.
	observations := snap.Bursts
	if observations == 0 && snap.Sent > 0 {
		// Compatibility for callers constructing WindowSnapshot directly.
		observations = snap.Sent
	}
	if observations == 0 {
		state, reason = HealthStateUnknown, ""
	} else if lastFailure != nil && (prev == HealthStateProbeError || snap.ConsecutiveFails >= m.cfg.FailThresholdConsecutive) {
		// probe_error is sticky: it represents repeated failures to execute a
		// useful probe (permission/netns/interface missing). Recovery requires
		// consecutive successes.
		state, reason = HealthStateProbeError, classifyFailReason(lastFailure, snap)
	} else if snap.ConsecutiveFails >= m.cfg.FailThresholdConsecutive {
		state, reason = HealthStateDown, classifyFailReason(lastFailure, snap)
	} else if snap.Sent == 0 {
		// The probe ran but could not send packets. Before the repeated-error
		// threshold this is degraded, matching the old one-sample error behavior.
		state, reason = HealthStateDegraded, classifyFailReason(lastFailure, snap)
	} else if snap.LossRatio >= m.cfg.DownLossThreshold {
		// A cold window makes the first failed sample look like 100% loss. Do
		// not call the link down until at least the configured failure evidence
		// has accumulated.
		if observations >= m.cfg.FailThresholdConsecutive {
			state, reason = HealthStateDown, classifyFailReason(lastFailure, snap)
		} else {
			state, reason = HealthStateDegraded, classifyFailReason(lastFailure, snap)
		}
	} else if snap.LossRatio >= m.cfg.LossThreshold {
		state, reason = HealthStateDegraded, classifyFailReason(lastFailure, snap)
	} else {
		state, reason = HealthStateHealthy, ""
	}

	// Hysteresis for recovery.
	if (prev == HealthStateDegraded || prev == HealthStateDown || prev == HealthStateProbeError) && state == HealthStateHealthy {
		m.consecRecover[instanceID]++
		if m.consecRecover[instanceID] < m.cfg.RecoverConsecutive {
			// Stay degraded until stable recovery.
			state = prev
			reason = "recovering"
		} else {
			m.consecRecover[instanceID] = 0
		}
	} else {
		m.consecRecover[instanceID] = 0
	}

	m.state[instanceID] = state
	return state, reason
}

// State returns the current health state for an instance.
func (m *StateMachine) State(instanceID string) string {
	s := m.state[instanceID]
	if s == "" {
		return HealthStateUnknown
	}
	return s
}

// SetProbeError marks an instance in probe_error due to dispatch failure.
func (m *StateMachine) SetProbeError(instanceID string, reason string) {
	m.state[instanceID] = HealthStateProbeError
}

// Reset clears state for an instance (used when link is removed).
func (m *StateMachine) Reset(instanceID string) {
	delete(m.state, instanceID)
	delete(m.consecRecover, instanceID)
}

// classifyFailReason maps a raw error into a stable reason category.
func classifyFailReason(failure error, snap WindowSnapshot) string {
	raw := ""
	if failure != nil {
		raw = failure.Error()
	}
	switch {
	case contains(raw, "permission"):
		return "permission_denied"
	case contains(raw, "netns") || contains(raw, "interface") || contains(raw, "missing"):
		return "netns_interface_missing"
	case contains(raw, "address"):
		return "peer_address_missing"
	case contains(raw, "firewall"):
		return "firewall_denied"
	case raw == "" && snap.Sent > 0 && snap.Received == 0:
		return "probe_timeout"
	default:
		return "probe_failure"
	}
}

func contains(s, sub string) bool {
	if len(sub) == 0 {
		return false
	}
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
