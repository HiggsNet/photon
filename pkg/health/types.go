package health

import (
	"net/netip"
	"time"
)

// HealthState is the local health state derived for a link. It does not replace
// Babel route selection or write into gossip active state. It only affects the
// local daemon reconcile/metrics/alerting.
const (
	HealthStateUnknown    = "unknown"
	HealthStateHealthy    = "healthy"
	HealthStateDegraded   = "degraded"
	HealthStateDown       = "down"
	HealthStateProbeError = "probe_error"
	HealthStateSuppressed = "suppressed"
)

// ProbeType describes the active probe mechanism used for a link.
const (
	ProbeTypeICMP = "icmp"
	ProbeTypeUDP  = "udp"
)

// ProbeTarget describes the target of a health probe for a single link
// generation. It is derived from LinkInstance and TransportLinkSpec.
type ProbeTarget struct {
	ProbeID         string     `json:"probe_id,omitempty"`
	InstanceID      string     `json:"instance_id"`
	GroupID         string     `json:"group_id,omitempty"`
	PeerZone        string     `json:"peer_zone,omitempty"`
	LocalZone       string     `json:"local_zone,omitempty"`
	Overlay         string     `json:"overlay,omitempty"`
	NetNS           string     `json:"netns,omitempty"`
	InterfaceName   string     `json:"interface_name,omitempty"`
	UnderlayFamily  string     `json:"underlay_family,omitempty"`
	LocalTunnelAddr netip.Addr `json:"local_tunnel_addr,omitempty,omitzero"`
	PeerTunnelAddr  netip.Addr `json:"peer_tunnel_addr,omitempty,omitzero"`
	Generation      uint64     `json:"generation,omitempty"`
	ProbeRole       string     `json:"probe_role,omitempty"`
	Role            string     `json:"role,omitempty"`
	State           string     `json:"state,omitempty"` // LinkInstance state (connecting/up/degraded/...)
	Staged          bool       `json:"staged,omitempty"`
}

// ShouldProbe reports whether this target is in a probeable link state.
// Policy-denied, revoked, removing links are not probed.
func (t ProbeTarget) ShouldProbe() bool {
	switch t.State {
	case "connecting", "up", "degraded", "stale", "dual_running":
		return true
	case "staged":
		return true
	default:
		return false
	}
}

// ProbeConfig is the per-link probe scheduling configuration.
type ProbeConfig struct {
	Interval time.Duration
	Timeout  time.Duration
	Burst    int
	// LossWindow is the number of probe bursts retained. Packet counters inside
	// each burst are summed, so loss ratios are packet-level while the time
	// horizon remains compatible with the previous burst-level window.
	LossWindow    int
	Jitter        time.Duration
	MaxConcurrent int
}

// DefaultProbeConfig returns conservative defaults. Low-frequency by default
// to avoid probes themselves creating congestion.
func DefaultProbeConfig() ProbeConfig {
	return ProbeConfig{
		Interval:      5 * time.Second,
		Timeout:       time.Second,
		Burst:         3,
		LossWindow:    20,
		Jitter:        500 * time.Millisecond,
		MaxConcurrent: 8,
	}
}

// HysteresisConfig controls state transitions to avoid flapping.
type HysteresisConfig struct {
	// FailThresholdConsecutive is the consecutive probe failures required to
	// degrade/down a healthy link.
	FailThresholdConsecutive int
	// LossThreshold is the window loss ratio (0.0-1.0) required to degrade.
	LossThreshold float64
	// DownLossThreshold is the window loss ratio required to mark down.
	DownLossThreshold float64
	// RecoverConsecutive is consecutive successes required to recover from
	// degraded/down.
	RecoverConsecutive int
}

// DefaultHysteresisConfig returns conservative defaults.
func DefaultHysteresisConfig() HysteresisConfig {
	return HysteresisConfig{
		FailThresholdConsecutive: 3,
		LossThreshold:            0.2,
		DownLossThreshold:        0.6,
		RecoverConsecutive:       5,
	}
}

// MetricsLabels are the low-cardinality labels attached to health metrics.
// Endpoint IPs, nonces and error strings must NOT be used as labels.
type MetricsLabels struct {
	LocalZone  string
	PeerZone   string
	Overlay    string
	ProbeID    string
	InstanceID string
	NetNS      string
	Generation string
	ProbeRole  string
	ProbeType  string
	Reason     string
}

// LinkHealth is the computed health snapshot for a link.
type LinkHealth struct {
	ProbeID         string
	InstanceID      string
	ProbeRole       string
	InterfaceName   string
	State           string
	ProbeType       string
	Sent            int
	Received        int
	Lost            int
	LossRatio       float64
	LastRTT         time.Duration
	EWMARTT         time.Duration
	MinRTT          time.Duration
	MaxRTT          time.Duration
	P50RTT          time.Duration
	P95RTT          time.Duration
	P99RTT          time.Duration
	Jitter          time.Duration
	ConsecutiveFail int
	LastSuccess     time.Time
	LastFailure     error  // raw failure from the latest probe execution
	LastReason      string // stable state/failure reason for metrics and policy
	NextProbeAt     time.Time
	CutoverBlocking bool
	Labels          MetricsLabels
}

// BabelObservation is passive data collected from BIRD/Babel. It augments the
// active probe but does not replace it.
type BabelObservation struct {
	ProbeID    string
	InstanceID string
	Neighbor   bool
	RTT        time.Duration
	Metric     int
	Route      bool
}
