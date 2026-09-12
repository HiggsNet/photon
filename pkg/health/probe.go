package health

import (
	"context"
	"errors"
	"net/netip"
	"time"
)

// ProbeResult is the outcome of a single probe burst. Sent/Received/Lost are
// packet counts. RTT is the last successful reply RTT in the burst, including
// partial bursts; it is zero when no reply was received.
type ProbeResult struct {
	InstanceID string
	Sent       int
	Received   int
	Lost       int
	RTT        time.Duration
	// Success retains the burst-level majority policy used for consecutive
	// failure hysteresis. Packet loss and link state thresholds use the counts
	// above, not this aggregate bit.
	Success bool
	Err     error // raw execution failure, NOT used as a metrics label
}

func normalizeProbeResult(result ProbeResult) ProbeResult {
	if result.Sent < 0 {
		result.Sent = 0
	}
	if result.Received < 0 {
		result.Received = 0
	}
	if result.Lost < 0 {
		result.Lost = 0
	}
	if result.Sent == 0 && result.Received == 0 && result.Lost == 0 {
		// Preserve source compatibility for simple/third-party probers that only
		// populated Success. Execution errors genuinely sent no known packets.
		if result.Err == nil {
			result.Sent = 1
			if result.Success {
				result.Received = 1
			} else {
				result.Lost = 1
			}
		}
	} else {
		if result.Sent == 0 {
			result.Sent = result.Received + result.Lost
		}
		if result.Received > result.Sent {
			result.Received = result.Sent
		}
		result.Lost = result.Sent - result.Received
	}
	result.Success = result.Err == nil && result.Received > result.Lost
	if result.Received == 0 {
		result.RTT = 0
	}
	return result
}

// Prober executes active probes. Implementations include ICMP echo and UDP
// keepalive. Probes must run in the overlay/data-plane netns and bind to the
// corresponding XFRM interface or source tunnel address.
type Prober interface {
	// Probe sends a burst of probe packets and returns the aggregate result.
	Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult
	// Type returns the probe type identifier (icmp/udp).
	Type() string
}

// ProbeRunner executes individual probe packets for a Prober.
type ProbeRunner interface {
	PingOnce(ctx context.Context, src, dst netip.Addr, iface string, netns string, timeout time.Duration) (time.Duration, error)
}

// nopProber is a no-op prober used as the default; the daemon injects the real
// implementation (ICMP/UDP) when capabilities allow.
type nopProber struct{}

func (nopProber) Probe(ctx context.Context, target ProbeTarget, cfg ProbeConfig) ProbeResult {
	return ProbeResult{InstanceID: target.InstanceID, Err: errors.New("no prober configured")}
}

func (nopProber) Type() string { return ProbeTypeICMP }
