package photonlinux

import (
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux/healthprobe"
	"github.com/HiggsNet/photon/pkg/health"
)

const healthFallbackLogInterval = 10 * time.Minute

type healthFallbackLogState struct {
	last       time.Time
	suppressed int
}

func (r *LinuxDriver) initializeHealthProber() {
	if r == nil || r.healthProber != nil {
		return
	}
	r.healthProber = healthprobe.NewRawICMProber(
		healthprobe.NewICMProber(nil),
		r.reportHealthFallback,
	)
}

// HealthProber returns the Linux probe implementation owned by this LinuxDriver.
// Probe scheduling and health policy remain in the platform-independent
// health manager; raw sockets, setns workers and exec fallback are Linux-owned.
func (r *LinuxDriver) HealthProber() health.Prober {
	if r == nil {
		return nil
	}
	return r.healthProber
}

func (r *LinuxDriver) reportHealthFallback(target health.ProbeTarget, rawErr error) {
	if r == nil || r.logger == nil {
		return
	}
	netns := strings.TrimSpace(target.NetNS)
	if netns == "" {
		netns = "host"
	}
	key := netns
	if rawErr != nil {
		key += "\x00" + rawErr.Error()
	}
	now := time.Now()
	r.healthFallbackMu.Lock()
	state := r.healthFallback[key]
	if !state.last.IsZero() && now.Sub(state.last) < healthFallbackLogInterval {
		state.suppressed++
		if r.healthFallback == nil {
			r.healthFallback = make(map[string]healthFallbackLogState)
		}
		r.healthFallback[key] = state
		r.healthFallbackMu.Unlock()
		return
	}
	suppressed := state.suppressed
	if r.healthFallback == nil {
		r.healthFallback = make(map[string]healthFallbackLogState)
	}
	r.healthFallback[key] = healthFallbackLogState{last: now}
	r.healthFallbackMu.Unlock()

	fields := map[string]any{
		"netns":     netns,
		"interface": target.InterfaceName,
		"fallback":  "exec_ping",
		"error":     rawErr,
	}
	if suppressed > 0 {
		fields["suppressed"] = suppressed
	}
	r.logger.Warn("health", "raw_icmp_fallback", fields)
}
