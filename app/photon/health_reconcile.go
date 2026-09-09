package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/internal/observability/healthspool"
	"github.com/HiggsNet/photon/internal/photonlinux/linkstate"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/urfave/cli/v3"
)

// newHealthManager creates a health.Manager from app config. Returns nil when
// health probing is disabled. The prober is injected by the daemon based on
// capabilities.
func newHealthManager(cfg healthConfig, prober health.Prober) *health.Manager {
	if !cfg.Enabled {
		return nil
	}
	return health.NewManager(cfg.probeConfig(), cfg.hysteresisConfig(), prober)
}

// healthDriver is the optional daemon-owned health subsystem. Platforms that
// do not want background health probing do not install one.
type healthDriver struct {
	*health.Manager
	spool         *healthspool.Store
	driverManaged bool
	asyncRunning  bool
}

// stripScope removes the %iface and netns=... suffixes from a scoped tunnel
// address string before parsing.
func stripScope(s string) string {
	if before, _, ok := strings.Cut(s, "%"); ok {
		return before
	}
	if before, _, ok := strings.Cut(s, " "); ok {
		return before
	}
	return s
}

func scopedNetNS(s string) string {
	for field := range strings.FieldsSeq(s) {
		if netns, ok := strings.CutPrefix(field, "netns="); ok {
			return strings.TrimSpace(netns)
		}
	}
	return ""
}

// reconcileHealth updates the health manager with the current link targets.
// In a running daemon, the independent health scheduler picks up due probes;
// the synchronous fallback supports one-shot callers and tests.
func (d *Daemon) reconcileHealth(ctx context.Context) int {
	if d == nil || d.health == nil || d.health.Manager == nil {
		return 0
	}
	view := d.StateStore.common.ReadView()
	localZone := ""
	if view.State != nil {
		localZone = view.State.ManagedZone.String()
	}
	links, reconcile := d.linuxObservation.ipsecSnapshot()
	targets := linkstate.HealthTargets(buildLinkOutputs(links, reconcile), localZone)
	now := d.now()
	d.health.SetTargets(targets, now)
	return d.tickHealth(ctx, now)
}

// tickHealth runs due probes without rebuilding the target set. Keeping this
// separate from reconcileHealth lets the daemon honor health.interval even
// when IPsec reconciliation is infrequent.
func (d *Daemon) tickHealth(ctx context.Context, now time.Time) int {
	if d == nil || d.health == nil || d.health.Manager == nil {
		return 0
	}
	if d.health.asyncRunning {
		return 0
	}
	dispatched := d.health.Tick(ctx, now)
	if dispatched > 0 {
		d.handleHealthUpdate(now)
	}
	return dispatched
}

func (d *Daemon) handleHealthUpdate(now time.Time) {
	if d == nil || d.health == nil || d.health.Manager == nil {
		return
	}
	if d.health.spool != nil {
		if err := d.health.spool.Append(now, healthSpoolSamples(d.healthStatusResponse())); err != nil && !errors.Is(err, healthspool.ErrNotConfigured) {
			d.logWarn("health", "spool_write_failed", map[string]any{"error": err})
		}
	}
	d.notifyObserver("health_updated", d.observerHealthLinkIDsPayload())
}

func healthSpoolSamples(links []healthLinkJSON) []healthspool.Sample {
	samples := make([]healthspool.Sample, 0, len(links))
	for _, link := range links {
		samples = append(samples, healthspool.Sample{
			ProbeID:       link.ProbeID,
			InstanceID:    link.InstanceID,
			ProbeRole:     link.ProbeRole,
			InterfaceName: link.InterfaceName,
			State:         link.State,
			ProbeType:     link.ProbeType,
			RTTMs:         link.LastRTTMs,
			LossRatioPct:  link.LossRatio,
			JitterMs:      link.JitterMs,
			Sent:          link.Sent,
			Received:      link.Received,
			Lost:          link.Lost,
		})
	}
	return samples
}

// healthStatusResponse builds the control API response for `health_status`.
func (d *Daemon) healthStatusResponse() []healthLinkJSON {
	if d == nil || d.health == nil || d.health.Manager == nil {
		return nil
	}
	now := d.now()
	snapshot := d.health.Snapshot(now)
	out := make([]healthLinkJSON, 0, len(snapshot))
	for _, h := range snapshot {
		view := healthLinkHealthView{
			ProbeID:         h.ProbeID,
			InstanceID:      h.InstanceID,
			ProbeRole:       h.ProbeRole,
			InterfaceName:   h.InterfaceName,
			State:           h.State,
			ProbeType:       h.ProbeType,
			Sent:            h.Sent,
			Received:        h.Received,
			Lost:            h.Lost,
			LossRatio:       h.LossRatio,
			LastRTT:         h.LastRTT,
			EWMARTT:         h.EWMARTT,
			P50RTT:          h.P50RTT,
			P95RTT:          h.P95RTT,
			P99RTT:          h.P99RTT,
			Jitter:          h.Jitter,
			ConsecutiveFail: h.ConsecutiveFail,
			LastError:       h.LastError,
			NextProbeUnix:   h.NextProbeAt.Unix(),
			CutoverBlocking: h.CutoverBlocking,
		}
		out = append(out, healthLinkJSONFromHealth(view))
	}
	return out
}

// showHealth prints the current link health state to stdout.
func showHealth(sortBy string, verbose bool) error {
	sortBy = strings.ToLower(strings.TrimSpace(sortBy))
	if sortBy != inspect.HealthSortPeer && sortBy != inspect.HealthSortRTT {
		return cli.Exit("--sort must be peer or rtt", 1)
	}
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	view, online, err := readCanonicalViewViaControl[inspect.HealthDebugView](rt, controlRequest{Method: "health_status"})
	if err != nil {
		return err
	}
	if !online {
		return fmt.Errorf("daemon control socket unavailable; health runtime state requires a running daemon")
	}
	return inspecttext.WriteHealth(os.Stdout, view, sortBy, verbose)
}

func healthViewFromOwners(common corestate.View, links map[string]linkInstanceState, reconcile *ipsecObservationSummary, live []healthLinkJSON) inspect.HealthDebugView {
	view := inspect.HealthDebugView{Live: inspectHealthLiveLinks(live)}
	if common.State == nil {
		return view
	}
	view.Targets = inspectHealthProbeTargets(linkstate.HealthTargets(buildLinkOutputs(links, reconcile), string(common.State.ManagedZone)))
	return view
}

func inspectHealthProbeTargets(targets []health.ProbeTarget) []inspect.HealthProbeTargetView {
	out := make([]inspect.HealthProbeTargetView, 0, len(targets))
	for _, target := range targets {
		out = append(out, inspect.HealthProbeTargetView{
			ProbeID:         target.ProbeID,
			InstanceID:      target.InstanceID,
			GroupID:         target.GroupID,
			PeerZone:        target.PeerZone,
			LocalZone:       target.LocalZone,
			Overlay:         target.Overlay,
			NetNS:           target.NetNS,
			InterfaceName:   target.InterfaceName,
			UnderlayFamily:  target.UnderlayFamily,
			LocalTunnelAddr: target.LocalTunnelAddr.String(),
			PeerTunnelAddr:  target.PeerTunnelAddr.String(),
			Generation:      target.Generation,
			ProbeRole:       target.ProbeRole,
			Role:            target.Role,
			State:           target.State,
			Staged:          target.Staged,
		})
	}
	return out
}

func inspectHealthLiveLinks(links []healthLinkJSON) []inspect.HealthLiveView {
	out := make([]inspect.HealthLiveView, 0, len(links))
	for _, link := range links {
		out = append(out, inspect.HealthLiveView{
			ProbeID:         link.ProbeID,
			InstanceID:      link.InstanceID,
			ProbeRole:       link.ProbeRole,
			State:           link.State,
			ProbeType:       link.ProbeType,
			Sent:            link.Sent,
			Received:        link.Received,
			Lost:            link.Lost,
			LossRatio:       link.LossRatio,
			LastRTTMs:       link.LastRTTMs,
			EWMARTTMs:       link.EWMARTTMs,
			P50RTTMs:        link.P50RTTMs,
			P95RTTMs:        link.P95RTTMs,
			P99RTTMs:        link.P99RTTMs,
			JitterMs:        link.JitterMs,
			ConsecutiveFail: link.ConsecutiveFail,
			LastError:       link.LastError,
			CutoverBlocking: link.CutoverBlocking,
		})
	}
	return out
}
