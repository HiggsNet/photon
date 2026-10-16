package photonwindows

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

var ErrDaemonNotRunning = errors.New("Windows daemon is not running")

// Observation is a detached, bounded sample from the daemon's event owner.
// Configured addresses describe the attached device, never pending intentions.
type Observation struct {
	Running         bool                      `json:"running"`
	ObservedAt      time.Time                 `json:"observed_at"`
	Revision        uint64                    `json:"revision"`
	Admission       gossip.AdmissionDiagnosis `json:"admission"`
	Readiness       ReadinessObservation      `json:"readiness"`
	TunnelReady     bool                      `json:"tunnel_ready"`
	UDPAddress      string                    `json:"udp_address"`
	Wintun          WintunObservation         `json:"wintun"`
	IKE             IKEObservation            `json:"ike"`
	Babel           BabelObservation          `json:"babel"`
	Peers           []PeerObservation         `json:"peers"`
	PeersTruncated  bool                      `json:"peers_truncated"`
	RoutesTruncated bool                      `json:"routes_truncated"`
}
type WintunObservation struct {
	Configured  bool           `json:"configured"`
	Truncated   bool           `json:"truncated"`
	Addresses   []netip.Prefix `json:"addresses"`
	SplitRoutes []netip.Prefix `json:"split_routes"`
}
type IKEObservation struct {
	Live           bool      `json:"live"`
	Gateway        string    `json:"gateway"`
	Generation     uint64    `json:"generation"`
	ExpiresAt      time.Time `json:"expires_at"`
	ChildLive      bool      `json:"child_live"`
	ChildExpiresAt time.Time `json:"child_expires_at"`
}
type BabelObservation struct {
	Live     bool               `json:"live"`
	Local    netip.Addr         `json:"local,omitempty"`
	Neighbor netip.Addr         `json:"neighbor"`
	Routes   []RouteObservation `json:"routes"`
}
type RouteObservation struct {
	Prefix       netip.Prefix `json:"prefix"`
	SourcePrefix netip.Prefix `json:"source_prefix"`
	Origin       string       `json:"origin"`
	Metric       uint16       `json:"metric"`
}
type PeerObservation struct {
	Peer          string    `json:"peer"`
	PullState     string    `json:"pull_state"`
	UpdatedAt     time.Time `json:"updated_at"`
	PullAttempts  int64     `json:"pull_attempts"`
	PullSuccesses int64     `json:"pull_successes"`
	PullFailures  int64     `json:"pull_failures"`
}

// Started closes once the system control plane has initialized successfully.
// It does not indicate IKE, Babel, address admission, or tunnel readiness.
func (d *Daemon) Started() <-chan struct{} { return d.ready }

// Stop cancels the one run and joins all resource cleanup. IPC is owned by the
// caller and must remain available until it has sent the stop acknowledgement.
func (d *Daemon) Stop(ctx context.Context) error {
	d.lifecycle.Lock()
	cancel := d.runCancel
	d.lifecycle.Unlock()
	if cancel == nil {
		return ErrDaemonNotRunning
	}
	cancel()
	select {
	case <-d.done:
		d.lifecycle.Lock()
		err := d.runErr
		d.lifecycle.Unlock()
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (d *Daemon) Observe(ctx context.Context) (Observation, error) {
	select {
	case <-d.done:
		return Observation{}, net.ErrClosed
	default:
	}
	select {
	case <-d.ready:
	default:
		return Observation{}, ErrDaemonNotRunning
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	result := make(chan Observation, 1)
	select {
	case d.observations <- result:
	case <-d.done:
		return Observation{}, net.ErrClosed
	case <-ctx.Done():
		return Observation{}, ctx.Err()
	}
	select {
	case observation := <-result:
		return observation, nil
	case <-d.done:
		return Observation{}, net.ErrClosed
	case <-ctx.Done():
		return Observation{}, ctx.Err()
	}
}

func observeRuntime(config *Config, view corestate.View, plan GatewayPlan, now time.Time, socket *packetSockets, tunnel *gatewayTunnel, leaf *leafRuntime, driver *corehost.GossipDriver) Observation {
	out := Observation{Running: true, ObservedAt: now, Revision: uint64(view.Revision), Admission: driver.AdmissionDiagnosis(now)}
	if socket != nil {
		if addr := socket.LocalAddr(); addr != nil {
			out.UDPAddress = addr.String()
		}
	}
	if leaf.device != nil {
		out.Wintun = WintunObservation{Configured: true, Addresses: slices.Clone(leaf.attachment.addresses), SplitRoutes: slices.Clone(leaf.attachment.routes)}
		if len(out.Wintun.Addresses) > 256 {
			out.Wintun.Addresses = out.Wintun.Addresses[:256]
			out.Wintun.Truncated = true
		}
		if len(out.Wintun.SplitRoutes) > 256 {
			out.Wintun.SplitRoutes = out.Wintun.SplitRoutes[:256]
			out.Wintun.Truncated = true
		}
	}
	current := revalidateActiveGateway(config, view, plan, now)
	binding, err := localTransportAuthorization(config, view, now)
	if err == nil && binding == tunnel.localAuthorization && tunnel.phase == 3 && tunnel.failed == nil && tunnel.session != nil && now.Before(tunnel.ikeExpiresAt) && tunnel.current(current) {
		out.IKE = IKEObservation{Live: true, Gateway: string(tunnel.plan.Selected.Zone), Generation: tunnel.generation, ExpiresAt: tunnel.ikeExpiresAt}
		if tunnel.data != nil && now.Before(tunnel.expiresAt) && tunnel.data.current(tunnel.generation, tunnel.data.active, current) {
			out.IKE.ChildLive = true
			out.IKE.ChildExpiresAt = tunnel.expiresAt
		}
	}
	if p := leaf.pipeline; p != nil {
		if _, valid := p.current(config, view, plan, now); valid {
			out.Babel.Local = p.local
			out.Babel.Live = p.leaf.NeighborLive(now)
			if out.Babel.Live {
				out.Babel.Neighbor = p.peer
			}
			authorize := currentBabelRouteAuthorizer(config, view, now)
			candidates := p.leaf.Candidates(now, authorize)
			// Candidates has just checked every complete route against the
			// sampled authorization. Reuse those exact verdicts during SADR
			// selection instead of rescanning permissions for every lookup.
			allowed := make(map[sadr.Route]bool, len(candidates))
			for _, route := range candidates {
				allowed[route] = true
			}
			authorize = func(route sadr.Route) bool { return allowed[route] }
			origins := p.localOrigins(config, view, now)
			hosts, _ := leafDeviceIntent(config, view, now)
			// Mirror lookupBabelRoutes' explicit host restriction once for the
			// sample. p.current above has checked the current SA/gateway/local
			// binding; view and now cannot change within this owner event.
			origins = slices.DeleteFunc(origins, func(origin babel.Origin) bool {
				return !slices.Contains(hosts, origin.Prefix)
			})
			identities := currentBabelOrigins(config, view, now)
			// Bound both response size and work. A truncation is explicit; no omitted
			// candidate is presented as an installed or selected route.
			lookups := 0
			seen := make(map[RouteObservation]bool)
		outer:
			for _, candidate := range candidates {
				for _, origin := range origins {
					source := origin.Prefix.Addr()
					if source.BitLen() != candidate.Destination.Addr().BitLen() || candidate.Source.IsValid() && !candidate.Source.Contains(source) {
						continue
					}
					if lookups == 256 {
						out.RoutesTruncated = true
						break outer
					}
					lookups++
					selected := sadr.Lookup(candidates, source, candidate.Destination.Addr(), now, authorize)
					out.TunnelReady = out.TunnelReady || leaf.device != nil && len(selected) > 0
					for _, route := range selected {
						r := RouteObservation{Prefix: route.Destination, SourcePrefix: route.Source, Origin: string(identities[route.RouterID]), Metric: route.Metric}
						if !seen[r] {
							if len(out.Babel.Routes) == 256 {
								out.RoutesTruncated = true
								break outer
							}
							seen[r] = true
							out.Babel.Routes = append(out.Babel.Routes, r)
						}
					}
				}
			}
		}
	}
	if driver != nil && driver.Observability != nil {
		peers := driver.Observability.Snapshots(now)
		ids := make([]string, 0, len(peers))
		for id := range peers {
			ids = append(ids, id)
		}
		slices.Sort(ids)
		if len(ids) > 256 {
			ids = ids[:256]
			out.PeersTruncated = true
		}
		for _, id := range ids {
			p := peers[id]
			r := PeerObservation{Peer: boundedObservationText(id), PullState: boundedObservationText(p.ActivePullState)}
			if p.ActivePullUpdatedUnix != 0 {
				r.UpdatedAt = time.Unix(p.ActivePullUpdatedUnix, 0)
			}
			if p.ObjectPullStats != nil {
				r.PullAttempts = p.ObjectPullStats.Attempts
				r.PullSuccesses = p.ObjectPullStats.Successes
				r.PullFailures = p.ObjectPullStats.Failures
			}
			out.Peers = append(out.Peers, r)
		}
	}
	if !out.TunnelReady && !out.Admission.Pending {
		out.Readiness = observeLeafReadiness(config, view, now)
	}
	return out
}
func boundedObservationText(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return s
}
