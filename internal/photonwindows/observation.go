package photonwindows

import (
	"cmp"
	"context"
	"errors"
	"net"
	"net/netip"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/gossipview"
	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

var ErrDaemonNotRunning = errors.New("Windows daemon is not running")

// Observation is a detached, bounded sample from the daemon's event owner.
// Configured addresses describe the attached device, never pending intentions.
type NodeAddressObservation struct {
	Node      string       `json:"node"`
	Prefix    netip.Prefix `json:"prefix"`
	Announced bool         `json:"announced"`
}

type Observation struct {
	NodeAddresses          []NodeAddressObservation  `json:"node_addresses,omitempty"`
	NodeAddressesTruncated bool                      `json:"node_addresses_truncated,omitempty"`
	Connections            []ConnectionObservation   `json:"connections"`
	ConnectionsTruncated   bool                      `json:"connections_truncated"`
	Running                bool                      `json:"running"`
	ObservedAt             time.Time                 `json:"observed_at"`
	Revision               uint64                    `json:"revision"`
	Admission              gossip.AdmissionDiagnosis `json:"admission"`
	Readiness              ReadinessObservation      `json:"readiness"`
	Gateway                GatewayObservation        `json:"gateway"`
	TunnelReady            bool                      `json:"tunnel_ready"`
	UDPAddress             string                    `json:"udp_address"`
	Wintun                 WintunObservation         `json:"wintun"`
	IKE                    IKEObservation            `json:"ike"`
	Babel                  BabelObservation          `json:"babel"`
	gossipview.View
	RoutesTruncated bool `json:"routes_truncated"`
	ipv4RouteReady  bool
	ipv6RouteReady  bool
}
type WintunObservation struct {
	Configured  bool           `json:"configured"`
	Truncated   bool           `json:"truncated"`
	Addresses   []netip.Prefix `json:"addresses"`
	SplitRoutes []netip.Prefix `json:"split_routes"`
}
type IKEObservation struct {
	AttemptActive         bool   `json:"attempt_active"`
	AttemptGateway        string `json:"attempt_gateway"`
	AttemptRemoteEndpoint string `json:"attempt_remote_endpoint"`
	AttemptGeneration     uint64 `json:"attempt_generation"`
	// SendAttempts counts completed whole exchange sends, including the first,
	// not individual fragments/datagrams. The deadline is zero without pending IKE.
	SendAttempts     int                    `json:"send_attempts"`
	NextRetransmitAt time.Time              `json:"next_retransmit_at"`
	RetryAt          time.Time              `json:"retry_at"`
	LastEvent        string                 `json:"last_event"`
	LastEventAt      time.Time              `json:"last_event_at"`
	LastFailure      *IKEFailureObservation `json:"last_failure,omitempty"`
	LastRejection    *IKEFailureObservation `json:"last_rejection,omitempty"`
	Phase            string                 `json:"phase"`
	Live             bool                   `json:"live"`
	MOBIKE           bool                   `json:"mobike"`
	Gateway          string                 `json:"gateway"`
	Generation       uint64                 `json:"generation"`
	ExpiresAt        time.Time              `json:"expires_at"`
	ChildLive        bool                   `json:"child_live"`
	ChildExpiresAt   time.Time              `json:"child_expires_at"`
}
type BabelObservation struct {
	Live     bool               `json:"live"`
	Local    netip.Addr         `json:"local,omitempty"`
	Neighbor netip.Addr         `json:"neighbor"`
	Routes   []RouteObservation `json:"routes"`
}
type RouteObservation struct {
	Peer         string       `json:"peer,omitempty"`
	Prefix       netip.Prefix `json:"prefix"`
	SourcePrefix netip.Prefix `json:"source_prefix"`
	Origin       string       `json:"origin"` // Unknown for gateway-forwarded Babel routes.
	Metric       uint16       `json:"metric"`
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
	case d.observations <- meshObservationRequest{ctx: ctx, reply: result}:
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
	out.Wintun = observeWintun(leaf)
	current := revalidateActiveGateway(config, view, plan, now)
	out.Gateway = observeGatewayPlan(plan, current)
	out.IKE = tunnel.observeIKE()
	binding, err := localTransportAuthorization(config, view, now)
	if err == nil && binding == tunnel.localAuthorization && tunnel.phase == 3 && tunnel.failed == nil && tunnel.session != nil && now.Before(tunnel.ikeExpiresAt) && tunnel.current(current) {
		out.IKE.Live, out.IKE.Gateway = true, string(tunnel.plan.Selected.Zone)
		out.IKE.Generation, out.IKE.ExpiresAt = tunnel.generation, tunnel.ikeExpiresAt
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
			origins := p.localOrigins(config, view, now)
			hosts, _ := leafDeviceIntent(config, view, now)
			out.observeRoutes(candidates, origins, hosts, now)
		}
	}
	out.observeGossipPeers(view, now, driver)
	if !out.TunnelReady && !out.Admission.Pending {
		out.Readiness = observeLeafReadiness(config, view, now)
	}
	return out
}
func observeWintun(leaf *leafRuntime) WintunObservation {
	var out WintunObservation
	if leaf.device != nil {
		out = WintunObservation{Configured: true, Addresses: slices.Clone(leaf.attachment.addresses), SplitRoutes: slices.Clone(leaf.attachment.routes)}
		if len(out.Addresses) > 256 {
			out.Addresses = out.Addresses[:256]
			out.Truncated = true
		}
		if len(out.SplitRoutes) > 256 {
			out.SplitRoutes = out.SplitRoutes[:256]
			out.Truncated = true
		}
	}
	return out
}

func (out *Observation) observeRoutes(candidates []sadr.Route, origins []babel.Origin, hosts []netip.Prefix, now time.Time) {
	// Callers have already authorized every route in this detached slice.
	authorize := func(sadr.Route) bool { return true }
	// Mirror lookupBabelRoutes' explicit host restriction for the sample.
	origins = slices.DeleteFunc(origins, func(origin babel.Origin) bool {
		return !slices.Contains(hosts, origin.Prefix)
	})
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
			if out.Wintun.Configured && len(selected) > 0 {
				out.TunnelReady = true
				if source.Is4() {
					out.ipv4RouteReady = true
				} else {
					out.ipv6RouteReady = true
				}
			}
			for _, route := range selected {
				r := RouteObservation{Prefix: route.Destination, SourcePrefix: route.Source, Metric: route.Metric}
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

func (out *Observation) observeGossipPeers(view corestate.View, now time.Time, driver *corehost.GossipDriver) {
	out.View = gossipview.Live(view, driver, now)
	out.View.LimitPeers(256, 256<<10)
}

func boundedObservationText(s string) string {
	if len(s) > 256 {
		return s[:256]
	}
	return s
}

// CompareRoutePrefixes orders observed prefixes by network, length, and address.
func CompareRoutePrefixes(a, b netip.Prefix) int {
	return cmp.Or(a.Masked().Addr().Compare(b.Masked().Addr()), cmp.Compare(a.Bits(), b.Bits()), a.Addr().Compare(b.Addr()))
}
