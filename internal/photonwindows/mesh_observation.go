package photonwindows

import (
	"context"
	"encoding/json"
	"net/netip"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/babel"
	"github.com/HiggsNet/photon/internal/photonclient/sadr"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
)

// Connections reports actual independent peer lifetimes. The legacy summary
// describes one representative connection; it is never an exclusive gateway.
type ConnectionObservation struct {
	Peer        string         `json:"peer"`
	IKE         IKEObservation `json:"ike"`
	BabelLive   bool           `json:"babel_live"`
	TunnelReady bool           `json:"tunnel_ready"`
}

type meshObservationRequest struct {
	ctx   context.Context
	reply chan Observation
}

type meshObservationSnapshot struct {
	at         time.Time
	revision   corestate.VerifiedRevision
	plan       GatewayPlan
	udpAddress string
	peers      []meshPeerSnapshot
}

type meshPeerSnapshot struct {
	config                   *Config
	plan                     GatewayPlan
	pinned                   *GatewaySelection
	binding                  [32]byte
	phase                    uint8
	ike                      IKEObservation
	wintun                   WintunObservation
	babel                    BabelObservation
	ikeExpires, childExpires time.Time
	addresses                []netip.Addr
	routes                   []sadr.Route
}

// Only the packet owner reads live tunnels and Babel tables. The snapshot
// shares immutable plans and verified state and detaches mutable peer data.
func (m *meshRuntime) observationSnapshot(plan GatewayPlan) meshObservationSnapshot {
	now := time.Now()
	snapshot := meshObservationSnapshot{at: now, revision: m.state.Store().VerifiedRevision(), plan: plan}
	if addr := m.socket.LocalAddr(); addr != nil {
		snapshot.udpAddress = addr.String()
	}
	for _, p := range m.ordered() {
		snapshot.peers = append(snapshot.peers, captureMeshPeer(p, now))
	}
	return snapshot
}

func captureMeshPeer(p *meshPeer, now time.Time) meshPeerSnapshot {
	t := p.tunnel
	sample := meshPeerSnapshot{config: &p.config, plan: p.plan, phase: t.phase,
		ike: t.observeIKE(), wintun: observeWintun(p.leaf)}
	if t.phase == 3 && t.failed == nil && t.session != nil && now.Before(t.ikeExpiresAt) {
		sample.pinned, sample.binding, sample.ikeExpires = t.plan.Selected, t.localAuthorization, t.ikeExpiresAt
		if t.data != nil && now.Before(t.expiresAt) && t.data.current(t.generation, t.data.active, t.plan) {
			sample.childExpires = t.expiresAt
			if pipeline := p.leaf.pipeline; pipeline != nil && pipeline.generation == t.generation && pipeline.leaf != nil {
				sample.babel.Local = pipeline.local
				sample.babel.Live = pipeline.leaf.NeighborLive(now)
				if sample.babel.Live {
					sample.babel.Neighbor = pipeline.peer
				}
				sample.addresses = slices.Clone(pipeline.addresses)
				sample.routes = pipeline.leaf.SnapshotCandidates(now)
			}
		}
	}
	return sample
}

func (s meshObservationSnapshot) render(config *Config, view corestate.View, driver *corehost.GossipDriver, verifier *photoncrypto.Verifier) Observation {
	now := s.at
	out := Observation{Running: true, ObservedAt: now, Revision: uint64(view.Revision), UDPAddress: s.udpAddress,
		Admission: driver.AdmissionDiagnosisFromView(view, now)}
	current := GatewayPlan{Rejected: "gateway plan is stale or rejected"}
	if s.plan.Revision == view.Revision && s.plan.Rejected == "" {
		current = revalidateResolvedGatewaySelection(config, view, s.plan, now, verifier)
	}
	out.Gateway = observeGatewayPlan(s.plan, current)
	// All peers share the same local identity, IPAM and route permissions.
	// AllowedZones changes only the per-peer gateway selection.
	binding, bindingErr := localTransportAuthorizationWithVerifier(config, view, now, verifier)
	set := currentAuthorizedRouteSetWithVerifier(config, view, now, verifier)
	permissions := authorizedGatewayRoutesFromSet(config, set)
	hosts, _ := leafDeviceIntentFromSet(config, set)
	authorize := babelRouteAuthorizer(permissions, hosts)
	representative := -1
	connectionBytes := 2
	for i, p := range s.peers {
		sample := Observation{IKE: p.ike, Wintun: p.wintun}
		if p.pinned != nil && bindingErr == nil && binding == p.binding {
			selected := revalidateActiveGatewaySelection(p.config, view, p.plan, now, verifier).Selected
			if selected != nil && dataplaneGatewayEqual(*selected, *p.pinned) {
				sample.IKE.Live, sample.IKE.Gateway = true, string(p.pinned.Zone)
				sample.IKE.Generation, sample.IKE.ExpiresAt = p.ike.AttemptGeneration, p.ikeExpires
				sample.IKE.ChildLive, sample.IKE.ChildExpiresAt = !p.childExpires.IsZero(), p.childExpires
				sample.Babel = p.babel
				routes := slices.DeleteFunc(p.routes, func(route sadr.Route) bool { return !authorize(route) })
				babel.SortCandidates(routes)
				pipeline := gatewayBabelPipeline{addresses: p.addresses}
				sample.observeRoutes(routes, pipeline.originsFromRoutes(config, permissions), hosts, now)
			}
		}
		if !out.TunnelReady && (representative < 0 || p.phase > s.peers[representative].phase || sample.TunnelReady) {
			representative = i
			out.IKE, out.Wintun = sample.IKE, sample.Wintun
			out.Babel.Local, out.Babel.Live, out.Babel.Neighbor = sample.Babel.Local, sample.Babel.Live, sample.Babel.Neighbor
		}
		out.TunnelReady = out.TunnelReady || sample.TunnelReady
		peer := boundedObservationText(string(p.config.Gateway.AllowedZones[0]))
		connection := ConnectionObservation{Peer: peer, IKE: sample.IKE, BabelLive: sample.Babel.Live, TunnelReady: sample.TunnelReady}
		encoded, _ := json.Marshal(connection)
		if len(out.Connections) < 256 && connectionBytes+len(encoded)+1 <= 128<<10 {
			out.Connections = append(out.Connections, connection)
			connectionBytes += len(encoded) + 1
		} else {
			out.ConnectionsTruncated = true
		}
		out.RoutesTruncated = out.RoutesTruncated || sample.RoutesTruncated
		for _, route := range sample.Babel.Routes {
			if len(out.Babel.Routes) == 256 {
				out.RoutesTruncated = true
				break
			}
			route.Peer = peer
			out.Babel.Routes = append(out.Babel.Routes, route)
		}
	}
	if representative < 0 {
		out.IKE = (&gatewayTunnel{}).observeIKE()
	}
	out.observeGossipPeers(view, now, driver)
	if !out.TunnelReady && !out.Admission.Pending {
		out.Readiness = observeLeafReadinessFromSet(config, view, now, func() *routing.AuthorizedRouteSet { return set })
	}
	return out
}

// One worker accepts diagnostic requests. The packet owner only hands it a
// snapshot through a buffered reply, even if the caller has timed out.
func (d *Daemon) runObservations(ctx context.Context, snapshots chan<- chan meshObservationSnapshot, store *corestate.Store, driver *corehost.GossipDriver) {
	verifier := new(photoncrypto.Verifier)
	var views packetStateView
	for {
		select {
		case <-ctx.Done():
			return
		case request := <-d.observations:
			d.renderObservation(ctx, request, snapshots, store, &views, driver, verifier)
		}
	}
}

func (d *Daemon) renderObservation(ctx context.Context, request meshObservationRequest, snapshots chan<- chan meshObservationSnapshot, store *corestate.Store, views *packetStateView, driver *corehost.GossipDriver, verifier *photoncrypto.Verifier) {
	sampled := make(chan meshObservationSnapshot, 1)
	for {
		view := views.read(store)
		select {
		case <-ctx.Done():
			return
		case <-request.ctx.Done():
			return
		case snapshots <- sampled:
		}
		select {
		case <-ctx.Done():
			return
		case <-request.ctx.Done():
			return
		case snapshot := <-sampled:
			if snapshot.revision != view.Revision {
				continue
			}
			view.Gossip = store.ReadGossipCheckpoint()
			request.reply <- snapshot.render(d.config, view, driver, verifier)
			return
		}
	}
}
