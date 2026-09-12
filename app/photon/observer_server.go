package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecthttp "github.com/HiggsNet/photon/internal/inspect/http"
	"github.com/HiggsNet/photon/internal/observability/healthspool"
	"github.com/HiggsNet/photon/internal/observer"
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type observerServer struct {
	daemon   *Daemon
	config   observerConfig
	provider *observerProvider
	server   *observer.Server
	hub      *observer.Hub
}

type observerProvider struct {
	daemon *Daemon
}

// newObserverServer creates a new read-only HTTP observer from the daemon
// service and observer configuration. Returns nil if observer is disabled.
func newObserverServer(d *Daemon, cfg observerConfig) *observerServer {
	if !cfg.Enabled || d == nil {
		return nil
	}
	provider := &observerProvider{daemon: d}
	server := observer.NewServer(provider, observer.Config{
		Enabled:            cfg.Enabled,
		BindAddr:           cfg.BindAddr,
		Port:               cfg.Port,
		EventBufferSeconds: cfg.EventBufferSeconds,
	})
	if server == nil {
		return nil
	}
	return &observerServer{
		daemon:   d,
		config:   cfg,
		provider: provider,
		server:   server,
		hub:      server.Hub(),
	}
}

// startObserverServer starts the HTTP observer if enabled. It returns a
// cleanup function that gracefully shuts down the server.
func (d *Daemon) startObserverServer(_ context.Context) (func(), error) {
	if d == nil || d.App == nil || d.App.Config == nil {
		return func() {}, nil
	}
	cfg := d.App.Config.Observer
	if !cfg.Enabled {
		return func() {}, nil
	}
	srv := newObserverServer(d, cfg)
	if srv == nil {
		return func() {}, nil
	}
	// Wire the observer hub so notifyObserver can broadcast events.
	d.observerHub = srv.hub
	addr := cfg.listenAddr()
	ln, err := net.Listen("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("observer listen %s: %w", addr, err)
	}
	httpServer := observer.DefaultHTTPServer(srv.handler())
	go func() {
		_ = httpServer.Serve(ln)
	}()
	if !cfg.isLoopbackBind() {
		d.logWarn("observer", "non_loopback_bind", map[string]any{
			"addr":    addr,
			"warning": "observer is bound to a non-loopback address; ensure external access control is in place",
		})
	}
	d.logInfo("observer", "started", map[string]any{"addr": addr})
	return func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(shutdownCtx)
	}, nil
}

// notifyObserver broadcasts an SSE event to all subscribers. Safe to call
// even when the observer is disabled (no-op if hub is nil).
func (d *Daemon) notifyObserver(eventType string, payload any) {
	if d == nil || d.observerHub == nil {
		return
	}
	d.observerHub.Broadcast(observer.Event{Type: eventType, Payload: payload})
}

// observerIDsPayload builds a lightweight {key: [sorted ids]} event payload.
// Payloads carry ids only — never diffs or large objects. Returns nil when
// there are no ids so the payload field is omitted entirely.
func observerIDsPayload(key string, ids []string) map[string]any {
	if len(ids) == 0 {
		return nil
	}
	sort.Strings(ids)
	return map[string]any{key: ids}
}

// observerLinkIDsPayload returns {link_ids: [...]} from the live observation.
func (d *Daemon) observerLinkIDsPayload() any {
	if d == nil {
		return nil
	}
	links, _ := d.linuxObservation.ipsecSnapshot()
	ids := make([]string, 0, len(links))
	for id := range links {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil
	}
	return observerIDsPayload("link_ids", ids)
}

// observerPeerIDsPayload returns {peer_ids: [...]} from the common gossip
// checkpoint.
func (d *Daemon) observerPeerIDsPayload() any {
	if d == nil || d.State == nil {
		return nil
	}
	view := d.State.Common.ReadView()
	if view.Gossip == nil {
		return nil
	}
	ids := make([]string, 0, len(view.Gossip.Peers))
	for id := range view.Gossip.Peers {
		ids = append(ids, id)
	}
	if len(ids) == 0 {
		return nil
	}
	return observerIDsPayload("peer_ids", ids)
}

// observerHealthLinkIDsPayload returns {link_ids: [...]} derived from the
// health manager's current target snapshot.
func (d *Daemon) observerHealthLinkIDsPayload() any {
	if d == nil || d.health == nil || d.health.Manager == nil {
		return nil
	}
	snapshot := d.health.Snapshot(d.now())
	ids := make([]string, 0, len(snapshot))
	for _, h := range snapshot {
		if h.InstanceID != "" {
			ids = append(ids, h.InstanceID)
		}
	}
	return observerIDsPayload("link_ids", ids)
}

// handler returns the HTTP handler for the observer, including REST APIs,
// SSE events, and static UI.
func (s *observerServer) handler() http.Handler {
	return s.server.Handler()
}

func (p *observerProvider) Status() (any, error) {
	return daemonStatusView(p.daemon), nil
}

func (p *observerProvider) Zones(zoneFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.State == nil {
		return inspect.ZonesView{Zones: []inspect.ZoneSummaryView{}}, nil
	}
	now := d.now()
	zp := zone.ZonePath(zoneFilter)
	view := d.State.Common.ReadView()
	if view.State == nil || view.State.Network == nil {
		return inspect.ZonesView{Zones: []inspect.ZoneSummaryView{}}, nil
	}
	if zp != "" {
		zs := view.State.Network.Zones[zp]
		if zs == nil {
			return nil, observer.Errorf(http.StatusNotFound, "zone not found")
		}
		return inspect.BuildZoneDetail(view.State.Network, zp, now, true), nil
	}
	return inspect.BuildZonesView(view.State.Network, now), nil
}

func (p *observerProvider) Peers(peerFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.State == nil {
		return inspect.PeersView{Peers: []inspect.PeerView{}}, nil
	}
	view := d.State.Common.ReadView()
	if view.State == nil {
		return inspect.PeersView{Peers: []inspect.PeerView{}}, nil
	}
	now := d.now()
	observabilitySnapshots := d.peerObservabilitySnapshots()
	peers := inspect.BuildGossipPeersView(view, gossipPeersOptions(d.gossipDriver.GossipConfig(), observabilitySnapshots, now))
	if peerFilter != "" {
		for _, peer := range peers.Peers {
			if peer.PeerID == peerFilter {
				return peer, nil
			}
		}
		return nil, observer.Errorf(http.StatusNotFound, "peer not found")
	}
	return peers, nil
}

func (d *Daemon) peerObservabilitySnapshots() map[string]observability.PeerDiagnostics {
	if d == nil || d.gossipDriver == nil || d.gossipDriver.Observability == nil {
		return nil
	}
	now := d.now()
	return d.gossipDriver.Observability.Snapshots(now)
}

func (p *observerProvider) Links(linkFilter string) (any, error) {
	d := p.daemon
	if d == nil || d.State == nil {
		return inspecthttp.LinksResponse{Instances: []inspecthttp.LinkJSON{}}, nil
	}
	health := d.healthSamples()
	observedLinks, reconcile := d.linuxObservation.ipsecSnapshot()
	var birdInstances map[string]*bird.InstanceObservation
	if routingObserved := d.linuxObservation.routingSnapshot(); routingObserved != nil {
		birdInstances = routingObserved.Instances
	}
	build := buildStoredLinkInspection(observerRuntime(d), observedLinks, reconcile, birdInstances, health)
	view := build.Inspection
	// Single link detail
	if linkFilter != "" {
		for _, link := range view.Links {
			if link.ID == linkFilter {
				return inspecthttp.LinkFromInspect(link), nil
			}
		}
		return nil, observer.Errorf(http.StatusNotFound, "link not found")
	}
	return inspecthttp.LinksFromInspection(view), nil
}

func observerRuntime(d *Daemon) *AppContext {
	if d == nil {
		return nil
	}
	return d.App
}

func healthLinksWithContext(view inspect.HealthView, observedLinks map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary) []inspecthttp.HealthContextItem {
	input := inspecthttp.HealthContextInput{View: view}
	desiredByID := map[string]photonstate.DesiredLinkState{}
	if reconcile != nil {
		desiredByID = desiredByInstanceID(reconcile.Desired)
	}
	input.Instances = inspectHealthInstances(observedLinks)
	input.Desired = inspectHealthDesired(desiredByID)
	return inspecthttp.BuildHealthContext(input)
}

func inspectHealthInstances(instances map[string]ipsec.LinkInstance) map[string]inspecthttp.HealthInstanceContextInput {
	out := make(map[string]inspecthttp.HealthInstanceContextInput, len(instances))
	for id, inst := range instances {
		out[id] = inspecthttp.HealthInstanceContextInput{
			ID:            inst.ID,
			PeerZone:      inst.PeerZone,
			GroupID:       inst.GroupID,
			InterfaceName: inst.InterfaceName,
			Endpoint:      inst.Endpoint,
			ActualState:   inst.ActualState,
			Instance:      inst,
		}
	}
	return out
}

func inspectHealthDesired(desiredByID map[string]photonstate.DesiredLinkState) map[string]inspecthttp.HealthDesiredContextInput {
	out := make(map[string]inspecthttp.HealthDesiredContextInput, len(desiredByID))
	for id, desired := range desiredByID {
		out[id] = inspecthttp.HealthDesiredContextInput{
			InstanceID:      desired.InstanceID,
			PeerZone:        desired.PeerZone,
			GroupID:         desired.GroupID,
			InterfaceName:   desired.InterfaceName,
			LocalTunnelAddr: desired.LocalTunnelAddr,
			PeerTunnelAddr:  desired.PeerTunnelAddr,
			Desired:         desired,
		}
	}
	return out
}

func (p *observerProvider) Health(linkFilter string) (any, error) {
	d := p.daemon
	var common corestate.View
	var observedLinks map[string]ipsec.LinkInstance
	var reconcile *ipsecObservationSummary
	if d != nil && d.State != nil {
		common = d.State.Common.ReadView()
		observedLinks, reconcile = d.linuxObservation.ipsecSnapshot()
	}
	view := healthViewFromOwners(common, observedLinks, reconcile, d.healthSamples())
	contextualLinks := healthLinksWithContext(view, observedLinks, reconcile)
	// Single link health detail
	if linkFilter != "" {
		for _, item := range contextualLinks {
			if item.Health.InstanceID == linkFilter || item.Health.ProbeID == linkFilter {
				return item, nil
			}
		}
		return nil, observer.Errorf(http.StatusNotFound, "health data not found for link %s", linkFilter)
	}
	return inspecthttp.HealthResponse{
		Datasource: daemonHealthDatasource(d),
		Links:      contextualLinks,
	}, nil
}

func (p *observerProvider) OpenMetrics() (string, error) {
	d := p.daemon
	config := observerAppConfig(d)
	if config == nil || !config.Health.MetricsEnabled {
		return "", fmt.Errorf("health metrics are not enabled")
	}
	if d == nil || d.health == nil || d.health.Manager == nil {
		return "", fmt.Errorf("health manager is not configured")
	}
	links := d.health.Snapshot(observerNow(d))
	errorsTotal := make(map[string]int, len(links))
	for _, link := range links {
		key := link.ProbeID
		if key == "" {
			key = link.InstanceID
		}
		errorsTotal[key] = d.health.ErrorsTotal(key)
	}
	var output bytes.Buffer
	if err := health.RenderOpenMetrics(&output, health.CollectMetrics(links), errorsTotal); err != nil {
		return "", err
	}
	return output.String(), nil
}

func (p *observerProvider) HealthSeries(linkID string, query map[string]string) (any, error) {
	config := observerAppConfig(p.daemon)
	if config == nil {
		return nil, observer.Errorf(http.StatusServiceUnavailable, "health datasource not configured")
	}
	rng, err := parseOptionalDuration(query["range"], time.Hour, "range")
	if err != nil {
		return nil, observer.APIError{StatusCode: http.StatusBadRequest, Err: err}
	}
	step, err := parseOptionalDuration(query["step"], 30*time.Second, "step")
	if err != nil {
		return nil, observer.APIError{StatusCode: http.StatusBadRequest, Err: err}
	}
	if p.daemon == nil || p.daemon.health == nil || p.daemon.health.spool == nil {
		return nil, observer.Errorf(http.StatusServiceUnavailable, "health datasource not_configured")
	}
	result, err := p.daemon.health.spool.Query(linkID, healthspool.SeriesQuery{
		Metric:    query["metric"],
		ProbeRole: query["probe_role"],
		Range:     rng,
		Step:      step,
		Now:       observerNow(p.daemon),
	})
	if errors.Is(err, healthspool.ErrNotConfigured) {
		return nil, observer.Errorf(http.StatusServiceUnavailable, "health datasource not_configured")
	}
	if err != nil {
		return nil, observer.APIError{StatusCode: http.StatusBadRequest, Err: err}
	}
	return inspecthttp.HealthSeriesResponse{
		Datasource: p.daemon.health.spool.Config().Datasource(),
		LinkID:     linkID,
		Series:     result,
	}, nil
}

func daemonHealthDatasource(d *Daemon) map[string]any {
	if d == nil || d.health == nil || d.health.spool == nil {
		return healthspool.Config{}.Datasource()
	}
	return d.health.spool.Config().Datasource()
}

func observerAppConfig(d *Daemon) *appConfig {
	if d == nil || d.App == nil {
		return nil
	}
	return d.App.Config
}

func observerNow(d *Daemon) time.Time {
	if d != nil {
		return d.now()
	}
	return time.Now()
}

func parseOptionalDuration(raw string, fallback time.Duration, name string) (time.Duration, error) {
	if strings.TrimSpace(raw) == "" {
		return fallback, nil
	}
	d, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("invalid %s: %q", name, raw)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s must be positive", name)
	}
	return d, nil
}

func (p *observerProvider) Routes() (any, error) {
	d := p.daemon
	if d == nil || d.State == nil {
		return &inspecthttp.RoutesResponse{}, nil
	}
	view := d.State.Common.ReadView()
	if view.State == nil || view.State.Network == nil {
		return &inspecthttp.RoutesResponse{}, nil
	}
	ars, err := routing.BuildAuthorizedRouteSet(view.State.Network, d.now())
	if err != nil {
		return &inspecthttp.RoutesResponse{}, nil
	}
	return inspecthttp.RoutesFromAuthorizedSet(view.State.ManagedZone, ars), nil
}

func (p *observerProvider) Bird() (any, error) {
	d := p.daemon
	if d == nil || d.State == nil {
		return inspecthttp.BirdResponse{Instances: map[string]any{}}, nil
	}
	routingReconcile := d.linuxObservation.routingSnapshot()
	lastRoutingError := ""
	var instances map[string]*bird.InstanceObservation
	if routingReconcile != nil {
		lastRoutingError = routingReconcile.LastError
		instances = routingReconcile.Instances
	}
	return inspecthttp.BirdResponse{
		Instances:        instances,
		LastRoutingError: lastRoutingError,
	}, nil
}
