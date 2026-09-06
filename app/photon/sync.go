package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const defaultSyncRoundTimeout = 5 * time.Second
const syncOnceResponderQuiet = 500 * time.Millisecond

var collectSyncLocalEndpoints = gossip.CollectLocalEndpointsWithReflectors

type SyncTransportDeps struct {
	KnownPeers map[string]*net.UDPAddr
	Replay     *gossip.ReplayWindow
	Quotas     *gossip.PeerQuotas
	Log        func(gossip.Event)
}

func defaultSyncTransportDeps(config *gossipStartupConfig, loggerConfig *appConfig) *SyncTransportDeps {
	return &SyncTransportDeps{
		KnownPeers: configuredKnownPeers(config),
		Replay:     gossip.NewReplayWindow(0),
		Quotas:     gossip.NewPeerQuotas(gossip.QuotaConfig{}),
		Log:        syncDebugLogger(loggerConfig),
	}
}

func (d *Daemon) now() time.Time {
	if d != nil && d.App != nil {
		return d.App.Now()
	}
	return time.Now()
}

func syncStatus(verbose bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.SyncStatusView](rt, controlRequest{Method: "sync_view", Verbose: verbose}); err != nil {
		return err
	} else if ok {
		fmt.Fprintf(os.Stdout, "daemon: online peer_id=%s\n", view.PeerID)
		return inspecttext.WriteSyncStatus(os.Stdout, view)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil {
		return errors.New("common state is not initialized")
	}
	config := gossipStartupConfigFromAppConfig(rt.Config, common.State)
	return inspecttext.WriteSyncStatus(os.Stdout, inspect.BuildSyncStatus(common, syncStatusOptions(config, rt.Now(), verbose)))
}

func syncStatusOptions(config *gossipStartupConfig, now time.Time, verbose bool) inspect.SyncStatusOptions {
	peers := gossipPeersOptions(config, nil, now)
	options := inspect.SyncStatusOptions{
		PeerID: config.PeerID, ListenAddr: config.ListenAddr,
		MaxDatagramBytes: config.MaxMessageBytes, MaxSyncZones: config.MaxSyncZones,
		MaxSyncRecords: config.MaxSyncRecords, Bootstrap: peers.Bootstrap, Now: now, Verbose: verbose,
	}
	return options
}

func syncServe(ctx context.Context) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	service, boltStore, err := openDaemon(rt, defaultDaemonInterval)
	if err != nil {
		return err
	}
	defer boltStore.Close()
	config := service.currentGossipConfig()
	logger := newAppLogger(rt.Config)
	transport, err := service.openGossipTransport()
	if err != nil {
		return err
	}
	service.updateDiscoveredPeers()
	err = service.gossipDriver.StartGossipTransport(ctx, transport, func(err error) {
		logger.Warn("transport", "receive_failed", map[string]any{"error": err})
	})
	if err != nil {
		return err
	}
	defer service.gossipDriver.Stop()
	if err := startObjectPullServer(ctx, service); err != nil {
		return err
	}
	if err := service.gossipDriver.StartGossipObjectPullWorkers(ctx, service.objectPullExecutor, 0, 0); err != nil {
		return err
	}
	stopControl, err := service.startControlServer(ctx)
	if err != nil {
		return err
	}
	defer stopControl()
	logger.Info("sync", "serve_started", map[string]any{
		"peer_id": config.PeerID,
		"addr":    transport.LocalAddr(),
	})
	for {
		select {
		case <-ctx.Done():
			return nil
		case hostEvent := <-service.gossipDriver.Events():
			_, _ = service.handleGossipDriverEvent(ctx, hostEvent)
		}
	}
}

func syncOnce(peerID string) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	service, boltStore, err := openDaemon(rt, defaultDaemonInterval)
	if err != nil {
		return err
	}
	defer boltStore.Close()
	transport, err := service.openGossipTransport()
	if err != nil {
		return err
	}
	service.updateDiscoveredPeers()
	logger := service.Log
	ctx, cancel := context.WithTimeout(context.Background(), defaultSyncRoundTimeout)
	defer cancel()
	err = service.gossipDriver.StartGossipTransport(ctx, transport, func(err error) {
		logger.Warn("transport", "receive_failed", map[string]any{"error": err})
	})
	if err != nil {
		return err
	}
	defer service.gossipDriver.Stop()
	if err := startObjectPullServer(ctx, service); err != nil {
		return err
	}
	if err := service.gossipDriver.StartGossipObjectPullWorkers(ctx, service.objectPullExecutor, 0, 0); err != nil {
		return err
	}
	if err := service.gossipDriver.StartGossipSession(peerID, "sync_once"); err != nil {
		return err
	}
	var responderQuietUntil time.Time
	for {
		drained := false
		if service.gossipDriver.Gossip.Session(peerID) == nil && service.gossipDriver.PendingEventCount() == 0 && service.gossipDriver.PendingGossipObjectPullCount() == 0 {
			drained = true
			if responderQuietUntil.IsZero() {
				responderQuietUntil = time.Now().Add(syncOnceResponderQuiet)
			}
			if !time.Now().Before(responderQuietUntil) {
				return nil
			}
		} else {
			responderQuietUntil = time.Time{}
		}
		var quiet <-chan time.Time
		var quietTimer *time.Timer
		if drained && !responderQuietUntil.IsZero() {
			remaining := time.Until(responderQuietUntil)
			if remaining <= 0 {
				return nil
			}
			quietTimer = time.NewTimer(remaining)
			quiet = quietTimer.C
		}
		select {
		case <-ctx.Done():
			if quietTimer != nil {
				quietTimer.Stop()
			}
			if session := service.gossipDriver.Gossip.Session(peerID); session != nil && session.PendingCount() > 0 {
				pending := session.PendingZones()
				return &syncPendingZonesError{zones: pending}
			}
			return errors.New("sync receive timed out")
		case hostEvent := <-service.gossipDriver.Events():
			if quietTimer != nil {
				quietTimer.Stop()
			}
			responderQuietUntil = time.Time{}
			if _, err := service.handleGossipDriverEvent(ctx, hostEvent); err != nil {
				return err
			}
		case <-quiet:
			return nil
		}
	}
}

func zonePathStrings(paths []zone.ZonePath) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = append(out, path.String())
	}
	return out
}

type syncPendingZonesError struct {
	zones []zone.ZonePath
}

func (e *syncPendingZonesError) Error() string {
	if e == nil {
		return "sync once timed out with pending zones"
	}
	if len(e.zones) == 0 {
		return "sync once timed out with pending zones"
	}
	return "sync once timed out with pending zones: " + strings.Join(zonePathStrings(e.zones), ",")
}

func (e *syncPendingZonesError) PendingZones() []string {
	if e == nil {
		return nil
	}
	return zonePathStrings(e.zones)
}

func (d *Daemon) openGossipTransport() (*gossip.Transport, error) {
	config := d.currentGossipConfig()
	if config == nil {
		return nil, errors.New("gossip configuration is not initialized")
	}
	deps := defaultSyncTransportDeps(config, d.App.Config)
	listenAddr := config.ListenAddr
	if listenAddr == "" {
		listenAddr = fmt.Sprintf(":%d", gossip.DefaultPort)
	}
	datagram, err := photonlinux.ListenGossipDatagram(listenAddr)
	if err != nil {
		return nil, err
	}
	transport, err := gossip.NewTransport(gossipTransportConfig(config, deps, d.now), datagram)
	if err != nil {
		_ = datagram.Close()
		return nil, err
	}
	if err := d.gossipDriver.BindGossipTransport(transport); err != nil {
		_ = datagram.Close()
		return nil, err
	}
	return transport, nil
}

func gossipTransportConfig(config *gossipStartupConfig, deps *SyncTransportDeps, clock func() time.Time) gossip.Config {
	return gossip.Config{
		PeerID:          config.PeerID,
		KnownPeers:      deps.KnownPeers,
		MaxMessageBytes: config.MaxMessageBytes,
		Replay:          deps.Replay,
		Quotas:          deps.Quotas,
		Clock:           clock,
		Log:             deps.Log,
	}
}

func listenPortFromAddr(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return uint16(gossip.DefaultPort)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return uint16(gossip.DefaultPort)
	}
	return uint16(port)
}

func (d *Daemon) endpointProtocolIntent(verified *corestate.VerifiedState) (*corestate.PutProtocolRecordIntent, error) {
	var config *appConfig
	if d != nil && d.App != nil && d.App.Config != nil {
		config = d.App.Config
	}
	if verified == nil || verified.Network == nil || verified.ManagedZone == zone.RootZone || len(verified.IdentityPrivateKey) == 0 || autoJoinPendingVerified(verified) {
		return nil, nil
	}
	if config == nil {
		return nil, errors.New("gossip configuration is not initialized")
	}
	if !config.PublishEndpoints {
		return corehost.PlanGossipEndpointIntent(corehost.GossipEndpointIntentInput{
			Verified: verified, Disabled: true, Now: d.now(), TTL: config.EndpointTTL,
		})
	}
	port := listenPortFromAddr(config.ListenAddr)
	advertiseAddrs, reflectors := filterEndpointDiscoveryInputs(config, port)
	endpoints, reflectorErr := collectSyncLocalEndpoints(port, advertiseAddrs, reflectors, config.ReflectorTimeout, config.FilterPrivateIPv4)
	if reflectorErr != nil && len(gossip.ResolvePublicIPReflectors(reflectors)) > 0 {
		d.logWarn("endpoint", "reflector_failed", map[string]any{"error": reflectorErr})
	}
	return corehost.PlanGossipEndpointIntent(corehost.GossipEndpointIntentInput{
		Verified: verified, Endpoints: endpoints, Now: d.now(),
		TTL: config.EndpointTTL, Grace: config.EndpointGrace, Refresh: config.EndpointRefresh,
	})
}

// filterEndpointDiscoveryInputs returns the advertise addresses and reflectors
// to use when publishing local endpoints, respecting the endpoint_discovery
// configuration. loopback_only suppresses public IP reflectors and interface
// scans, keeping only loopback addresses and explicit loopback advertise_addrs.
// advertise_only uses only explicit advertise_addrs.
//
// When endpoint_discovery is unset, the daemon auto-detects loopback-only test
// deployments: if every configured bootstrap peer uses a loopback address, it
// behaves like loopback_only to avoid publishing unreachable public IPs that
// would starve loopback bootstrap paths.
func filterEndpointDiscoveryInputs(config *appConfig, port uint16) (advertiseAddrs, reflectors []string) {
	mode := strings.ToLower(strings.TrimSpace(config.EndpointDiscovery))
	if mode == "" && allBootstrapAddrsLoopback(config.Bootstrap) {
		mode = "loopback_only"
	}
	switch mode {
	case "advertise_only":
		return config.AdvertiseAddrs, nil
	case "loopback_only":
		for _, addr := range config.AdvertiseAddrs {
			if host, _, err := net.SplitHostPort(addr); err == nil && isLoopbackIP(host) {
				advertiseAddrs = append(advertiseAddrs, addr)
			}
		}
		// Derive loopback endpoints from listen_addr. If listen_addr is not a
		// specific loopback address, fall back to the well-known loopback IPs.
		if host, _, err := net.SplitHostPort(config.ListenAddr); err == nil && isLoopbackIP(host) {
			advertiseAddrs = append(advertiseAddrs, net.JoinHostPort(host, strconv.Itoa(int(port))))
		} else {
			advertiseAddrs = append(advertiseAddrs, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
			advertiseAddrs = append(advertiseAddrs, net.JoinHostPort("::1", strconv.Itoa(int(port))))
		}
		return advertiseAddrs, nil
	case "", "all":
		return config.AdvertiseAddrs, config.Reflectors
	default:
		return config.AdvertiseAddrs, config.Reflectors
	}
}

func allBootstrapAddrsLoopback(peers []syncConfigPeer) bool {
	if len(peers) == 0 {
		return false
	}
	for _, peer := range peers {
		if peer.Addr == "" {
			return false
		}
		host, _, err := net.SplitHostPort(peer.Addr)
		if err != nil {
			host = peer.Addr
		}
		if !isLoopbackIP(host) {
			return false
		}
	}
	return true
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func syncLimits(config *gossipStartupConfig) corestate.SyncLimits {
	limits := corestate.DefaultSyncLimits()
	if config == nil {
		return limits
	}
	if config.MaxSyncZones > 0 {
		limits.MaxZones = config.MaxSyncZones
	}
	if config.MaxSyncRecords > 0 {
		limits.MaxRecords = config.MaxSyncRecords
	}
	if config.MaxMessageBytes > 0 {
		limits.MaxBytes = config.MaxMessageBytes
	}
	return limits
}
