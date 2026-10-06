package main

import (
	"context"
	"errors"
	"fmt"
	"maps"
	"net"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	photonlinux "github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// refreshGossipDiscovery supplies detached owner data to GossipDriver. Peer
// selection, endpoint ordering, checkpoint patches and address-book updates
// are common runtime responsibilities.
func (d *Daemon) refreshGossipDiscovery() {
	if d.State == nil || d.gossipDriver == nil || d.gossipDriver.Transport() == nil {
		return
	}
	if err := d.gossipDriver.RefreshGossipDiscovery(context.Background(), d.gossipSuppressions(), d.now(), d.gossipDriver.Transport()); err != nil {
		d.logWarn("endpoint", "discovered_peer_commit_failed", map[string]any{"error": err})
	}
}

func (d *Daemon) gossipSuppressions() map[string]bool {
	if d.State == nil {
		return nil
	}
	cfg := inspect.PeerLifecycleConfig{}
	if d.Config != nil {
		cfg = d.Config.PeerLifecycle
	}
	now := d.now()
	return peerLifecycleSuppressions(d.State.Common.ReadPeerActivity(now), now, cfg)
}

func gossipDriverConfig(app *appConfig, verified *corestate.VerifiedState, logger *appLogger) corehost.GossipDriverConfig {
	if app == nil {
		return corehost.GossipDriverConfig{}
	}
	return corehost.GossipDriverConfig{
		PeerID: configuredPeerID(app, verified),
		Limits: syncLimits(app),
		Log:    gossipDriverLogger(logger),
		Discovery: corehost.GossipDiscoveryConfig{
			Bootstrap:      configuredKnownPeers(app),
			BootstrapPeers: bootstrapPeerIDs(app.Bootstrap),
			EndpointGrace:  app.EndpointGrace,
			SourceOrder:    append([]string(nil), app.EndpointSourceOrder...),
		},
	}
}

func gossipDriverLogger(logger *appLogger) func(corehost.GossipDriverLog) {
	if logger == nil {
		return nil
	}
	return func(event corehost.GossipDriverLog) {
		fields := make(map[string]any, len(event.Fields)+3)
		maps.Copy(fields, event.Fields)
		if event.PeerID != "" {
			fields["peer_id"] = event.PeerID
		}
		if event.Phase != "" {
			fields["phase"] = event.Phase
		}
		if event.Err != nil {
			fields["error"] = event.Err
		}
		switch event.Level {
		case "error":
			logger.Error("sync", event.Event, fields)
		case "warn":
			logger.Warn("sync", event.Event, fields)
		case "info":
			logger.Info("sync", event.Event, fields)
		default:
			logger.Debug("sync", event.Event, fields)
		}
	}
}

// startObjectPullServer binds the platform listener and gives its lifecycle to
// GossipDriver.
func startObjectPullServer(ctx context.Context, d *Daemon) error {
	if d == nil || d.gossipDriver == nil || d.gossipDriver.Transport() == nil {
		return errors.New("object-pull server runtime is not configured")
	}
	udp := d.gossipDriver.Transport().LocalAddr()
	if udp == nil {
		return errors.New("object-pull local address is not configured")
	}
	// TCP object pull shares the gossip UDP address and numeric port.
	addr := (&net.TCPAddr{IP: udp.IP, Port: udp.Port, Zone: udp.Zone}).String()
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if err := d.gossipDriver.StartGossipObjectPullServer(ctx, listener, 0, 0); err != nil {
		_ = listener.Close()
		return err
	}
	d.logInfo("object_pull", "serve_started", map[string]any{"addr": listener.Addr()})
	return nil
}

func (d *Daemon) handleSyncTimerEvent(ctx context.Context, force bool) error {
	changed, err := d.gossipDriver.SyncGossipPeers(ctx, d.now(), d.gossipSuppressions(), force)
	if changed {
		d.refreshGossipDiscovery()
		d.notifyStateChanged()
	}
	return err
}

func (d *Daemon) handleGossipDriverEvent(ctx context.Context, hostEvent corehost.Event) (corehost.GossipHostEventResult, error) {
	now := d.now()
	result, err := d.gossipDriver.HandleGossipHostEvent(ctx, hostEvent, now, d.gossipSuppressions())
	if err == nil && result.Session.Done && result.Session.NetworkChanged {
		d.refreshGossipDiscovery()
		d.notifyStateChanged()
	}
	return result, err
}

func (d *Daemon) openGossipTransport() (*gossip.Transport, error) {
	if d.Config == nil || d.gossipDriver == nil {
		return nil, errors.New("gossip configuration is not initialized")
	}
	config := d.gossipDriver.GossipConfig()
	listenAddr := d.Config.ListenAddr
	if listenAddr == "" {
		listenAddr = fmt.Sprintf(":%d", gossip.DefaultPort)
	}
	datagram, err := photonlinux.ListenGossipDatagram(listenAddr)
	if err != nil {
		return nil, err
	}
	transport, err := gossip.NewTransport(gossipTransportConfig(config, d.Config, d.now), datagram)
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

func gossipTransportConfig(config corehost.GossipDriverConfig, loggerConfig *appConfig, clock func() time.Time) gossip.Config {
	return gossip.Config{
		PeerID:          config.PeerID,
		KnownPeers:      config.Discovery.Bootstrap,
		MaxMessageBytes: config.Limits.MaxBytes,
		Replay:          gossip.NewReplayWindow(0),
		Quotas:          gossip.NewPeerQuotas(gossip.QuotaConfig{}),
		Clock:           clock,
		Log:             syncDebugLogger(loggerConfig),
	}
}

func syncLimits(config *appConfig) corestate.SyncLimits {
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
