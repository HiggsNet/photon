package main

import (
	"context"

	"github.com/HiggsNet/photon/internal/inspect"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
)

// updateDiscoveredPeers supplies detached owner data to GossipDriver. Peer
// selection, endpoint ordering, checkpoint patches and address-book updates
// are common runtime responsibilities.
func (d *Daemon) updateDiscoveredPeers() {
	if d == nil || d.StateStore == nil || d.gossipDriver == nil || d.gossipDriver.Transport() == nil {
		return
	}
	if err := d.gossipDriver.RefreshGossipDiscovery(context.Background(), d.currentGossipSuppressions(), d.now(), d.gossipDriver.Transport()); err != nil {
		d.logWarn("endpoint", "discovered_peer_commit_failed", map[string]any{"error": err})
	}
}

// currentGossipConfig derives app/platform gossip settings from the current
// app config and verified identity. Protocol execution keeps its own detached
// configuration inside host.GossipDriver.
func (d *Daemon) currentGossipConfig() *gossipStartupConfig {
	if d == nil || d.App == nil || d.App.Config == nil {
		return nil
	}
	config := gossipStartupConfigFromAppConfig(d.App.Config, nil)
	if d.gossipDriver != nil {
		driverConfig := d.gossipDriver.GossipConfig()
		if driverConfig.PeerID != "" {
			config.PeerID = driverConfig.PeerID
		}
		if driverConfig.Limits.MaxZones > 0 {
			config.MaxSyncZones = driverConfig.Limits.MaxZones
		}
		if driverConfig.Limits.MaxRecords > 0 {
			config.MaxSyncRecords = driverConfig.Limits.MaxRecords
		}
		if len(driverConfig.Discovery.BootstrapPeers) > 0 {
			config.Bootstrap = make([]syncConfigPeer, 0, len(driverConfig.Discovery.BootstrapPeers))
			for _, peerID := range driverConfig.Discovery.BootstrapPeers {
				peer := syncConfigPeer{ID: peerID}
				if addr := driverConfig.Discovery.Bootstrap[peerID]; addr != nil {
					peer.Addr = addr.String()
				}
				config.Bootstrap = append(config.Bootstrap, peer)
			}
		}
	}
	return config
}

func (d *Daemon) currentGossipSuppressions() map[string]bool {
	if d == nil || d.StateStore == nil {
		return nil
	}
	view := d.StateStore.common.ReadView()
	if view.State == nil {
		return nil
	}
	cfg := inspect.PeerLifecycleConfig{}
	if d.App != nil && d.App.Config != nil {
		cfg = d.App.Config.PeerLifecycle
	}
	return peerLifecycleSuppressions(view.State.Network, view.Gossip, d.now(), cfg)
}

func gossipDriverConfig(config *gossipStartupConfig, app *appConfig, logger *appLogger) corehost.GossipDriverConfig {
	if config == nil {
		return corehost.GossipDriverConfig{}
	}
	bootstrapPeers := make([]string, 0, len(config.Bootstrap))
	for _, peer := range config.Bootstrap {
		bootstrapPeers = append(bootstrapPeers, peer.ID)
	}
	driverConfig := corehost.GossipDriverConfig{
		PeerID: config.PeerID,
		Limits: syncLimits(config),
		Log:    gossipDriverLogger(logger),
		Discovery: corehost.GossipDiscoveryConfig{
			Bootstrap:      configuredKnownPeers(config),
			BootstrapPeers: bootstrapPeers,
		},
	}
	if app != nil {
		driverConfig.Discovery.EndpointGrace = app.EndpointGrace
		driverConfig.Discovery.SourceOrder = append([]string(nil), app.EndpointSourceOrder...)
	}
	return driverConfig
}

func gossipDriverLogger(logger *appLogger) func(corehost.GossipDriverLog) {
	return func(event corehost.GossipDriverLog) {
		if logger == nil {
			return
		}
		fields := make(map[string]any, len(event.Fields)+3)
		for key, value := range event.Fields {
			fields[key] = value
		}
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
		case "warn":
			logger.Warn("sync", event.Event, fields)
		default:
			logger.Debug("sync", event.Event, fields)
		}
	}
}
