package main

import (
	"context"
	"maps"

	"github.com/HiggsNet/photon/internal/inspect"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// refreshGossipDiscovery supplies detached owner data to GossipDriver. Peer
// selection, endpoint ordering, checkpoint patches and address-book updates
// are common runtime responsibilities.
func (d *Daemon) refreshGossipDiscovery() {
	if d == nil || d.State == nil || d.gossipDriver == nil || d.gossipDriver.Transport() == nil {
		return
	}
	if err := d.gossipDriver.RefreshGossipDiscovery(context.Background(), d.gossipSuppressions(), d.now(), d.gossipDriver.Transport()); err != nil {
		d.logWarn("endpoint", "discovered_peer_commit_failed", map[string]any{"error": err})
	}
}

func (d *Daemon) gossipSuppressions() map[string]bool {
	if d == nil || d.State == nil {
		return nil
	}
	view := d.State.Common.ReadView()
	if view.State == nil {
		return nil
	}
	cfg := inspect.PeerLifecycleConfig{}
	if d.App != nil && d.App.Config != nil {
		cfg = d.App.Config.PeerLifecycle
	}
	return peerLifecycleSuppressions(view.State.Network, view.Gossip, d.now(), cfg)
}

func gossipDriverConfig(app *appConfig, verified *corestate.VerifiedState, logger *appLogger) corehost.GossipDriverConfig {
	if app == nil {
		return corehost.GossipDriverConfig{}
	}
	bootstrapPeers := make([]string, 0, len(app.Bootstrap))
	for _, peer := range app.Bootstrap {
		bootstrapPeers = append(bootstrapPeers, peer.ID)
	}
	driverConfig := corehost.GossipDriverConfig{
		PeerID: configuredPeerID(app, verified),
		Limits: syncLimits(app),
		Log:    gossipDriverLogger(logger),
		Discovery: corehost.GossipDiscoveryConfig{
			Bootstrap:      configuredKnownPeers(app),
			BootstrapPeers: bootstrapPeers,
			EndpointGrace:  app.EndpointGrace,
			SourceOrder:    append([]string(nil), app.EndpointSourceOrder...),
		},
	}
	return driverConfig
}

func gossipDriverLogger(logger *appLogger) func(corehost.GossipDriverLog) {
	return func(event corehost.GossipDriverLog) {
		if logger == nil {
			return
		}
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
		case "warn":
			logger.Warn("sync", event.Event, fields)
		default:
			logger.Debug("sync", event.Event, fields)
		}
	}
}
