package main

import (
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	"github.com/HiggsNet/photon/pkg/core/observability"
)

// peerSnapshotView is shared by Observer HTTP and the local management
// transport so both expose the same detailed peer projection.
func (d *Daemon) peerSnapshotView() inspect.PeersView {
	if d == nil || d.State == nil {
		return inspect.PeersView{Peers: []inspect.PeerView{}}
	}
	view := d.State.Common.ReadView()
	if view.State == nil {
		return inspect.PeersView{Peers: []inspect.PeerView{}}
	}
	var config corehost.GossipDriverConfig
	if d.gossipDriver != nil {
		config = d.gossipDriver.GossipConfig()
	}
	return inspect.BuildGossipPeersView(view, gossipPeersOptions(config, d.peerObservabilitySnapshots(), d.now()))
}

func gossipPeersOptions(config corehost.GossipDriverConfig, diagnostics map[string]observability.PeerDiagnostics, now time.Time) inspect.GossipPeersOptions {
	options := inspect.GossipPeersOptions{LocalPeerID: config.PeerID, Diagnostics: diagnostics, Now: now}
	for _, peerID := range config.Discovery.BootstrapPeers {
		bootstrap := inspect.PeerBootstrap{PeerID: peerID}
		if addr := config.Discovery.Bootstrap[peerID]; addr != nil {
			bootstrap.Addr = addr.String()
			bootstrap.ResolvedAddr = addr.String()
		}
		options.Bootstrap = append(options.Bootstrap, bootstrap)
	}
	return options
}
