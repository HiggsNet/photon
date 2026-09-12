package main

import (
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	"github.com/HiggsNet/photon/pkg/core/observability"
)

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
