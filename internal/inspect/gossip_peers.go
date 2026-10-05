package inspect

import (
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

type PeerBootstrap struct {
	PeerID       string
	Addr         string
	ResolvedAddr string
}

// GossipPeersOptions contains local query configuration and optional live
// diagnostics. Verified records and restartable peer state come directly from
// the common owner view passed to the builder.
type GossipPeersOptions struct {
	LocalPeerID string
	Bootstrap   []PeerBootstrap
	Diagnostics map[string]observability.PeerDiagnostics
	Now         time.Time
	Lifecycle   PeerLifecycleConfig
}

func BuildGossipPeerDebugViews(common corestate.View, options GossipPeersOptions) []PeerDebugView {
	if common.State == nil || common.State.Network == nil {
		return nil
	}
	ids := gossipPeerIDs(common, options)
	views := make([]PeerDebugView, 0, len(ids))
	for _, peerID := range ids {
		view, _ := BuildGossipPeerDebugView(common, options, peerID)
		views = append(views, view)
	}
	return views
}

func BuildGossipPeerDebugView(common corestate.View, options GossipPeersOptions, peerID string) (PeerDebugView, bool) {
	if common.State == nil || common.State.Network == nil || !PeerKnown(gossipPeerSetInput(common, options), peerID) {
		return PeerDebugView{}, false
	}
	facts := gossipPeerProjection(common, options, peerID)
	view := buildPeerDebugFromCheckpoint(
		peerID, facts.source, facts.configuredAddr, facts.resolvedAddr,
		facts.checkpoint, facts.diagnostics, options.Now,
	)
	view.Historical = gossipPeerHistorical(common, options, peerID, facts.checkpoint)
	if view.Historical {
		view.Status = "offline"
	}
	return view, true
}

// Keep the checkpoint for lifecycle suppression and explicit diagnostics;
// historical peers are omitted only by the default CLI list renderer.
func gossipPeerHistorical(common corestate.View, options GossipPeersOptions, peerID string, peer corestate.PeerCheckpoint) bool {
	if _, configured := gossipPeerBootstrap(options.Bootstrap, peerID); configured {
		return false
	}
	lastActive := max(peer.LastSyncUnix, peer.ObservedLastSeenUnix)
	if lastActive == 0 || options.Now.Before(time.Unix(lastActive, 0).Add(NormalizePeerLifecycleConfig(options.Lifecycle).CleanupAfter)) {
		return false
	}
	if peer.ObservedEndpoint != "" && options.Now.Before(time.Unix(peer.ObservedUntilUnix, 0)) {
		return false
	}
	for _, endpoint := range peer.ObservedGraceEndpoints {
		if endpoint.Endpoint != "" && options.Now.Before(time.Unix(endpoint.UntilUnix, 0)) {
			return false
		}
	}
	return len(gossip.ExtractPeerEndpointsAt(common.State.Network, options.Now)[peerID]) == 0
}

func BuildGossipPeersView(common corestate.View, options GossipPeersOptions) PeersView {
	if common.State == nil || common.State.Network == nil {
		return PeersView{Peers: []PeerView{}}
	}
	ids := gossipPeerIDs(common, options)
	view := PeersView{Peers: make([]PeerView, 0, len(ids))}
	for _, peerID := range ids {
		facts := gossipPeerProjection(common, options, peerID)
		view.Peers = append(view.Peers, BuildPeerViewFromCheckpoint(
			peerID, facts.configuredAddr, facts.endpoints, facts.checkpoint, facts.diagnostics,
		))
	}
	return view
}

type gossipPeerProjectionFacts struct {
	checkpoint     corestate.PeerCheckpoint
	diagnostics    observability.PeerDiagnostics
	source         string
	configuredAddr string
	resolvedAddr   string
	endpoints      []PeerEndpointView
}

func gossipPeerProjection(common corestate.View, options GossipPeersOptions, peerID string) gossipPeerProjectionFacts {
	checkpoint := syncPeerCheckpoint(common.Gossip, peerID)
	diagnostics := options.Diagnostics[peerID]
	bootstrap, configured := gossipPeerBootstrap(options.Bootstrap, peerID)
	endpointInput := PeerEndpointInput{
		BootstrapAddr: bootstrap.Addr, SelectedAddr: checkpoint.DiscoveredEndpoint,
		ObservedAddr: checkpoint.ObservedEndpoint, ObservedSource: diagnostics.ObservedSource,
	}
	if common.State != nil {
		for _, endpoint := range gossip.ExtractPeerEndpointsAt(common.State.Network, options.Now)[peerID] {
			endpointInput.Signed = append(endpointInput.Signed, PeerSignedEndpoint{
				Address: endpoint.Address, Port: endpoint.Port, Protocol: endpoint.Protocol,
				Scope: endpoint.Scope, Source: endpoint.Source, Priority: endpoint.Priority,
				LastObserved: endpoint.LastObserved,
			})
		}
	}
	for _, grace := range checkpoint.ObservedGraceEndpoints {
		endpointInput.Grace = append(endpointInput.Grace, PeerGraceEndpoint{Addr: grace.Endpoint})
	}
	endpoints := BuildPeerEndpoints(endpointInput)
	resolved := bootstrap.ResolvedAddr
	if resolved == "" {
		resolved = "-"
	}
	if selected := selectedPeerEndpoint(endpoints); selected != "" {
		resolved = selected
	}
	source := "discovered"
	configuredAddr := ""
	if configured {
		source = "bootstrap"
		configuredAddr = bootstrap.Addr
	} else if checkpoint.ObservedEndpoint != "" {
		source = "observed"
	}
	return gossipPeerProjectionFacts{
		checkpoint: checkpoint, diagnostics: diagnostics, source: source,
		configuredAddr: configuredAddr, resolvedAddr: resolved, endpoints: endpoints,
	}
}

func gossipPeerIDs(common corestate.View, options GossipPeersOptions) []string {
	return BuildPeerIDs(gossipPeerSetInput(common, options))
}

func gossipPeerSetInput(common corestate.View, options GossipPeersOptions) PeerSetInput {
	input := PeerSetInput{LocalIDs: []string{options.LocalPeerID}}
	if common.State != nil {
		input.LocalIDs = append(input.LocalIDs, string(common.State.ManagedZone))
		for peerID := range gossip.ExtractPeerEndpointsAt(common.State.Network, options.Now) {
			input.SignedIDs = append(input.SignedIDs, peerID)
		}
	}
	if common.Gossip != nil {
		for peerID := range common.Gossip.Peers {
			input.RuntimeIDs = append(input.RuntimeIDs, peerID)
		}
	}
	for _, peer := range options.Bootstrap {
		input.BootstrapIDs = append(input.BootstrapIDs, peer.PeerID)
	}
	for peerID := range options.Diagnostics {
		input.RuntimeIDs = append(input.RuntimeIDs, peerID)
	}
	return input
}

func gossipPeerBootstrap(peers []PeerBootstrap, peerID string) (PeerBootstrap, bool) {
	for _, peer := range peers {
		if peer.PeerID == peerID {
			return peer, true
		}
	}
	return PeerBootstrap{}, false
}

func selectedPeerEndpoint(endpoints []PeerEndpointView) string {
	for _, endpoint := range endpoints {
		if endpoint.Selected && endpoint.Addr != "" {
			return endpoint.Addr
		}
	}
	for _, endpoint := range endpoints {
		if endpoint.Addr != "" {
			return endpoint.Addr
		}
	}
	return ""
}
