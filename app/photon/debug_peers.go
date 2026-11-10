package main

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/gossipview"
	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// debugPeers implements `photon debug peers`: it prints the derived lifecycle
// status of every known peer, including state, reason, last sync, link counts
// and cleanup timers. It prioritizes daemon committed state when available.
func debugPeers(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, controlRequestDeadline)
	defer cancel()
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	view, online, err := readCanonicalViewViaControlContext[inspect.PeerLifecycleDebugView](ctx, config, controlRequest{Method: "peer_lifecycle_view"}, false)
	if err != nil {
		return err
	}
	if online {
		return inspecttext.WritePeerLifecycleDebug(os.Stdout, view)
	}
	return fmt.Errorf("daemon control socket unavailable; peer lifecycle runtime state requires a running daemon")
}

func showPeers(filter string, verbose bool) error {
	cfg, err := loadAppConfig()
	if err != nil {
		return err
	}
	if peers, ok, err := readCanonicalViewViaControl[gossipview.View](cfg, controlRequest{Method: "sync_view"}, false); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteGossipPeers(os.Stdout, peers.Peers, filter, verbose)
	}
	common, _, err := loadOfflineOwnerViews(cfg)
	if err != nil {
		return err
	}
	if common.State == nil {
		return nil
	}
	fmt.Fprintln(os.Stdout, "source: checkpoint (daemon offline; last-known gossip runtime)")
	config := gossipDriverConfig(cfg, common.State, nil)
	return inspecttext.WriteGossipPeers(os.Stdout, gossipview.Build(common, config, cfg.ListenAddr, time.Now()).Peers, filter, verbose)
}

func buildPeerLifecycleDebugView(config *appConfig, common corestate.View, suspended map[zone.ZonePath]bool, links map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, now time.Time) inspect.PeerLifecycleDebugView {
	if common.State == nil || common.State.Network == nil {
		return inspect.PeerLifecycleDebugView{}
	}

	cfg := inspect.PeerLifecycleConfig{}
	if config != nil {
		cfg = config.PeerLifecycle
	}
	hasOverlay := config != nil && len(config.IPsec.LinkGroups) > 0

	statuses := derivePeerStatuses(common.State.ManagedZone, common.State.Network, common.Gossip, suspended, links, reconcile, now, cfg, hasOverlay)
	return inspect.BuildPeerLifecycleDebug(cfg, statuses)
}
