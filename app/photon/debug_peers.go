package main

import (
	"context"
	"fmt"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// debugPeers implements `photon debug peers`: it prints the derived lifecycle
// status of every known peer, including state, reason, last sync, link counts
// and cleanup timers. It prioritizes daemon committed state when available.
func debugPeers(_ context.Context) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if status, ok, err := daemonStatusViaControl(rt); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s link_instances=%d desired_links=%d\n",
			status.PeerID,
			status.LinkInstances,
			status.DesiredLinks,
		)
		view, peersOnline, err := readCanonicalViewViaControl[inspect.PeerLifecycleDebugView](rt, controlRequest{Method: "peer_lifecycle_view"})
		if err != nil {
			return err
		}
		if peersOnline {
			return inspecttext.WritePeerLifecycleDebug(os.Stdout, view)
		}
	}
	return fmt.Errorf("daemon control socket unavailable; peer lifecycle runtime state requires a running daemon")
}

func showPeers(filter string, verbose bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if peers, ok, err := readCanonicalViewViaControl[[]inspect.PeerDebugView](rt, controlRequest{Method: "gossip_peers_view"}); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteGossipPeers(os.Stdout, peers, filter, verbose)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil {
		return nil
	}
	fmt.Fprintln(os.Stdout, "source: checkpoint (daemon offline; last-known gossip runtime)")
	config := gossipDriverConfig(rt.Config, common.State, nil)
	return inspecttext.WriteGossipPeers(os.Stdout, inspect.BuildGossipPeerDebugViews(common, gossipPeersOptions(config, nil, rt.Now())), filter, verbose)
}

func buildPeerLifecycleDebugView(rt *AppContext, common corestate.View, links map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary) inspect.PeerLifecycleDebugView {
	if common.State == nil || common.State.Network == nil {
		return inspect.PeerLifecycleDebugView{}
	}
	now := rt.Now()
	cfg := inspect.PeerLifecycleConfig{}
	if rt != nil && rt.Config != nil {
		cfg = rt.Config.PeerLifecycle
	}
	hasOverlay := rt != nil && rt.Config != nil && len(rt.Config.IPsec.LinkGroups) > 0

	statuses := derivePeerStatuses(common.State.ManagedZone, common.State.Network, common.Gossip, links, reconcile, now, cfg, hasOverlay)
	return inspect.BuildPeerLifecycleDebug(cfg, statuses)
}

func (d *Daemon) gossipPeerSnapshotForControl() []inspect.PeerDebugView {
	if d == nil || d.State == nil {
		return nil
	}
	view := d.State.Common.ReadView()
	if view.State == nil {
		return nil
	}
	return inspect.BuildGossipPeerDebugViews(view, gossipPeersOptions(d.gossipDriver.GossipConfig(), d.peerObservabilitySnapshots(), d.now()))
}
