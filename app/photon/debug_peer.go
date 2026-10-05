package main

import (
	"fmt"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func debugPeer(peerID string) error {
	cfg, err := loadAppConfig()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.PeerDebugView](cfg, controlRequest{Method: "peer_debug", Zone: peerID}, false); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s\n", view.PeerID)
		return inspecttext.WritePeerDebug(os.Stdout, view)
	}
	common, _, err := loadOfflineOwnerViews(cfg)
	if err != nil {
		return err
	}
	if common.State == nil {
		return fmt.Errorf("common state is not initialized")
	}
	fmt.Fprintln(os.Stdout, "source: checkpoint (daemon offline; last-known gossip runtime)")
	config := gossipDriverConfig(cfg, common.State, nil)
	options := gossipPeersOptions(config, nil, time.Now())
	options.Lifecycle = cfg.PeerLifecycle
	view, ok := inspect.BuildGossipPeerDebugView(common, options, peerID)
	if !ok {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, peerID)
	}
	return inspecttext.WritePeerDebug(os.Stdout, view)
}
