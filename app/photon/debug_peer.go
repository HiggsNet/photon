package main

import (
	"fmt"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func debugPeer(peerID string) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.PeerDebugView](rt, controlRequest{Method: "peer_debug", Zone: peerID}); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online peer_id=%s\n", view.PeerID)
		return inspecttext.WritePeerDebug(os.Stdout, view)
	}
	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		return err
	}
	if common.State == nil {
		return fmt.Errorf("common state is not initialized")
	}
	fmt.Fprintln(os.Stdout, "source: checkpoint (daemon offline; last-known gossip runtime)")
	config := gossipDriverConfig(rt.Config, common.State, nil)
	view, ok := inspect.BuildGossipPeerDebugView(common, gossipPeersOptions(config, nil, rt.Now()), peerID)
	if !ok {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, peerID)
	}
	return inspecttext.WritePeerDebug(os.Stdout, view)
}
