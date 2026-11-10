package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/gossipview"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
)

func syncStatus(verbose bool) error {
	cfg, err := loadAppConfig()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[gossipview.View](cfg, controlRequest{Method: "sync_view"}, false); err != nil {
		return err
	} else if ok {
		fmt.Fprintf(os.Stdout, "daemon: online peer_id=%s\n", view.PeerID)
		return inspecttext.WriteSyncStatus(os.Stdout, view, verbose)
	}
	common, _, err := loadOfflineOwnerViews(cfg)
	if err != nil {
		return err
	}
	if common.State == nil {
		return errors.New("common state is not initialized")
	}
	fmt.Fprintln(os.Stdout, "source: checkpoint (daemon offline; last-known gossip runtime)")
	config := gossipDriverConfig(cfg, common.State, nil)
	return inspecttext.WriteSyncStatus(os.Stdout, gossipview.Build(common, config, cfg.ListenAddr, time.Now()), verbose)
}
