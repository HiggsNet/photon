package main

import (
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
)

func syncStatus(verbose bool) error {
	cfg, err := loadAppConfig()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.SyncStatusView](cfg, controlRequest{Method: "sync_view", Verbose: verbose}, false); err != nil {
		return err
	} else if ok {
		fmt.Fprintf(os.Stdout, "daemon: online peer_id=%s\n", view.PeerID)
		return inspecttext.WriteSyncStatus(os.Stdout, view)
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
	return inspecttext.WriteSyncStatus(os.Stdout, inspect.BuildSyncStatus(common, syncStatusOptions(cfg.ListenAddr, config, time.Now(), verbose)))
}
