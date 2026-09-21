package main

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const defaultSyncRoundTimeout = 5 * time.Second
const syncOnceResponderQuiet = 500 * time.Millisecond

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

func syncServe(ctx context.Context) error {
	cfg, err := loadAppConfig()
	if err != nil {
		return err
	}
	service, err := openDaemon(cfg, defaultDaemonInterval)
	if err != nil {
		return err
	}
	defer service.Close()
	config := service.gossipDriver.GossipConfig()
	logger := newAppLogger(cfg)
	transport, err := service.openGossipTransport()
	if err != nil {
		return err
	}
	service.refreshGossipDiscovery()
	err = service.gossipDriver.StartGossipTransport(ctx, transport, func(err error) {
		logger.Warn("transport", "receive_failed", map[string]any{"error": err})
	})
	if err != nil {
		return err
	}
	defer service.gossipDriver.Stop()
	if err := startObjectPullServer(ctx, service); err != nil {
		return err
	}
	if err := service.gossipDriver.StartGossipObjectPullWorkers(ctx, service.objectPullExecutor, 0, 0); err != nil {
		return err
	}
	stopControl, err := service.startControlServer(ctx)
	if err != nil {
		return err
	}
	defer stopControl()
	logger.Info("sync", "serve_started", map[string]any{
		"peer_id": config.PeerID,
		"addr":    transport.LocalAddr(),
	})
	for {
		select {
		case <-ctx.Done():
			return nil
		case hostEvent := <-service.gossipDriver.Events():
			_, _ = service.handleGossipDriverEvent(ctx, hostEvent)
			service.flushRevocationCleanup()
		}
	}
}

func syncOnce(peerID string) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	service, err := openDaemon(config, defaultDaemonInterval)
	if err != nil {
		return err
	}
	defer service.Close()
	transport, err := service.openGossipTransport()
	if err != nil {
		return err
	}
	service.refreshGossipDiscovery()
	logger := service.Log
	ctx, cancel := context.WithTimeout(context.Background(), defaultSyncRoundTimeout)
	defer cancel()
	err = service.gossipDriver.StartGossipTransport(ctx, transport, func(err error) {
		logger.Warn("transport", "receive_failed", map[string]any{"error": err})
	})
	if err != nil {
		return err
	}
	defer service.gossipDriver.Stop()
	if err := startObjectPullServer(ctx, service); err != nil {
		return err
	}
	if err := service.gossipDriver.StartGossipObjectPullWorkers(ctx, service.objectPullExecutor, 0, 0); err != nil {
		return err
	}
	if err := service.gossipDriver.StartGossipSession(peerID, "sync_once"); err != nil {
		return err
	}
	var responderQuietUntil time.Time
	for {
		drained := false
		if service.gossipDriver.Gossip.Session(peerID) == nil && service.gossipDriver.PendingEventCount() == 0 && service.gossipDriver.PendingGossipObjectPullCount() == 0 {
			drained = true
			if responderQuietUntil.IsZero() {
				responderQuietUntil = time.Now().Add(syncOnceResponderQuiet)
			}
			if !time.Now().Before(responderQuietUntil) {
				return nil
			}
		} else {
			responderQuietUntil = time.Time{}
		}
		var quiet <-chan time.Time
		var quietTimer *time.Timer
		if drained && !responderQuietUntil.IsZero() {
			remaining := time.Until(responderQuietUntil)
			if remaining <= 0 {
				return nil
			}
			quietTimer = time.NewTimer(remaining)
			quiet = quietTimer.C
		}
		select {
		case <-ctx.Done():
			if quietTimer != nil {
				quietTimer.Stop()
			}
			if session := service.gossipDriver.Gossip.Session(peerID); session != nil && session.PendingCount() > 0 {
				pending := session.PendingZones()
				return &syncPendingZonesError{zones: pending}
			}
			return errors.New("sync receive timed out")
		case hostEvent := <-service.gossipDriver.Events():
			if quietTimer != nil {
				quietTimer.Stop()
			}
			responderQuietUntil = time.Time{}
			if _, err := service.handleGossipDriverEvent(ctx, hostEvent); err != nil {
				return err
			}
			service.flushRevocationCleanup()
		case <-quiet:
			return nil
		}
	}
}

func zonePathStrings(paths []zone.ZonePath) []string {
	out := make([]string, 0, len(paths))
	for _, path := range paths {
		out = append(out, path.String())
	}
	return out
}

type syncPendingZonesError struct {
	zones []zone.ZonePath
}

func (e *syncPendingZonesError) Error() string {
	if e == nil {
		return "sync once timed out with pending zones"
	}
	if len(e.zones) == 0 {
		return "sync once timed out with pending zones"
	}
	return "sync once timed out with pending zones: " + strings.Join(zonePathStrings(e.zones), ",")
}

func (e *syncPendingZonesError) PendingZones() []string {
	if e == nil {
		return nil
	}
	return zonePathStrings(e.zones)
}
