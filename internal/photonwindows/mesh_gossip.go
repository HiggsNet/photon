package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"reflect"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// runMeshGossip owns protocol dispatch and discovery after startup. The mesh
// consumes a notification of the latest committed revision and never waits
// for Gossip verification, persistence, or outbound synchronization.
func runMeshGossip(ctx context.Context, config *Config, state *State, driver *corehost.GossipDriver, transport *gossip.Transport, logger *slog.Logger, bootstrap map[string]*net.UDPAddr, refresh <-chan map[string]*net.UDPAddr, leafIntents <-chan struct{}, published chan<- struct{}) error {
	store := state.Store()
	syncPeers := func() {
		if _, err := driver.SyncGossipPeers(ctx, time.Now(), false); err != nil && ctx.Err() == nil {
			logger.Warn("gossip_sync_failed", "error", err)
		}
	}
	lastRevision := store.VerifiedRevision()
	syncPeers()
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for {
		var event corehost.Event
		refreshDue := false
		select {
		case <-ctx.Done():
			return nil
		case <-leafIntents:
			if err := state.EnsureLocalLeafRoutes(ctx, config, time.Now()); err != nil &&
				!errors.Is(err, corestate.ErrVerifiedRevisionStale) && ctx.Err() == nil {
				logger.Warn("leaf_route_publication_failed", "error", err)
			}
		case next := <-refresh:
			if !reflect.DeepEqual(bootstrap, next) {
				if err := driver.UpdateGossipBootstrap(next); err != nil {
					return err
				}
				bootstrap = next
			}
			refreshDue = true
		case <-ticker.C:
			refreshDue = true
		case event = <-driver.Events():
		case event = <-driver.Completions():
		case event = <-driver.Continuations():
		}
		if refreshDue {
			if err := driver.RefreshGossipDiscovery(ctx, time.Now(), transport); err != nil && ctx.Err() == nil {
				return fmt.Errorf("refresh gossip discovery: %w", err)
			}
			syncPeers()
		}
		if event != nil {
			if _, err := driver.HandleGossipHostEvent(ctx, event, time.Now()); err != nil && !errors.Is(err, corehost.ErrGossipSessionNotFound) && ctx.Err() == nil {
				logger.Warn("gossip_event_failed", "error", err)
			}
		}
		if revision := store.VerifiedRevision(); revision != lastRevision {
			lastRevision = revision
			if err := driver.RefreshGossipDiscovery(ctx, time.Now(), transport); err != nil && ctx.Err() == nil {
				logger.Warn("gossip_discovery_refresh_failed", "error", err)
			}
			select {
			case published <- struct{}{}:
			default:
			}
		}
	}
}
