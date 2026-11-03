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
func runMeshGossip(ctx context.Context, config *Config, store *corestate.Store, driver *corehost.GossipDriver, transport *gossip.Transport, logger *slog.Logger, bootstrap map[string]*net.UDPAddr, refresh <-chan map[string]*net.UDPAddr, published chan<- struct{}) error {
	var lastCandidates []GatewayCandidate
	observeGateways := func() {
		view, now := store.ReadView(), time.Now()
		candidates := GatewayCandidates(config, view, now)
		if !reflect.DeepEqual(lastCandidates, candidates) {
			logger.Info("gateway_candidates_changed", "revision", view.Revision, "evaluated_at", now,
				"candidates", candidates, "tunnel_ready", false, "route_authorized", false)
			lastCandidates = candidates
		}
	}
	syncPeers := func() {
		if _, err := driver.SyncGossipPeers(ctx, time.Now(), nil, false); err != nil && ctx.Err() == nil {
			logger.Warn("gossip_sync_failed", "error", err)
		}
	}
	lastRevision := store.VerifiedRevision()
	observeGateways()
	syncPeers()
	for {
		var event corehost.Event
		select {
		case <-ctx.Done():
			return nil
		case next := <-refresh:
			if !reflect.DeepEqual(bootstrap, next) {
				if err := driver.UpdateGossipBootstrap(next); err != nil {
					return err
				}
				bootstrap = next
			}
			if err := driver.RefreshGossipDiscovery(ctx, nil, time.Now(), transport); err != nil && ctx.Err() == nil {
				return fmt.Errorf("refresh gossip discovery: %w", err)
			}
			observeGateways()
			syncPeers()
		case event = <-driver.Events():
		case event = <-driver.Completions():
		case event = <-driver.Continuations():
		}
		if event != nil {
			if _, err := driver.HandleGossipHostEvent(ctx, event, time.Now(), nil); err != nil && !errors.Is(err, corehost.ErrGossipSessionNotFound) && ctx.Err() == nil {
				logger.Warn("gossip_event_failed", "error", err)
			}
		}
		if revision := store.VerifiedRevision(); revision != lastRevision {
			lastRevision = revision
			select {
			case published <- struct{}{}:
			default:
			}
			observeGateways()
		}
	}
}
