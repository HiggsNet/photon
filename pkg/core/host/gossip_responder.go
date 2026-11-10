package host

import (
	"context"
	"crypto/rand"
	"fmt"
	"log/slog"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func (driver *GossipDriver) respondGossipFetchZone(ctx context.Context, peerID string, request *gossip.FetchZone, sender GossipSender, budget int) error {
	if request == nil || driver.gossipState == nil {
		return nil
	}
	now := driver.schedulerForRead().clock.Now()
	driver.observeReadOnlyResponder(peerID, "chunk_fallback", request.Zone, now)
	snapshot, revoked, err := driver.gossipState.ReadZoneSnapshot(request.Zone, now)
	if err != nil {
		driver.logGossip(slog.LevelDebug, "fetch_zone_snapshot_missing", peerID, "responder", err, map[string]any{"zone": request.Zone})
		return nil
	}
	if revoked || snapshot == nil {
		return nil
	}
	chunks, err := driver.buildGossipSnapshotChunks(peerID, snapshot, budget, now)
	if err != nil {
		return err
	}
	driver.mu.RLock()
	active := driver.gossipChunkSends[gossipChunkSendTimerID(peerID, chunks[0].TransferID)] != nil
	driver.mu.RUnlock()
	if active {
		return nil
	}
	driver.observeChunkFallback(peerID, len(chunks), now)
	return driver.queueGossipChunkSend(ctx, peerID, chunks, sender)
}

func (driver *GossipDriver) buildGossipSnapshotChunks(peerID string, snapshot *corestate.ZoneSnapshot, budget int, now time.Time) ([]*gossip.ObjectChunk, error) {
	transferID := make([]byte, 16)
	if _, err := rand.Read(transferID); err != nil {
		return nil, fmt.Errorf("create gossip chunk transfer id: %w", err)
	}
	chunks, err := gossip.BuildZoneSnapshotChunks(snapshot, budget, driver.GossipConfig().PeerID, transferID)
	if err != nil {
		return nil, err
	}
	return driver.gossipSentChunks.Put(peerID, transferID, chunks, now)
}

func (driver *GossipDriver) handleGossipObjectChunkNACK(ctx context.Context, message *gossip.Message, sender GossipSender) error {
	if message == nil || message.ObjectChunkNACK == nil {
		return nil
	}
	now := driver.schedulerForRead().clock.Now()
	chunks := driver.gossipSentChunks.Repair(message.PeerID, message.ObjectChunkNACK, now)
	driver.observeChunkRepair(message.PeerID, len(chunks) == 0, len(chunks), now)
	return driver.queueGossipChunkSend(ctx, message.PeerID, chunks, sender)
}

// GossipObjectPullResponse serves a read-only TCP object pull from the same
// committed Store owned by GossipDriver. A missing Store is treated like an empty
// source rather than allowing platform composition to read another state root.
func (driver *GossipDriver) GossipObjectPullResponse(request *gossip.ObjectPullRequest, now time.Time) *gossip.ObjectPullResponse {
	if driver == nil || driver.gossipState == nil {
		return &gossip.ObjectPullResponse{Error: "invalid request"}
	}
	response := gossip.BuildObjectPullResponse(driver.gossipState, request, now)
	if request != nil && response != nil && response.OK && response.Snapshot != nil {
		driver.logGossip(slog.LevelDebug, "lookup_snapshot", "", "object_pull", nil, map[string]any{"zone": request.Zone.String(), "records": len(response.Snapshot.Records)})
	}
	return response
}
