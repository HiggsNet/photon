package host

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

var ErrGossipChunkSendCacheFull = errors.New("gossip chunk send cache limits exceeded")

// gossipFetchZoneResponse is detached responder input derived from one
// committed Store read and consumed inside GossipDriver.
type gossipFetchZoneResponse struct {
	Found    bool
	Plan     gossip.DatagramPlan
	Snapshot *corestate.ZoneSnapshot
}

func (driver *GossipDriver) gossipFetchZoneResponse(path zone.ZonePath, budget int, now time.Time) gossipFetchZoneResponse {
	if driver == nil || driver.gossipState == nil {
		return gossipFetchZoneResponse{}
	}
	view := driver.gossipState.ReadView()
	if view.State == nil || view.State.Network == nil || view.State.Network.Zones[path] == nil {
		return gossipFetchZoneResponse{}
	}
	network := view.State.Network
	response := gossipFetchZoneResponse{Found: true, Plan: gossip.PlanSnapshotDatagrams(network, []zone.ZonePath{path}, budget, now)}
	if network.IsZoneRevoked(path, now) {
		return response
	}
	response.Snapshot, _ = corestate.Snapshot(network, path)
	return response
}

func (driver *GossipDriver) respondGossipFetchZone(ctx context.Context, peerID string, request *gossip.FetchZone, sender GossipSender, budget int) error {
	if request == nil {
		return nil
	}
	now := driver.schedulerForRead().clock.Now()
	response := driver.gossipFetchZoneResponse(request.Zone, budget, now)
	kind := "fetch_zone"
	if request.ChunkFallback {
		kind = "chunk_fallback"
	}
	driver.observeReadOnlyResponder(peerID, kind, request.Zone, now)
	if !response.Found {
		driver.logGossip("debug", "fetch_zone_snapshot_missing", peerID, "responder", zone.ErrZoneNotFound, map[string]any{"zone": request.Zone})
		return nil
	}
	for _, oversized := range response.Plan.Oversized {
		driver.observeDatagramTooLarge(peerID, oversized.Object, oversized.Zone, oversized.Key, oversized.Size, budget, now)
		driver.logGossip("debug", "datagram_too_large", peerID, "responder", nil, map[string]any{
			"object": oversized.Object, "zone": oversized.Zone, "key": oversized.Key,
			"bytes": oversized.Size, "limit": budget,
		})
	}
	for _, announce := range response.Plan.Announces {
		if announce == nil {
			continue
		}
		if err := sender.SendGossip(ctx, gossip.OutboundMessage{PeerID: peerID, Message: &gossip.Message{Type: gossip.MessageAnnounce, Announce: announce}}); err != nil {
			return err
		}
		driver.logGossip("info", "sending_announce", peerID, "responder", nil, map[string]any{"digests": len(announce.Zones)})
	}
	if !request.ChunkFallback || response.Snapshot == nil {
		return nil
	}
	chunks, err := driver.buildGossipSnapshotChunks(peerID, response.Snapshot, budget, now)
	if err != nil {
		return err
	}
	for _, chunk := range chunks {
		if err := sender.SendGossip(ctx, gossip.OutboundMessage{PeerID: peerID, Message: &gossip.Message{Type: gossip.MessageObjectChunk, ObjectChunk: chunk}}); err != nil {
			return err
		}
	}
	driver.observeChunkFallback(peerID, len(chunks), now)
	return nil
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
	if !driver.gossipSentChunks.Put(peerID, transferID, chunks, now) {
		return nil, ErrGossipChunkSendCacheFull
	}
	return chunks, nil
}

func (driver *GossipDriver) handleGossipObjectChunkNACK(ctx context.Context, message *gossip.Message, sender GossipSender) error {
	if message == nil || message.ObjectChunkNACK == nil {
		return nil
	}
	now := driver.schedulerForRead().clock.Now()
	chunks := driver.gossipSentChunks.Repair(message.PeerID, message.ObjectChunkNACK, now)
	driver.observeChunkRepair(message.PeerID, len(chunks) == 0, len(chunks), now)
	for _, chunk := range chunks {
		if err := sender.SendGossip(ctx, gossip.OutboundMessage{PeerID: message.PeerID, Message: &gossip.Message{Type: gossip.MessageObjectChunk, ObjectChunk: chunk}}); err != nil {
			return err
		}
	}
	return nil
}

// GossipObjectPullResponse serves a read-only TCP object pull from the same
// committed Store owned by GossipDriver. A missing Store is treated like an empty
// source rather than allowing platform composition to read another state root.
func (driver *GossipDriver) GossipObjectPullResponse(request *gossip.ObjectPullRequest, now time.Time) *gossip.ObjectPullResponse {
	if driver == nil || driver.gossipState == nil {
		return &gossip.ObjectPullResponse{Error: "invalid request"}
	}
	view := driver.gossipState.ReadView()
	var network *zone.NetworkState
	if view.State != nil {
		network = view.State.Network
	}
	return gossip.BuildObjectPullResponse(network, request, now)
}
