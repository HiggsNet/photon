package host

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

const GossipChunkRepairNamespace = "gossip_chunk_repair"

var ErrGossipChunkStoreUnavailable = errors.New("gossip chunk store is unavailable")

type GossipObjectChunkResult struct {
	PeerID        string
	Zone          string
	Complete      bool
	ChunkFallback bool
	CheckpointErr error
}

// HandleGossipObjectChunk owns bounded assembly, repair scheduling, snapshot
// decoding/root verification and completion delivery. These are common gossip
// semantics; platforms only observe the detached result.
func (driver *GossipDriver) HandleGossipObjectChunk(ctx context.Context, message *gossip.Message, now time.Time) (GossipObjectChunkResult, error) {
	var result GossipObjectChunkResult
	if driver == nil {
		return result, ErrGossipDriverStopped
	}
	if message == nil || message.ObjectChunk == nil {
		return result, nil
	}
	chunk := message.ObjectChunk
	result.PeerID = message.PeerID
	result.Zone = chunk.Zone.String()
	data, complete, err := driver.AddGossipObjectChunk(message.PeerID, chunk, now)
	if err != nil {
		return driver.rejectGossipObjectChunk(ctx, message.PeerID, chunk, result, err, now)
	}
	if !complete {
		return result, driver.ScheduleGossipChunkRepair(message.PeerID, chunk)
	}
	result.Complete = true
	if chunk.Object != gossip.ObjectPullZone {
		return result, nil
	}
	snapshot, err := gossip.DecodeZoneSnapshotObject(data)
	if err != nil {
		return driver.rejectGossipObjectChunk(ctx, message.PeerID, chunk, result, err, now)
	}
	actualRoot := corestate.ZoneRoot(corestate.ZoneStateFromSnapshot(snapshot))
	if len(chunk.RootHash) > 0 && !bytes.Equal(chunk.RootHash, actualRoot) {
		err = fmt.Errorf("chunk snapshot root mismatch for %s: advertised %x, decoded %x", snapshot.Zone, chunk.RootHash, actualRoot)
		return driver.rejectGossipObjectChunk(ctx, message.PeerID, chunk, result, err, now)
	}
	result.ChunkFallback = true
	err = driver.PostGossip(&gossip.ObjectChunkEvent{PeerID: message.PeerID, Zone: chunk.Zone, Snapshot: snapshot})
	return result, err
}

func (driver *GossipDriver) rejectGossipObjectChunk(ctx context.Context, peerID string, chunk *gossip.ObjectChunk, result GossipObjectChunkResult, chunkErr error, now time.Time) (GossipObjectChunkResult, error) {
	result.CheckpointErr = driver.RecordGossipRejectedObject(ctx, peerID, chunk, chunkErr, now)
	_ = driver.PostGossip(&gossip.ObjectChunkEvent{PeerID: peerID, Zone: chunk.Zone, Err: chunkErr})
	return result, chunkErr
}

// AddGossipObjectChunk adds one UDP chunk to this host's bounded in-memory
// assembly store. Chunk state is scoped to one GossipDriver and never persisted.
func (driver *GossipDriver) AddGossipObjectChunk(peerID string, chunk *gossip.ObjectChunk, now time.Time) ([]byte, bool, error) {
	if driver == nil || driver.gossipChunks == nil {
		return nil, false, ErrGossipChunkStoreUnavailable
	}
	driver.mu.RLock()
	defer driver.mu.RUnlock()
	if driver.stopped {
		return nil, false, ErrGossipDriverStopped
	}
	scheduler := driver.scheduler
	data, complete, err := driver.gossipChunks.Add(peerID, chunk, now)
	if complete && chunk != nil {
		scheduler.Cancel(gossipChunkRepairTimerID(peerID, chunk.TransferID))
	}
	return data, complete, err
}

// ScheduleGossipChunkRepair puts the gossip-selected quiet deadline onto the
// one GossipDriver scheduler. No protocol package creates a timer or goroutine.
func (driver *GossipDriver) ScheduleGossipChunkRepair(peerID string, chunk *gossip.ObjectChunk) error {
	if driver == nil || driver.gossipChunks == nil {
		return ErrGossipChunkStoreUnavailable
	}
	driver.mu.RLock()
	defer driver.mu.RUnlock()
	if driver.stopped {
		return ErrGossipDriverStopped
	}
	scheduler := driver.scheduler
	deadline, ok := driver.gossipChunks.RepairDeadline(peerID, chunk)
	if !ok {
		return nil
	}
	_, err := scheduler.Schedule(gossipChunkRepairTimerID(peerID, chunk.TransferID), deadline)
	return err
}

func (driver *GossipDriver) dropGossipPeerChunks(peerID string) {
	if driver != nil && driver.gossipChunks != nil {
		driver.gossipChunks.DropPeer(peerID)
		driver.schedulerForRead().CancelOwner(GossipChunkRepairNamespace, peerID)
	}
}

func gossipChunkRepairTimerID(peerID string, transferID []byte) TimerID {
	return TimerID{Namespace: GossipChunkRepairNamespace, Owner: peerID, Key: hex.EncodeToString(transferID)}
}
