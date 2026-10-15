package host

import (
	"context"
	"encoding/hex"
	"errors"
	"math"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
)

const GossipChunkSendNamespace = "gossip_chunk_send"
const gossipChunkSendBatch = 16

// Only the host event consumer advances a send. Stop may discard the map under
// driver.mu; it never edits a cursor already held by the consumer.
type gossipChunkSend struct {
	sender     GossipSender
	transferID []byte
	indexes    []uint16
	expires    time.Time
}

func (driver *GossipDriver) queueGossipChunkSend(ctx context.Context, peerID string, chunks []*gossip.ObjectChunk, sender GossipSender) error {
	if len(chunks) == 0 {
		return nil
	}
	id := TimerID{Namespace: GossipChunkSendNamespace, Owner: peerID, Key: hex.EncodeToString(chunks[0].TransferID)}
	driver.mu.Lock()
	if driver.stopped {
		driver.mu.Unlock()
		return ErrGossipDriverStopped
	}
	job := driver.gossipChunkSends[id]
	if job == nil {
		job = &gossipChunkSend{sender: sender, transferID: append([]byte(nil), chunks[0].TransferID...), expires: driver.scheduler.clock.Now().Add(gossip.ChunkTransferTTL)}
		driver.gossipChunkSends[id] = job
	}
	driver.mu.Unlock()
	// A repair may overlap a paced initial transfer. Merge indexes instead of
	// retaining duplicate payloads or repeatedly sending already queued parts.
	queued := make(map[uint16]bool, len(job.indexes)+len(chunks))
	for _, index := range job.indexes {
		queued[index] = true
	}
	for _, chunk := range chunks {
		if !queued[chunk.Index] {
			job.indexes = append(job.indexes, chunk.Index)
			queued[chunk.Index] = true
		}
	}
	return driver.flushGossipChunkSend(ctx, id)
}

func (driver *GossipDriver) flushGossipChunkSend(ctx context.Context, id TimerID) error {
	driver.mu.RLock()
	job := driver.gossipChunkSends[id]
	driver.mu.RUnlock()
	if job == nil {
		return nil
	}
	finish := func() {
		driver.mu.Lock()
		delete(driver.gossipChunkSends, id)
		driver.mu.Unlock()
		driver.schedulerForRead().Cancel(id)
	}
	now := driver.schedulerForRead().clock.Now()
	if !now.Before(job.expires) {
		finish()
		return nil
	}
	delay := time.Millisecond
	for sent := 0; sent < gossipChunkSendBatch && len(job.indexes) > 0; sent++ {
		chunk := driver.gossipSentChunks.Chunk(id.Owner, job.transferID, job.indexes[0], now)
		if chunk == nil {
			finish()
			return nil
		}
		err := job.sender.SendGossip(ctx, gossip.OutboundMessage{PeerID: id.Owner, Message: &gossip.Message{Type: gossip.MessageObjectChunk, ObjectChunk: chunk}})
		if err != nil {
			var quotaErr *gossip.QuotaExceededError
			if !errors.As(err, &quotaErr) || quotaErr.RequestedBytes > quotaErr.ByteBurst || quotaErr.RequestedObjects > quotaErr.ObjectBurst {
				finish()
				driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: id.Owner, Err: err})
				return err
			}
			// Do not sleep on the host event loop. Retain the failed index and
			// resume through its existing bounded, generation-checked scheduler.
			// Refill a small batch rather than waking once per token. At the
			// default rate eight parts take 62.5ms, below repair quiet time.
			parts := int64(min(gossipChunkSendBatch/2, len(job.indexes)))
			bytes := min(quotaErr.ByteBurst, quotaErr.RequestedBytes*parts)
			objects := min(quotaErr.ObjectBurst, quotaErr.RequestedObjects*parts)
			seconds := max(float64(bytes-quotaErr.AvailableBytes)/float64(quotaErr.ByteRate), float64(objects-quotaErr.AvailableObjects)/float64(quotaErr.ObjectRate))
			delay = max(time.Millisecond, time.Duration(math.Ceil(min(seconds, gossip.ChunkTransferTTL.Seconds())*float64(time.Second))))
			break
		}
		job.indexes = job.indexes[1:]
	}
	if len(job.indexes) == 0 {
		finish()
		return nil
	}
	deadline := driver.schedulerForRead().clock.Now().Add(delay)
	if deadline.After(job.expires) {
		deadline = job.expires
	}
	_, err := driver.schedulerForRead().Schedule(id, deadline)
	if err != nil {
		finish()
	}
	return err
}
