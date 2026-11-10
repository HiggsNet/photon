package gossip

import "fmt"

// SyncEventName returns the stable diagnostic name for a session event.
func SyncEventName(event SyncEvent) string {
	switch event.(type) {
	case *SyncTimerEvent:
		return "sync_timer"
	case *PongReceivedEvent:
		return "pong"
	case *CatalogSummaryReceivedEvent:
		return "catalog_summary"
	case *CatalogPageReceivedEvent:
		return "catalog_page"
	case *CatalogPageTimeoutEvent:
		return "catalog_page_timeout"
	case *RoundTimeoutEvent:
		return "round_timeout"
	case *ChunkRepairTimeoutEvent:
		return "chunk_repair_timeout"
	case *ObjectPullResultEvent:
		return "object_pull_result"
	case *ObjectChunkEvent:
		return "object_chunk"
	case *SnapshotAppliedEvent:
		return "snapshot_applied"
	default:
		return fmt.Sprintf("%T", event)
	}
}

// SyncEventPeerID returns the peer owning a session event.
func SyncEventPeerID(event SyncEvent) string {
	switch event := event.(type) {
	case *SyncTimerEvent:
		return event.PeerID
	case *PongReceivedEvent:
		return event.PeerID
	case *CatalogSummaryReceivedEvent:
		return event.PeerID
	case *CatalogPageReceivedEvent:
		return event.PeerID
	case *CatalogPageTimeoutEvent:
		return event.PeerID
	case *RoundTimeoutEvent:
		return event.PeerID
	case *ChunkRepairTimeoutEvent:
		return event.PeerID
	case *ObjectPullResultEvent:
		return event.PeerID
	case *ObjectChunkEvent:
		return event.PeerID
	case *SnapshotAppliedEvent:
		return event.PeerID
	default:
		return ""
	}
}
