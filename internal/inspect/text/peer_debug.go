package text

import (
	"io"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WritePeerDebug(w io.Writer, view inspect.PeerDebugView) error {
	out := newLineWriter(w)
	out.Linef("peer_id: %s", view.PeerID)
	out.Linef("source: %s", view.Source)
	out.Linef("configured_addr: %s", dash(view.ConfiguredAddr))
	out.Linef("resolved_addr: %s", dash(view.ResolvedAddr))
	out.Linef("status: %s", view.Status)
	out.Linef("last_success: %s", view.LastSuccess)
	out.Linef("last_failure: %s", failureDisplay(view.LastFailure))
	out.Linef("backoff: %s", dash(view.Backoff))
	out.Linef("next_retry: %s", dash(view.NextRetry))
	out.Linef("known_endpoint: %s", dash(view.KnownEndpoint))
	out.Linef("discovered_addr: %s", dash(view.DiscoveredAddr))
	out.Linef("observed_addr: %s", dash(view.ObservedAddr))
	out.Linef("observed_status: %s", view.ObservedStatus)
	out.Linef("last_update_source: %s", dash(view.LastUpdateSource))
	out.Linef("last_relay: %s", view.LastRelay)
	out.Linef("relay_suppression: %s", view.RelaySuppression)
	writePeerDebugSyncFlow(out, view.SyncFlow)
	writePeerDebugDatagramStats(out, view.DatagramStats)
	writePeerDebugObjectPullStats(out, view.ObjectPullStats)
	return out.Err()
}

func writePeerDebugSyncFlow(out *lineWriter, flow inspect.PeerSyncFlowView) {
	out.Linef("active_pull_state: %s", dash(flow.ActivePullState))
	out.Linef("active_pull_last_event: %s", dash(flow.ActivePullLastEvent))
	out.Linef("active_pull_updated: %s", flow.ActivePullUpdated)
	out.Linef("hint_accepted: %d", flow.HintAccepted)
	out.Linef("hint_suppressed: %d", flow.HintSuppressed)
	out.Linef("hint_last: %s reason=%s suppression=%s",
		flow.LastHint,
		dash(flow.LastHintReason),
		dash(flow.LastHintSuppression),
	)
	out.Linef("read_only_responder: %d", flow.ReadOnlyResponder)
	out.Linef("read_only_responder_last: %s kind=%s zone=%s",
		flow.LastResponder,
		dash(flow.LastResponderKind),
		dash(flow.LastResponderZone),
	)
}

func writePeerDebugDatagramStats(out *lineWriter, stats inspect.PeerDatagramStatsView) {
	out.Linef("datagram_too_large_dropped: %d", stats.TooLargeDropped)
	out.Linef("datagram_digest_only_announces: %d", stats.DigestOnlyAnnounces)
	out.Linef("datagram_chunk_fallbacks: %d", stats.ChunkFallbacks)
	out.Linef("datagram_chunk_repair_nacks: %d", stats.ChunkRepairNACKs)
	out.Linef("datagram_chunk_repair_chunks: %d", stats.ChunkRepairChunks)
	out.Linef("datagram_chunk_repair_ignored: %d", stats.ChunkRepairIgnored)
	out.Linef("catalog_root: %s", dash(stats.LastCatalogRootHex))
	out.Linef("catalog_zone_count: %d", stats.LastCatalogZoneCount)
	out.Linef("catalog_last_page_cursor: %s", dash(stats.LastCatalogCursor))
	out.Linef("catalog_last_page_entries: %d", stats.LastCatalogPageEntries)
	out.Linef("catalog_last_rejected_reason: %s", dash(stats.LastCatalogRejectedReason))
	if stats.LastTooLarge == "" || stats.LastTooLarge == "never" {
		out.Linef("datagram_last_too_large: -")
		return
	}
	out.Linef("datagram_last_too_large: %s direction=%s object=%s zone=%s key=%s bytes=%d limit=%d",
		stats.LastTooLarge,
		dash(stats.LastTooLargeDirection),
		dash(stats.LastTooLargeObject),
		dash(stats.LastTooLargeZone),
		dash(stats.LastTooLargeKey),
		stats.LastTooLargeBytes,
		stats.LastTooLargeLimit,
	)
}

func writePeerDebugObjectPullStats(out *lineWriter, stats inspect.PeerObjectPullStatsView) {
	out.Linef("object_pull_attempts: %d", stats.Attempts)
	out.Linef("object_pull_successes: %d", stats.Successes)
	out.Linef("object_pull_failures: %d", stats.Failures)
	out.Linef("object_pull_large_object_unreachable: %d", stats.LargeObjectUnreachable)
	if stats.Last == "" || stats.Last == "never" {
		out.Linef("object_pull_last: -")
		return
	}
	out.Linef("object_pull_last: %s object=%s zone=%s key=%s bytes=%d source_peer=%s unreachable=%t failure=%s",
		stats.Last,
		dash(stats.LastObject),
		dash(stats.LastZone),
		dash(stats.LastKey),
		stats.LastBytes,
		dash(stats.LastSourcePeer),
		stats.LastUnreachable,
		failureDisplay(stats.LastFailure),
	)
}
