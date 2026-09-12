package text

import (
	"io"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteSyncStatus(w io.Writer, view inspect.SyncStatusView) error {
	out := newLineWriter(w)
	out.Linef("peer_id: %s", view.PeerID)
	out.Linef("listen_addr: %s", view.ListenAddr)
	out.Linef("known_peers: %d", view.KnownPeers)
	out.Linef("known_zones: %d", view.KnownZones)
	out.Linef("local_root: %s", view.LocalRootHex)
	wireCodec := view.Limits.WireCodec
	if wireCodec == "" {
		wireCodec = "msgpack"
	}
	out.Linef("limits: max_datagram_bytes=%d max_sync_zones=%d max_sync_records=%d wire_version=%d wire_codec=%s",
		view.Limits.MaxDatagramBytes,
		view.Limits.MaxSyncZones,
		view.Limits.MaxSyncRecords,
		view.Limits.WireVersion,
		wireCodec,
	)
	if view.Verbose {
		writeSyncVerbose(out, view)
	}
	for _, peer := range view.Peers {
		out.Linef("peer %s addr=%s status=%s last_sync=%s known_zones=%d last_failure=%s next_retry=%s",
			peer.PeerID,
			peer.Addr,
			peer.Status,
			peer.LastSync,
			peer.KnownZones,
			failureDisplay(peer.LastFailure),
			peer.NextRetry,
		)
	}
	for _, zone := range view.Zones {
		out.Linef("zone %s root=%s records=%d history=%d delegations=%d revocations=%d",
			zone.Zone,
			zone.RootHex,
			zone.Records,
			zone.History,
			zone.Delegations,
			zone.Revocations,
		)
	}
	return out.Err()
}

func writeSyncVerbose(out *lineWriter, view inspect.SyncStatusView) {
	out.Linef("allowlist_source: %s", dash(view.AllowlistSource))
	out.Linef("bootstrap_peers: %d", view.BootstrapPeers)
	out.Linef("discovered_peers: %d", view.DiscoveredPeers)
	for _, peer := range view.Bootstrap {
		out.Linef("bootstrap peer=%s configured_addr=%s resolved_addr=%s status=%s last_success=%s last_failure=%s next_retry=%s",
			peer.PeerID,
			peer.ConfiguredAddr,
			peer.ResolvedAddr,
			peer.Status,
			peer.LastSuccess,
			failureDisplay(peer.LastFailure),
			peer.NextRetry,
		)
		writeSyncPeerDetail(out, peer)
	}
	for _, peer := range view.Discovered {
		out.Linef("discovered peer=%s addr=%s status=%s last_success=%s",
			peer.PeerID,
			peer.Addr,
			peer.Status,
			peer.LastSuccess,
		)
		writeSyncPeerDetail(out, peer)
	}
}

func writeSyncPeerDetail(out *lineWriter, peer inspect.SyncVerbosePeerView) {
	out.Linef("  update_source=%s last_relay=%s relay_suppression=%s",
		dash(peer.LastUpdateSource),
		peer.LastRelay,
		peer.RelaySuppression,
	)
	out.Linef("  observed_addr=%s observed_status=%s",
		dash(peer.ObservedAddr),
		peer.ObservedStatus,
	)
	writeSyncFlowLine(out, peer.PeerID, peer.SyncFlow)
	writeDatagramStatsLine(out, peer.PeerID, peer.DatagramStats)
	writeObjectPullStatsLine(out, peer.PeerID, peer.ObjectPullStats)
}

func writeSyncFlowLine(out *lineWriter, peerID string, flow inspect.PeerSyncFlowView) {
	if flow.ActivePullState == "" &&
		flow.HintAccepted == 0 &&
		flow.HintSuppressed == 0 &&
		flow.ReadOnlyResponder == 0 {
		return
	}
	out.Linef("sync_flow peer=%s active_pull=%s active_event=%s active_updated=%s hint_accepted=%d hint_suppressed=%d last_hint=%s hint_reason=%s hint_suppression=%s read_only_responder=%d responder_kind=%s responder_zone=%s responder_last=%s",
		peerID,
		dash(flow.ActivePullState),
		dash(flow.ActivePullLastEvent),
		flow.ActivePullUpdated,
		flow.HintAccepted,
		flow.HintSuppressed,
		flow.LastHint,
		dash(flow.LastHintReason),
		dash(flow.LastHintSuppression),
		flow.ReadOnlyResponder,
		dash(flow.LastResponderKind),
		dash(flow.LastResponderZone),
		flow.LastResponder,
	)
}

func writeDatagramStatsLine(out *lineWriter, peerID string, stats inspect.PeerDatagramStatsView) {
	if stats.TooLargeDropped == 0 &&
		stats.DigestOnlyAnnounces == 0 &&
		stats.ChunkFallbacks == 0 &&
		stats.ChunkRepairNACKs == 0 &&
		stats.ChunkRepairChunks == 0 &&
		stats.ChunkRepairIgnored == 0 &&
		stats.LastCatalogRootHex == "" &&
		stats.LastCatalogRejectedReason == "" {
		return
	}
	if stats.LastCatalogRootHex != "" || stats.LastCatalogRejectedReason != "" {
		lastCatalog := stats.LastCatalog
		if lastCatalog == "" || lastCatalog == "never" {
			lastCatalog = "-"
		}
		out.Linef("catalog peer=%s root=%s zone_count=%d cursor=%s page_entries=%d last=%s rejected_reason=%s",
			peerID,
			dash(stats.LastCatalogRootHex),
			stats.LastCatalogZoneCount,
			dash(stats.LastCatalogCursor),
			stats.LastCatalogPageEntries,
			lastCatalog,
			dash(stats.LastCatalogRejectedReason),
		)
	}
	last := stats.LastTooLarge
	if last == "" || last == "never" {
		last = "-"
	}
	out.Linef("datagram peer=%s too_large_dropped=%d digest_only_announces=%d chunk_fallbacks=%d repair_nacks=%d repair_chunks=%d repair_ignored=%d last_too_large=%s direction=%s object=%s zone=%s key=%s bytes=%d limit=%d",
		peerID,
		stats.TooLargeDropped,
		stats.DigestOnlyAnnounces,
		stats.ChunkFallbacks,
		stats.ChunkRepairNACKs,
		stats.ChunkRepairChunks,
		stats.ChunkRepairIgnored,
		last,
		dash(stats.LastTooLargeDirection),
		dash(stats.LastTooLargeObject),
		dash(stats.LastTooLargeZone),
		dash(stats.LastTooLargeKey),
		stats.LastTooLargeBytes,
		stats.LastTooLargeLimit,
	)
}

func writeObjectPullStatsLine(out *lineWriter, peerID string, stats inspect.PeerObjectPullStatsView) {
	if stats.Attempts == 0 &&
		stats.Successes == 0 &&
		stats.Failures == 0 &&
		stats.LargeObjectUnreachable == 0 {
		return
	}
	last := stats.Last
	if last == "" || last == "never" {
		last = "-"
	}
	out.Linef("object_pull peer=%s attempts=%d successes=%d failures=%d large_object_unreachable=%d last=%s object=%s zone=%s key=%s bytes=%d source_peer=%s unreachable=%t last_failure=%s",
		peerID,
		stats.Attempts,
		stats.Successes,
		stats.Failures,
		stats.LargeObjectUnreachable,
		last,
		dash(stats.LastObject),
		dash(stats.LastZone),
		dash(stats.LastKey),
		stats.LastBytes,
		dash(stats.LastSourcePeer),
		stats.LastUnreachable,
		failureDisplay(stats.LastFailure),
	)
}
