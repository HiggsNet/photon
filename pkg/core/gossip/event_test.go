package gossip

import "testing"

func TestSyncEventMetadata(t *testing.T) {
	tests := []struct {
		event SyncEvent
		name  string
	}{
		{&SyncTimerEvent{PeerID: "peer"}, "sync_timer"},
		{&PongReceivedEvent{PeerID: "peer"}, "pong"},
		{&CatalogSummaryReceivedEvent{PeerID: "peer"}, "catalog_summary"},
		{&CatalogPageReceivedEvent{PeerID: "peer"}, "catalog_page"},
		{&CatalogPageTimeoutEvent{PeerID: "peer"}, "catalog_page_timeout"},
		{&RoundTimeoutEvent{PeerID: "peer"}, "round_timeout"},
		{&ObjectPullResultEvent{PeerID: "peer"}, "object_pull_result"},
		{&ObjectChunkEvent{PeerID: "peer"}, "object_chunk"},
		{&SnapshotAppliedEvent{PeerID: "peer"}, "snapshot_applied"},
	}
	for _, test := range tests {
		if got := SyncEventName(test.event); got != test.name {
			t.Errorf("SyncEventName(%T) = %q, want %q", test.event, got, test.name)
		}
		if got := SyncEventPeerID(test.event); got != "peer" {
			t.Errorf("SyncEventPeerID(%T) = %q, want peer", test.event, got)
		}
	}
}

func TestSyncEventMetadataForNil(t *testing.T) {
	if got := SyncEventPeerID(nil); got != "" {
		t.Fatalf("SyncEventPeerID(nil) = %q, want empty", got)
	}
	if got := SyncEventName(nil); got != "<nil>" {
		t.Fatalf("SyncEventName(nil) = %q, want <nil>", got)
	}
}
