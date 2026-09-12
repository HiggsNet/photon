package main

import (
	"encoding/json"
	"reflect"
	"testing"

	photonstate "github.com/HiggsNet/photon/internal/state"
)

func TestLegacyPeerDiagnosticsAreIgnored(t *testing.T) {
	var meta stateMeta
	err := json.Unmarshal([]byte(`{
		"sync_peers": {
			"peer-a.catofes.": {
				"datagram_stats": {"chunk_fallbacks": 2},
				"object_pull_stats": {"attempts": 3},
				"active_pull_state": "object_pulling",
				"hint_accepted": 2,
				"read_only_responder": 3
			}
		}
	}`), &meta)
	if err != nil {
		t.Fatalf("Unmarshal legacy state: %v", err)
	}
	peer := meta.SyncPeers["peer-a.catofes."]
	if !reflect.DeepEqual(peer, photonstate.PeerRuntimeState{}) {
		t.Fatalf("legacy diagnostics leaked into runtime state: %#v", peer)
	}
}

func TestLegacyStateMetaCannotPersistPeerDiagnostics(t *testing.T) {
	meta := stateMeta{SyncPeers: map[string]photonstate.PeerRuntimeState{
		"peer-a.catofes.": {LastSyncUnix: 42},
	}}
	data, err := json.Marshal(meta)
	if err != nil {
		t.Fatalf("Marshal state metadata: %v", err)
	}
	if string(data) == "" || json.Valid(data) == false {
		t.Fatalf("invalid state metadata: %q", data)
	}
	var decoded map[string]any
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatalf("Unmarshal state metadata: %v", err)
	}
	peers := decoded["sync_peers"].(map[string]any)
	encodedPeer := peers["peer-a.catofes."].(map[string]any)
	if got := encodedPeer["last_sync_unix"]; got != float64(42) {
		t.Fatalf("legacy control state = %#v, want last_sync_unix 42", encodedPeer)
	}
	if _, ok := encodedPeer["datagram_stats"]; ok {
		t.Fatalf("datagram diagnostics were persisted: %#v", encodedPeer)
	}
	if _, ok := encodedPeer["object_pull_stats"]; ok {
		t.Fatalf("object-pull diagnostics were persisted: %#v", encodedPeer)
	}
	for _, field := range []string{"active_pull_state", "hint_accepted", "read_only_responder"} {
		if _, ok := encodedPeer[field]; ok {
			t.Fatalf("protocol diagnostic %q was persisted: %#v", field, encodedPeer)
		}
	}
}
