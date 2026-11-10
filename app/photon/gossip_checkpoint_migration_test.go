package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestProjectLegacyGossipCheckpointKeepsOnlyBehaviorHints(t *testing.T) {
	root := []byte("root")
	checkpoint, report := projectLegacyGossipCheckpoint(map[string]legacyPeerState{
		"peer-a.catofes.": {
			LastSyncUnix: 10, LastAttemptUnix: 11, BackoffUntilUnix: 20, FailureCount: 2,
			LastRelayUnix: 12, LastRelayCatalogRootHex: "catalog",
			DiscoveredAddr: "192.0.2.1:4242",
			RejectedDigests: map[string]photonstate.PeerRejectedDigest{"zone:bad.catofes.": {
				Zone: "bad.catofes.", Object: "zone", RootHashHex: hex.EncodeToString(root),
				Reason: "invalid_snapshot", RejectedAtUnix: 18, UntilUnix: 28,
			}},
			LastError: "diagnostic",
		},
	})
	if report.PeersMigrated != 1 || report.RejectedMigrated != 1 || report.PeersDropped != 0 || report.RejectedDropped != 0 {
		t.Fatalf("report = %+v", report)
	}
	peer := checkpoint.Peers["peer-a.catofes."]
	if peer.BackoffUntilUnix != 20 || peer.LastRelayCatalogRootHex != "catalog" || peer.DiscoveredEndpoint != "192.0.2.1:4242" {
		t.Fatalf("checkpoint peer = %+v", peer)
	}
	if peer.LastFailure == nil || peer.LastFailure.Code != corestate.PeerFailureLegacy || peer.LastFailure.Error() != "diagnostic" || peer.LastFailure.AtUnix != 11 {
		t.Fatalf("typed legacy failure = %+v", peer.LastFailure)
	}
	rejected := peer.RejectedObjects["bad.catofes."]
	if string(rejected.RootHash) != "root" || rejected.UntilUnix != 28 {
		t.Fatalf("rejected = %+v", rejected)
	}
}

func TestProjectLegacyPeerCleanupsPreservesSuppressionWithoutOverwritingNewerActivity(t *testing.T) {
	checkpoint := &corestate.GossipCheckpoint{Peers: map[string]corestate.PeerCheckpoint{
		"stale.catofes.": {LastSyncUnix: 5, ObservedLastSeenUnix: 30},
		"fresh.catofes.": {LastSyncUnix: 20},
	}}
	cleanups := map[string]photonlinux.LegacyPeerCleanupState{
		"cleaned.catofes.": {LastActiveUnix: 10, CleanupUnix: 15, Reason: peerCleanupReasonOffline},
		"stale.catofes.":   {LastActiveUnix: 10, CleanupUnix: 15, Reason: peerCleanupReasonOffline},
		"fresh.catofes.":   {LastActiveUnix: 10, CleanupUnix: 15, Reason: peerCleanupReasonOffline},
		"revoked.catofes.": {LastActiveUnix: 10, CleanupUnix: 15, Reason: "zone_revoked"},
		"invalid":          {LastActiveUnix: 10, CleanupUnix: 15, Reason: peerCleanupReasonOffline},
	}
	runtime := &photonlinux.LinuxState{}
	report := projectLegacyPeerCleanups(checkpoint, cleanups, runtime, legacyGossipCheckpointReport{})
	if report.CleanupsMigrated != 1 || report.CleanupsDropped != 4 || len(runtime.SuspendedTunnelPeers) != 1 || !runtime.SuspendedTunnelPeers["cleaned.catofes."] {
		t.Fatalf("suspensions = %v report = %+v", runtime.SuspendedTunnelPeers, report)
	}
	if len(checkpoint.Peers) != 2 {
		t.Fatal("suspension migration modified the gossip checkpoint")
	}
}

func TestProjectLegacyGossipCheckpointKeepsFailureAndDropsMalformedHints(t *testing.T) {
	checkpoint, report := projectLegacyGossipCheckpoint(map[string]legacyPeerState{
		"diagnostic.catofes.": {LastError: "only diagnostic"},
		"invalid":             {BackoffUntilUnix: 10},
		"peer.catofes.": {RejectedDigests: map[string]photonstate.PeerRejectedDigest{
			"bad-root": {Zone: "bad.catofes.", Object: "zone", RootHashHex: "not-hex"},
			"record":   {Zone: "bad.catofes.", Object: "record", Key: "identity", RootHashHex: "00"},
		}},
	})
	if len(checkpoint.Peers) != 1 || checkpoint.Peers["diagnostic.catofes."].LastFailure == nil {
		t.Fatalf("checkpoint peers = %+v, want typed legacy failure", checkpoint.Peers)
	}
	if report.PeersDropped != 1 || report.RejectedDropped != 2 || report.PeersMigrated != 1 {
		t.Fatalf("report = %+v", report)
	}
}

func TestProjectLegacyCommonStateRejectsMalformedRequiredFields(t *testing.T) {
	tests := []struct {
		name  string
		state *legacyStateFixture
	}{
		{name: "nil state"},
		{name: "missing network", state: &legacyStateFixture{stateMeta: stateMeta{ManagedZone: zone.RootZone}}},
		{name: "missing managed zone", state: &legacyStateFixture{stateMeta: stateMeta{ManagedZone: "node.catofes."}, Network: zone.NewNetworkState()}},
		{name: "bad root key", state: legacyProjectionFixture([]byte("short"), nil)},
		{name: "bad identity key", state: legacyProjectionFixture(nil, []byte("short"))},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var meta *stateMeta
			var network *zone.NetworkState
			if test.state != nil {
				meta, network = &test.state.stateMeta, test.state.Network
			}
			if _, _, err := projectLegacyCommonState(meta, network, nil); !errors.Is(err, errLegacyCommonStateInvalid) || !errors.Is(err, corestate.ErrInvalidStateRoot) {
				t.Fatalf("error = %v, want errLegacyCommonStateInvalid", err)
			}
		})
	}
}

func legacyProjectionFixture(rootPrivate, identityPrivate []byte) *legacyStateFixture {
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, &zone.ZoneAuthority{Zone: zone.RootZone})
	return &legacyStateFixture{Network: network, stateMeta: stateMeta{
		ManagedZone:    zone.RootZone,
		RootPrivateKey: append(ed25519.PrivateKey(nil), rootPrivate...), ZonePrivateKey: append(ed25519.PrivateKey(nil), identityPrivate...),
	}}
}
