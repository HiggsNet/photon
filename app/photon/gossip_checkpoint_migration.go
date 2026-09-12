package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"

	photonstate "github.com/HiggsNet/photon/internal/state"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

var errLegacyCommonStateInvalid = errors.New("legacy common state is invalid")

// legacyGossipCheckpointReport makes loss-tolerant migration explicit. A
// malformed checkpoint entry never prevents verified state from loading.
type legacyGossipCheckpointReport struct {
	PeersMigrated    int
	PeersDropped     int
	RejectedMigrated int
	RejectedDropped  int
}

// projectLegacyCommonState is used only inside the one-way old-database
// migration. Platform controller fields are intentionally unreachable from
// the returned candidate; no online compatibility adapter exposes this API.
func projectLegacyCommonState(state *stateFile, trustedRoot ed25519.PublicKey) (*corestate.CommitCandidate, legacyGossipCheckpointReport, error) {
	if state == nil {
		return nil, legacyGossipCheckpointReport{}, fmt.Errorf("%w: %w", errLegacyCommonStateInvalid, corestate.ValidateStateRoot(nil))
	}
	network := zone.CloneNetworkState(state.Network)
	checkpoint, report := projectLegacyGossipCheckpoint(state.SyncPeers)
	candidate := &corestate.CommitCandidate{
		Verified: &corestate.VerifiedState{
			ManagedZone:          state.ManagedZone,
			Network:              network,
			TrustedRootPublicKey: append(ed25519.PublicKey(nil), trustedRoot...),
			RootPrivateKey:       append(ed25519.PrivateKey(nil), state.RootPrivateKey...),
			IdentityPrivateKey:   append(ed25519.PrivateKey(nil), state.ZonePrivateKey...),
		},
		Gossip: checkpoint,
	}
	if err := corestate.ValidateStateRoot(candidate.Verified); err != nil {
		return nil, legacyGossipCheckpointReport{}, fmt.Errorf("%w: %w", errLegacyCommonStateInvalid, err)
	}
	if len(candidate.Verified.TrustedRootPublicKey) == 0 {
		root := network.Zones[zone.RootZone]
		if root == nil || root.Authority == nil || len(root.Authority.Keys) != 1 || len(root.Authority.Keys[0].Key) != ed25519.PublicKeySize {
			return nil, legacyGossipCheckpointReport{}, fmt.Errorf("%w: %w: legacy trusted root pin is unavailable", errLegacyCommonStateInvalid, corestate.ErrInvalidStateRoot)
		}
		candidate.Verified.TrustedRootPublicKey = append(ed25519.PublicKey(nil), root.Authority.Keys[0].Key...)
		if err := corestate.ValidateStateRoot(candidate.Verified); err != nil {
			return nil, legacyGossipCheckpointReport{}, fmt.Errorf("%w: %w", errLegacyCommonStateInvalid, err)
		}
	}
	configureValidation(candidate.Verified.Network)
	return candidate, report, nil
}

// projectLegacyGossipCheckpoint is used only by the one-way schema migration.
// Only restart hints and the most recent typed failure survive. Session state
// and pure counters are intentionally omitted.
func projectLegacyGossipCheckpoint(peers map[string]photonstate.PeerRuntimeState) (*corestate.GossipCheckpoint, legacyGossipCheckpointReport) {
	checkpoint := &corestate.GossipCheckpoint{Peers: make(map[string]corestate.PeerCheckpoint)}
	var report legacyGossipCheckpointReport
	peerIDs := make([]string, 0, len(peers))
	for peerID := range peers {
		peerIDs = append(peerIDs, peerID)
	}
	sort.Strings(peerIDs)
	for _, peerID := range peerIDs {
		path := zone.ZonePath(peerID)
		if !path.Valid() || path == zone.RootZone {
			report.PeersDropped++
			continue
		}
		legacy := peers[peerID]
		peer := corestate.PeerCheckpoint{
			LastSyncUnix:            legacy.LastSyncUnix,
			LastAttemptUnix:         legacy.LastAttemptUnix,
			BackoffUntilUnix:        legacy.BackoffUntilUnix,
			FailureCount:            legacy.FailureCount,
			LastRelayUnix:           legacy.LastRelayUnix,
			LastRelayCatalogRootHex: legacy.LastRelayCatalogRootHex,
			DiscoveredEndpoint:      legacy.DiscoveredAddr,
			DiscoveredAtUnix:        legacy.DiscoveredAtUnix,
			ObservedEndpoint:        legacy.ObservedAddr,
			ObservedFirstSeenUnix:   legacy.ObservedFirstSeenUnix,
			ObservedLastSeenUnix:    legacy.ObservedLastSeenUnix,
			ObservedLastSyncUnix:    legacy.ObservedLastSyncUnix,
			ObservedUntilUnix:       legacy.ObservedUntilUnix,
			ObservedFailureCount:    legacy.ObservedFailureCount,
		}
		if legacy.LastError != "" {
			peer.LastFailure = &corestate.PeerFailure{
				Code: corestate.PeerFailureLegacy, Message: legacy.LastError, AtUnix: legacy.LastAttemptUnix,
			}
		}
		for _, grace := range legacy.ObservedGraceAddrs {
			if grace.Addr == "" {
				continue
			}
			peer.ObservedGraceEndpoints = append(peer.ObservedGraceEndpoints, corestate.ObservedGraceEndpoint{
				Endpoint: grace.Addr, UntilUnix: grace.UntilUnix,
			})
		}
		peer.RejectedObjects, report = projectLegacyRejectedObjects(legacy.RejectedDigests, report)
		if peerCheckpointEmpty(peer) {
			continue
		}
		checkpoint.Peers[peerID] = peer
		report.PeersMigrated++
	}
	return checkpoint, report
}

func projectLegacyRejectedObjects(rejected map[string]photonstate.PeerRejectedDigest, report legacyGossipCheckpointReport) (map[zone.ZonePath]corestate.RejectedObject, legacyGossipCheckpointReport) {
	out := make(map[zone.ZonePath]corestate.RejectedObject)
	keys := make([]string, 0, len(rejected))
	for key := range rejected {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		item := rejected[key]
		if !item.Zone.Valid() || (item.Object != "" && item.Object != string(gossip.ObjectPullZone)) || item.Key != "" || item.RootHashHex == "" {
			report.RejectedDropped++
			continue
		}
		root, err := hex.DecodeString(item.RootHashHex)
		if err != nil || len(root) == 0 {
			report.RejectedDropped++
			continue
		}
		candidate := corestate.RejectedObject{
			RootHash: root, Reason: item.Reason, UpdatedUnix: item.RejectedAtUnix, UntilUnix: item.UntilUnix,
		}
		if current, ok := out[item.Zone]; ok && current.UpdatedUnix > candidate.UpdatedUnix {
			continue
		}
		out[item.Zone] = candidate
		report.RejectedMigrated++
	}
	if len(out) == 0 {
		return nil, report
	}
	return out, report
}

func peerCheckpointEmpty(peer corestate.PeerCheckpoint) bool {
	return peer.LastSyncUnix == 0 && peer.LastAttemptUnix == 0 && peer.BackoffUntilUnix == 0 &&
		peer.FailureCount == 0 && peer.LastRelayUnix == 0 && peer.LastRelayCatalogRootHex == "" &&
		peer.DiscoveredEndpoint == "" && peer.DiscoveredAtUnix == 0 &&
		peer.ObservedEndpoint == "" && peer.ObservedFirstSeenUnix == 0 && peer.ObservedLastSeenUnix == 0 &&
		peer.ObservedLastSyncUnix == 0 && peer.ObservedUntilUnix == 0 && peer.ObservedFailureCount == 0 &&
		len(peer.ObservedGraceEndpoints) == 0 && peer.LastFailure == nil && len(peer.RejectedObjects) == 0
}
