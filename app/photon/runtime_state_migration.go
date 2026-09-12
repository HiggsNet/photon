package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/HiggsNet/photon/internal/photonlinux"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

var (
	bucketLegacyMeta = []byte("_meta")

	errLegacyStateConflict = errors.New("legacy and common state representations coexist")
)

type legacyStateMigrationReport struct {
	Gossip legacyGossipCheckpointReport
}

// migrateLegacyLinuxStateTx atomically replaces the legacy _meta/cli_state
// plus zone:* representation with the common state buckets and one Linux
// runtime bucket. The caller owns tx and decides commit/rollback. This remains
// detached from the online loader until the single-writer cutover.
func migrateLegacyLinuxStateTx(tx *bolt.Tx, trustedRoot ed25519.PublicKey) (legacyStateMigrationReport, bool, error) {
	var report legacyStateMigrationReport
	if tx == nil || !tx.Writable() {
		return report, false, errors.New("legacy state migration requires a writable bbolt transaction")
	}
	_, _, _, commonFound, err := corestate.LoadBoltState(tx)
	if err != nil {
		return report, false, err
	}
	legacyMeta := tx.Bucket(bucketLegacyMeta)
	legacyMetadataPresent := legacyMeta != nil && legacyMeta.Get([]byte(cliMetaKey)) != nil
	legacyNetwork, err := zone.LoadNetworkTx(tx)
	if err != nil {
		return report, false, err
	}
	legacyNetworkPresent := len(legacyNetwork.Zones) > 0

	if commonFound {
		if legacyMetadataPresent || legacyNetworkPresent {
			return report, false, errLegacyStateConflict
		}
		if _, found, err := photonlinux.LoadLinuxStateTx(tx); err != nil {
			return report, false, err
		} else if !found {
			return report, false, fmt.Errorf("%w: runtime bucket is missing", photonlinux.ErrLinuxStateCorrupt)
		}
		return report, false, nil
	}
	if tx.Bucket([]byte(photonlinux.LinuxStateBucketName)) != nil {
		return report, false, errLegacyStateConflict
	}
	if !legacyMetadataPresent && !legacyNetworkPresent {
		return report, false, nil
	}
	if !legacyMetadataPresent || !legacyNetworkPresent {
		return report, false, fmt.Errorf("%w: incomplete legacy state", errLegacyStateConflict)
	}

	var meta stateMeta
	if err := json.Unmarshal(legacyMeta.Get([]byte(cliMetaKey)), &meta); err != nil {
		return report, false, fmt.Errorf("decode legacy %s: %w", cliMetaKey, err)
	}
	legacy := &stateFile{
		ManagedZone:       meta.ManagedZone,
		IdentityKeyPath:   meta.IdentityKeyPath,
		RootPrivateKey:    meta.RootPrivateKey,
		ZonePrivateKey:    meta.ZonePrivateKey,
		Network:           legacyNetwork,
		SyncPeers:         meta.SyncPeers,
		IPsecTransportKey: meta.IPsecTransportKey,
		EndpointACLs:      meta.EndpointACLs,
	}
	candidate, gossipReport, err := projectLegacyCommonState(legacy, trustedRoot)
	if err != nil {
		return report, false, err
	}
	report.Gossip = gossipReport
	if _, err := corestate.CommitBoltState(tx, candidate, corestate.ChangeSet{}); err != nil {
		return report, false, err
	}
	if _, err := photonlinux.SaveLinuxStateTx(tx, linuxStateFromLegacy(legacy)); err != nil {
		return report, false, err
	}
	if _, err := zone.DeleteNetworkTx(tx); err != nil {
		return report, false, err
	}
	if err := legacyMeta.Delete([]byte(cliMetaKey)); err != nil {
		return report, false, err
	}
	return report, true, nil
}

func linuxStateFromLegacy(state *stateFile) *photonlinux.LinuxState {
	if state == nil {
		return &photonlinux.LinuxState{}
	}
	return &photonlinux.LinuxState{
		IPsecTransportKey: state.IPsecTransportKey,
		EndpointACLs:      state.EndpointACLs,
	}
}
