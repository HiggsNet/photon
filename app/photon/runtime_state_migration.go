package main

import (
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	bolt "go.etcd.io/bbolt"
)

const cliMetaKey = "cli_state"

// stateMeta decodes the retired _meta/cli_state payload during one-way migration.
type stateMeta struct {
	ManagedZone       zone.ZonePath                                 `json:"managed_zone"`
	RootPrivateKey    ed25519.PrivateKey                            `json:"root_private_key"`
	ZonePrivateKey    ed25519.PrivateKey                            `json:"zone_private_key"`
	SyncPeers         map[string]legacyPeerState                    `json:"sync_peers,omitempty"`
	PeerCleanups      map[string]photonlinux.LegacyPeerCleanupState `json:"peer_cleanups,omitempty"`
	IPsecTransportKey *photonstate.IPsecTransportKeyState           `json:"ipsec_transport_key,omitempty"`
	EndpointACLs      map[string]photonstate.EndpointACL            `json:"endpoint_acls,omitempty"`
}

// legacyPeerState decodes only restart hints retained from the old aggregate.
type legacyPeerState struct {
	LastSyncUnix            int64                                     `json:"last_sync_unix,omitempty"`
	LastAttemptUnix         int64                                     `json:"last_attempt_unix,omitempty"`
	BackoffUntilUnix        int64                                     `json:"backoff_until_unix,omitempty"`
	LastRelayUnix           int64                                     `json:"last_relay_unix,omitempty"`
	LastRelayCatalogRootHex string                                    `json:"last_relay_catalog_root_hex,omitempty"`
	FailureCount            int                                       `json:"failure_count,omitempty"`
	LastError               string                                    `json:"last_error,omitempty"`
	DiscoveredAddr          string                                    `json:"discovered_addr,omitempty"`
	DiscoveredAtUnix        int64                                     `json:"discovered_at_unix,omitempty"`
	ObservedAddr            string                                    `json:"observed_addr,omitempty"`
	ObservedFirstSeenUnix   int64                                     `json:"observed_first_seen_unix,omitempty"`
	ObservedLastSeenUnix    int64                                     `json:"observed_last_seen_unix,omitempty"`
	ObservedLastSyncUnix    int64                                     `json:"observed_last_sync_unix,omitempty"`
	ObservedUntilUnix       int64                                     `json:"observed_until_unix,omitempty"`
	ObservedFailureCount    int                                       `json:"observed_failure_count,omitempty"`
	ObservedGraceAddrs      []photonstate.PeerObservedGraceAddrState  `json:"observed_grace_addrs,omitempty"`
	RejectedDigests         map[string]photonstate.PeerRejectedDigest `json:"rejected_digests,omitempty"`
}

var (
	bucketLegacyMeta = []byte("_meta")

	errLegacyStateConflict = errors.New("legacy and common state representations coexist")
)

type legacyStateMigrationReport struct {
	Gossip legacyGossipCheckpointReport
}

// migrateLegacyLinuxStateTx atomically handles both supported one-way upgrades:
// it moves a retired cleanup marker from an already partitioned Linux payload
// into GossipCheckpoint, or replaces the older _meta/cli_state plus zone:*
// representation with the common and Linux buckets. The caller owns tx and
// decides commit/rollback.
func migrateLegacyLinuxStateTx(tx *bolt.Tx, trustedRoot ed25519.PublicKey) (legacyStateMigrationReport, bool, error) {
	var report legacyStateMigrationReport
	if tx == nil || !tx.Writable() {
		return report, false, errors.New("legacy state migration requires a writable bbolt transaction")
	}
	candidate, revision, loadReport, commonFound, err := corestate.LoadBoltState(tx)
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
		linuxState, peerCleanups, found, err := photonlinux.LoadLinuxStateForMigrationTx(tx)
		if err != nil {
			return report, false, err
		}
		if !found {
			return report, false, fmt.Errorf("%w: runtime bucket is missing", photonlinux.ErrLinuxStateCorrupt)
		}
		if peerCleanups == nil && !loadReport.RootAuthorityRepaired {
			return report, false, nil
		}
		var checkpointChanged bool
		report.Gossip, checkpointChanged = projectLegacyPeerCleanups(candidate.Gossip, peerCleanups, report.Gossip)
		commonChanged := false
		if checkpointChanged || loadReport.RootAuthorityRepaired {
			if loadReport.RootAuthorityRepaired {
				revision++
			}
			commonChanged, err = corestate.CommitBoltState(tx, candidate, corestate.ChangeSet{
				VerifiedRevision:        revision,
				GossipCheckpointChanged: checkpointChanged,
				NetworkChanged:          loadReport.RootAuthorityRepaired,
				SecurityPriority:        loadReport.RootAuthorityRepaired,
			})
			if err != nil {
				return report, false, err
			}
		}
		linuxChanged, err := photonlinux.SaveLinuxStateTx(tx, linuxState)
		return report, commonChanged || linuxChanged, err
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
	candidate, gossipReport, err := projectLegacyCommonState(&meta, legacyNetwork, trustedRoot)
	if err != nil {
		return report, false, err
	}
	report.Gossip = gossipReport
	if _, err := corestate.CommitBoltState(tx, candidate, corestate.ChangeSet{}); err != nil {
		return report, false, err
	}
	if _, err := photonlinux.SaveLinuxStateTx(tx, &photonlinux.LinuxState{
		IPsecTransportKey: meta.IPsecTransportKey,
		EndpointACLs:      meta.EndpointACLs,
	}); err != nil {
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
