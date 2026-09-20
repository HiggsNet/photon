package main

import (
	"crypto/ed25519"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"

	"github.com/HiggsNet/photon/pkg/core/zone"
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
