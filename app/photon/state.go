package main

import (
	"crypto/ed25519"
	"encoding/hex"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

const cliMetaKey = "cli_state"

type stateFile struct {
	ManagedZone       zone.ZonePath      `json:"managed_zone"`
	IdentityKeyPath   string             `json:"identity_key_path,omitempty"`
	RootPrivateKey    ed25519.PrivateKey `json:"root_private_key"`
	ZonePrivateKey    ed25519.PrivateKey `json:"zone_private_key"`
	Network           *zone.NetworkState `json:"network"`
	SyncPeers         map[string]syncPeerState
	PeerCleanups      map[string]peerLifecycleCleanupState
	IPsecTransportKey *ipsecTransportKeyState
	LinkInstances     map[string]linkInstanceState
	IPsecReconcile    *ipsecReconcileState
	RoutingReconcile  *routingReconcileState
	FirewallReconcile *firewallReconcileState
	EndpointACLs      map[string]endpointACL
	BirdInstances     map[string]*BirdInstanceState
}

type stateMeta struct {
	ManagedZone       zone.ZonePath                        `json:"managed_zone"`
	IdentityKeyPath   string                               `json:"identity_key_path,omitempty"`
	RootPrivateKey    ed25519.PrivateKey                   `json:"root_private_key"`
	ZonePrivateKey    ed25519.PrivateKey                   `json:"zone_private_key"`
	SyncPeers         map[string]syncPeerState             `json:"sync_peers,omitempty"`
	PeerCleanups      map[string]peerLifecycleCleanupState `json:"peer_cleanups,omitempty"`
	IPsecTransportKey *ipsecTransportKeyState              `json:"ipsec_transport_key,omitempty"`
	LinkInstances     map[string]linkInstanceState         `json:"link_instances,omitempty"`
	IPsecReconcile    *ipsecReconcileState                 `json:"ipsec_reconcile,omitempty"`
	RoutingReconcile  *routingReconcileState               `json:"routing_reconcile,omitempty"`
	FirewallReconcile *firewallReconcileState              `json:"firewall_reconcile,omitempty"`
	EndpointACLs      map[string]endpointACL               `json:"endpoint_acls,omitempty"`
	BirdInstances     map[string]*BirdInstanceState        `json:"bird_instances,omitempty"`
}

type firewallReconcileState = photonstate.FirewallReconcileState
type firewallInstanceReconcileStateEntry = photonstate.FirewallReconcileInstance
type endpointACL = photonstate.EndpointACL

type BirdInstanceState = photonstate.BirdInstanceState

type routingReconcileState = photonstate.RoutingReconcileState

type ipsecTransportKeyState = photonstate.IPsecTransportKeyState

type linkInstanceState = photonstate.LinkInstanceState
type linkOwnerState = photonstate.LinkOwnerState

type ipsecReconcileState = photonstate.IPsecReconcileState
type desiredLinkState = photonstate.DesiredLinkState
type linkSAState = photonstate.LinkSAState
type linkActionState = photonstate.LinkActionState
type linkSkipState = photonstate.LinkSkipState

type syncPeerState = photonstate.PeerRuntimeState
type observedGraceAddrState = photonstate.PeerObservedGraceAddrState
type rejectedDigestState = photonstate.PeerRejectedDigest

type peerLifecycleCleanupState = photonstate.PeerLifecycleCleanupState
type linuxRuntimeState = photonlinux.RuntimeState

type gossipStartupConfig struct {
	PeerID          string           `json:"peer_id"`
	ListenAddr      string           `json:"listen_addr"`
	Bootstrap       []syncConfigPeer `json:"bootstrap"`
	MaxMessageBytes int              `json:"max_message_bytes"`
	MaxSyncZones    int              `json:"max_sync_zones"`
	MaxSyncRecords  int              `json:"max_sync_records"`
}

type syncConfigPeer struct {
	ID   string `json:"id" yaml:"id"`
	Addr string `json:"addr" yaml:"addr"`
}

type AppContext struct {
	Config         *appConfig
	StatePath      string
	Clock          func() time.Time
	DisableControl bool
}

func NewAppContext() (*AppContext, error) {
	config, err := loadAppConfig()
	if err != nil {
		return nil, err
	}
	path := config.StatePath
	if override := statePathOverride(); override != "" {
		path = override
	}
	return &AppContext{
		Config:    config,
		StatePath: path,
		Clock:     time.Now,
	}, nil
}

func (rt *AppContext) Now() time.Time {
	if rt != nil && rt.Clock != nil {
		return rt.Clock()
	}
	return time.Now()
}

func equalPublicKey(a, b ed25519.PublicKey) bool {
	if len(a) != len(b) {
		return false
	}
	var out byte
	for i := range a {
		out |= a[i] ^ b[i]
	}
	return out == 0
}

func configureValidation(ns *zone.NetworkState) {
	ns.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
}

func normalizeState(ns *zone.NetworkState) {
	if ns.Zones == nil {
		ns.Zones = make(map[zone.ZonePath]*zone.ZoneState)
	}
	for path, zs := range ns.Zones {
		if zs.Path == "" {
			zs.Path = path
		}
		if zs.Delegations == nil {
			zs.Delegations = make(map[zone.ZonePath]*zone.Delegation)
		}
		if zs.Revocations == nil {
			zs.Revocations = make(map[zone.ZonePath]*zone.DelegationRevocation)
		}
		if zs.Records == nil {
			zs.Records = make(map[string]*zone.Record)
		}
		if zs.RecordHistory == nil {
			zs.RecordHistory = make(map[string][]*zone.Record)
		}
	}
}

func defaultPeerID(verified *corestate.VerifiedState) string {
	if verified == nil {
		return "local"
	}
	if verified.ManagedZone != "" && verified.ManagedZone != zone.RootZone {
		return string(verified.ManagedZone)
	}
	if len(verified.IdentityPrivateKey) == 0 {
		return "local"
	}
	pub := verified.IdentityPrivateKey.Public().(ed25519.PublicKey)
	return hex.EncodeToString(photoncrypto.KeyID(pub))[:16]
}

func timeNow() time.Time {
	return time.Now()
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}
