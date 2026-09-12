package main

import (
	"crypto/ed25519"

	photonstate "github.com/HiggsNet/photon/internal/state"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const cliMetaKey = "cli_state"

// stateFile and stateMeta describe only the retired aggregate schema. Current
// runtime code must use State, Common and photonlinux.LinuxState instead.
type stateFile struct {
	ManagedZone       zone.ZonePath      `json:"managed_zone"`
	IdentityKeyPath   string             `json:"identity_key_path,omitempty"`
	RootPrivateKey    ed25519.PrivateKey `json:"root_private_key"`
	ZonePrivateKey    ed25519.PrivateKey `json:"zone_private_key"`
	Network           *zone.NetworkState `json:"network"`
	SyncPeers         map[string]photonstate.PeerRuntimeState
	IPsecTransportKey *photonstate.IPsecTransportKeyState
	EndpointACLs      map[string]photonstate.EndpointACL
}

type stateMeta struct {
	ManagedZone       zone.ZonePath                           `json:"managed_zone"`
	IdentityKeyPath   string                                  `json:"identity_key_path,omitempty"`
	RootPrivateKey    ed25519.PrivateKey                      `json:"root_private_key"`
	ZonePrivateKey    ed25519.PrivateKey                      `json:"zone_private_key"`
	SyncPeers         map[string]photonstate.PeerRuntimeState `json:"sync_peers,omitempty"`
	IPsecTransportKey *photonstate.IPsecTransportKeyState     `json:"ipsec_transport_key,omitempty"`
	EndpointACLs      map[string]photonstate.EndpointACL      `json:"endpoint_acls,omitempty"`
}
