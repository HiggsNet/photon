package state

import (
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// IPsecTransportKeyState stores the local node's IPsec transport key.
type IPsecTransportKeyState struct {
	Kind        string `json:"kind,omitempty"`
	Algorithm   string `json:"algorithm,omitempty"`
	PublicKey   []byte `json:"public_key,omitempty"`
	PrivateKey  []byte `json:"private_key,omitempty"`
	Fingerprint string `json:"fingerprint,omitempty"`
	NotBefore   int64  `json:"not_before,omitempty"`
	NotAfter    int64  `json:"not_after,omitempty"`
	UpdatedAt   int64  `json:"updated_at,omitempty"`
}

// DesiredLinkObservation is the secret-free projection of a planned IPsec link.
type DesiredLinkObservation struct {
	InstanceID      string        `json:"instance_id,omitempty"`
	GroupID         string        `json:"group_id,omitempty"`
	PeerZone        zone.ZonePath `json:"peer_zone,omitempty"`
	LinkID          string        `json:"link_id,omitempty"`
	PathKey         string        `json:"path_key,omitempty"`
	TransportID     string        `json:"transport_id,omitempty"`
	DesiredSpecHash string        `json:"desired_spec_hash,omitempty"`
	InterfaceName   string        `json:"interface_name,omitempty"`
	XFRMIfID        uint32        `json:"xfrm_if_id,omitempty"`
	Endpoint        string        `json:"endpoint,omitempty"`
	LocalTunnelAddr string        `json:"local_tunnel_addr,omitempty"`
	PeerTunnelAddr  string        `json:"peer_tunnel_addr,omitempty"`
}

// LinkSAObservation is the secret-free projection of a StrongSwan SA.
type LinkSAObservation struct {
	Name            string `json:"name,omitempty"`
	UniqueID        uint64 `json:"unique_id,omitempty"`
	Initiator       bool   `json:"initiator,omitempty"`
	InitiatorKnown  bool   `json:"initiator_known,omitempty"`
	IKEAgeSeconds   uint64 `json:"ike_age_seconds,omitempty"`
	ChildAgeSeconds uint64 `json:"child_age_seconds,omitempty"`
	InboundBytes    uint64 `json:"inbound_bytes,omitempty"`
	InboundPackets  uint64 `json:"inbound_packets,omitempty"`
	InboundIdleSecs uint64 `json:"inbound_idle_seconds,omitempty"`
	InboundKnown    bool   `json:"inbound_activity_known,omitempty"`
	Peer            string `json:"peer,omitempty"`
	ChildSA         string `json:"child_sa,omitempty"`
	IKEState        string `json:"ike_state,omitempty"`
	ChildState      string `json:"child_state,omitempty"`
	XFRMIfID        uint32 `json:"xfrm_if_id,omitempty"`
	ReqID           uint32 `json:"reqid,omitempty"`
	LocalIdentity   string `json:"local_identity,omitempty"`
	RemoteIdentity  string `json:"remote_identity,omitempty"`
	LocalEndpoint   string `json:"local_endpoint,omitempty"`
	RemoteEndpoint  string `json:"remote_endpoint,omitempty"`
	Endpoint        string `json:"endpoint,omitempty"`
	Established     bool   `json:"established,omitempty"`
}

// LinkActionObservation is the secret-free projection of a reconcile action.
type LinkActionObservation struct {
	Action     string        `json:"action"`
	InstanceID string        `json:"instance_id,omitempty"`
	GroupID    string        `json:"group_id,omitempty"`
	PeerZone   zone.ZonePath `json:"peer_zone,omitempty"`
	Reason     string        `json:"reason,omitempty"`
	SAUniqueID uint64        `json:"sa_unique_id,omitempty"`
}

// LinkSkipObservation records a peer skipped by reconcile.
type LinkSkipObservation struct {
	GroupID string        `json:"group_id,omitempty"`
	Peer    zone.ZonePath `json:"peer,omitempty"`
	Reason  string        `json:"reason,omitempty"`
	Detail  string        `json:"detail,omitempty"`
}
