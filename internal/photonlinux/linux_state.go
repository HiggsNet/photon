package photonlinux

import (
	"maps"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// LinuxState contains only Linux-local controller and configuration state.
// Verified network facts and gossip restart hints are owned by pkg/core/state.
type LinuxState struct {
	IPsecTransportKey    *photonstate.IPsecTransportKeyState `json:"ipsec_transport_key,omitempty"`
	EndpointACLs         map[string]photonstate.EndpointACL  `json:"endpoint_acls,omitempty"`
	SuspendedTunnelPeers map[zone.ZonePath]bool              `json:"suspended_tunnel_peers,omitempty"`
}

// CloneLinuxState returns a detached persistent-state candidate suitable for
// plan/commit without publishing mutations into the live owner.
func CloneLinuxState(state *LinuxState) *LinuxState {
	if state == nil {
		return &LinuxState{}
	}
	return &LinuxState{
		IPsecTransportKey:    photonstate.CloneIPsecTransportKeyState(state.IPsecTransportKey),
		EndpointACLs:         photonstate.CloneEndpointACLs(state.EndpointACLs),
		SuspendedTunnelPeers: maps.Clone(state.SuspendedTunnelPeers),
	}
}
