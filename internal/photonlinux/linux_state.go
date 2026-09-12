package photonlinux

import photonstate "github.com/HiggsNet/photon/internal/state"

// LinuxState contains only Linux-local controller and configuration state.
// Verified network facts and gossip restart hints are owned by pkg/core/state.
type LinuxState struct {
	IPsecTransportKey *photonstate.IPsecTransportKeyState `json:"ipsec_transport_key,omitempty"`
	EndpointACLs      map[string]photonstate.EndpointACL  `json:"endpoint_acls,omitempty"`
}

// CloneLinuxState returns a detached persistent-state candidate suitable for
// plan/commit without publishing mutations into the live owner.
func CloneLinuxState(state *LinuxState) *LinuxState {
	if state == nil {
		return &LinuxState{}
	}
	return &LinuxState{
		IPsecTransportKey: photonstate.CloneIPsecTransportKeyState(state.IPsecTransportKey),
		EndpointACLs:      photonstate.CloneEndpointACLs(state.EndpointACLs),
	}
}
