package photonlinux

import photonstate "github.com/HiggsNet/photon/internal/state"

// RuntimeState contains only Linux-local controller and configuration state.
// Verified network facts and gossip restart hints are owned by pkg/core/state.
type RuntimeState struct {
	PeerCleanups      map[string]photonstate.PeerLifecycleCleanupState `json:"peer_cleanups,omitempty"`
	IPsecTransportKey *photonstate.IPsecTransportKeyState              `json:"ipsec_transport_key,omitempty"`
	EndpointACLs      map[string]photonstate.EndpointACL               `json:"endpoint_acls,omitempty"`
}

// CloneRuntimeState returns a detached persistent-state candidate suitable for
// plan/commit without publishing mutations into the live owner.
func CloneRuntimeState(runtime *RuntimeState) *RuntimeState {
	if runtime == nil {
		return &RuntimeState{}
	}
	return &RuntimeState{
		PeerCleanups:      photonstate.ClonePeerLifecycleCleanups(runtime.PeerCleanups),
		IPsecTransportKey: photonstate.CloneIPsecTransportKeyState(runtime.IPsecTransportKey),
		EndpointACLs:      photonstate.CloneEndpointACLs(runtime.EndpointACLs),
	}
}
