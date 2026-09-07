package photonlinux

import photonstate "github.com/HiggsNet/photon/internal/state"

// RuntimeState contains only Linux-local controller and configuration state.
// Verified network facts and gossip restart hints are owned by pkg/core/state.
type RuntimeState struct {
	PeerCleanups      map[string]photonstate.PeerLifecycleCleanupState `json:"peer_cleanups,omitempty"`
	IPsecTransportKey *photonstate.IPsecTransportKeyState              `json:"ipsec_transport_key,omitempty"`
	LinkInstances     map[string]photonstate.LinkInstanceState         `json:"link_instances,omitempty"`
	IPsecReconcile    *photonstate.IPsecReconcileState                 `json:"ipsec_reconcile,omitempty"`
	RoutingReconcile  *photonstate.RoutingReconcileState               `json:"routing_reconcile,omitempty"`
	FirewallReconcile *photonstate.FirewallReconcileState              `json:"firewall_reconcile,omitempty"`
	EndpointACLs      map[string]photonstate.EndpointACL               `json:"endpoint_acls,omitempty"`
	BirdInstances     map[string]*photonstate.BirdInstanceState        `json:"bird_instances,omitempty"`
}

// CloneRuntimeState returns a detached controller candidate suitable for
// observe/plan/commit without publishing mutations into the live owner.
func CloneRuntimeState(runtime *RuntimeState) *RuntimeState {
	if runtime == nil {
		return &RuntimeState{}
	}
	return &RuntimeState{
		PeerCleanups:      photonstate.ClonePeerLifecycleCleanups(runtime.PeerCleanups),
		IPsecTransportKey: photonstate.CloneIPsecTransportKeyState(runtime.IPsecTransportKey),
		LinkInstances:     photonstate.CloneLinkInstances(runtime.LinkInstances),
		IPsecReconcile:    photonstate.CloneIPsecReconcileState(runtime.IPsecReconcile),
		RoutingReconcile:  photonstate.CloneRoutingReconcileState(runtime.RoutingReconcile),
		FirewallReconcile: photonstate.CloneFirewallReconcileState(runtime.FirewallReconcile),
		EndpointACLs:      photonstate.CloneEndpointACLs(runtime.EndpointACLs),
		BirdInstances:     photonstate.CloneBirdInstances(runtime.BirdInstances),
	}
}
