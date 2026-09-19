package photonlinux

import (
	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// ProjectIPsecDesired strips transport secrets and mutable spec references.
func ProjectIPsecDesired(desired []ipsec.TransportLinkSpec) []photonstate.DesiredLinkObservation {
	var out []photonstate.DesiredLinkObservation
	for _, spec := range desired {
		endpoint := ""
		if len(spec.ContactPoints) > 0 {
			endpoint = spec.ContactPoints[0].Address
			if endpoint == "" {
				endpoint = spec.ContactPoints[0].Host
			}
		}
		out = append(out, photonstate.DesiredLinkObservation{
			InstanceID:      ipsec.LinkInstanceID(spec),
			GroupID:         spec.OverlayID,
			PeerZone:        spec.PeerZone,
			LinkID:          spec.LinkID,
			PathKey:         spec.PathKey,
			TransportID:     spec.TransportID,
			DesiredSpecHash: ipsec.TransportLinkSpecHash(spec),
			InterfaceName:   spec.InterfaceName,
			XFRMIfID:        spec.XFRMIfID,
			Endpoint:        endpoint,
			LocalTunnelAddr: ipsec.FormatScopedTunnelAddress(spec.LocalTunnelAddr, spec.InterfaceName, spec.NetNS),
			PeerTunnelAddr:  ipsec.FormatScopedTunnelAddress(spec.PeerTunnelAddr, spec.InterfaceName, spec.NetNS),
		})
	}
	return out
}

// ProjectIPsecActions retains only public action identity and outcome metadata.
func ProjectIPsecActions(actions []ipsec.ReconcileAction) []photonstate.LinkActionObservation {
	var out []photonstate.LinkActionObservation
	for _, action := range actions {
		item := photonstate.LinkActionObservation{Action: action.Action, Reason: action.Reason, SAUniqueID: action.SAUniqueID}
		if action.Instance != nil {
			item.InstanceID = action.Instance.ID
			item.GroupID = action.Instance.GroupID
			item.PeerZone = action.Instance.PeerZone
		}
		if action.Spec != nil {
			item.InstanceID = ipsec.LinkInstanceID(*action.Spec)
			item.GroupID = action.Spec.OverlayID
			item.PeerZone = action.Spec.PeerZone
		}
		out = append(out, item)
	}
	return out
}

// ProjectIPsecSAs copies current SA counters and status into the public observation model.
func ProjectIPsecSAs(sas []ipsec.SAState) []photonstate.LinkSAObservation {
	out := make([]photonstate.LinkSAObservation, 0, len(sas))
	for _, sa := range sas {
		out = append(out, photonstate.LinkSAObservation{
			Name:            sa.Name,
			UniqueID:        sa.UniqueID,
			Initiator:       sa.Initiator,
			InitiatorKnown:  sa.InitiatorKnown,
			IKEAgeSeconds:   sa.IKEAgeSeconds,
			ChildAgeSeconds: sa.ChildAgeSeconds,
			InboundBytes:    sa.InboundBytes,
			InboundPackets:  sa.InboundPackets,
			InboundIdleSecs: sa.InboundIdleSecs,
			InboundKnown:    sa.InboundKnown,
			Peer:            sa.Peer,
			ChildSA:         sa.ChildSA,
			IKEState:        sa.IKEState,
			ChildState:      sa.ChildState,
			XFRMIfID:        sa.XFRMIfID,
			ReqID:           sa.ReqID,
			LocalIdentity:   sa.LocalIdentity,
			RemoteIdentity:  sa.RemoteIdentity,
			LocalEndpoint:   sa.LocalEndpoint,
			RemoteEndpoint:  sa.RemoteEndpoint,
			Endpoint:        sa.Endpoint,
			Established:     sa.Established,
		})
	}
	return out
}
