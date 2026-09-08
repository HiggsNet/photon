package ipsec

import "github.com/HiggsNet/photon/pkg/core/zone"

// Compatibility helpers keep focused tests on the lower-level implementations
// without retaining these convenience APIs in production builds.
func NewTransportLinkSpec(local, peer zone.ZonePath, overlayID, transportID string, records *NodeRecords, contacts []ContactPoint) (TransportLinkSpec, error) {
	return NewTransportLinkSpecWithOptions(local, peer, overlayID, records, contacts, TransportLinkOptions{TransportID: transportID})
}

func NewTransportLinkSpecForGroup(local, peer zone.ZonePath, group LinkGroupSpec, records *NodeRecords, contacts []ContactPoint, linkIndex int) (TransportLinkSpec, error) {
	if err := group.Validate(); err != nil {
		return TransportLinkSpec{}, err
	}
	group = group.Normalized()
	pathKey := DefaultPathKey
	linkID := StableLinkID(local, peer, group.ID, pathKey)
	localAddr, peerAddr, err := group.DeriveTunnelAddressesForLink(local, peer, linkID, pathKey, 0, linkIndex)
	if err != nil {
		return TransportLinkSpec{}, err
	}
	if group.normalizedTunnelAddress().Mode == TunnelAddressSequentialPool && peer < local {
		localAddr, peerAddr = peerAddr, localAddr
	}
	return NewTransportLinkSpecWithOptions(local, peer, group.ID, records, contacts, TransportLinkOptions{
		LinkID: linkID, PathKey: pathKey, Provider: group.Provider, PathMode: group.DefaultPathMode,
		NetNS: group.NetNS.Target(), LocalTunnelAddr: localAddr, PeerTunnelAddr: peerAddr,
	})
}

func rotateSpecForRole(base TransportLinkSpec, generation uint64, role string) TransportLinkSpec {
	base.InitiatorRole = role
	return mustRuntimeSpecForPortGeneration(base, generation)
}

func RotateChildSAName(transportID string, generation uint64) string {
	return RotateConnectionName(transportID, generation) + "-child"
}

func NewReconnectingVICIClient(factory VICIClientFactory) (*ReconnectingVICIClient, error) {
	client, closeFn, err := factory()
	if err != nil {
		return nil, err
	}
	return &ReconnectingVICIClient{factory: factory, client: client, closeFn: closeFn}, nil
}
