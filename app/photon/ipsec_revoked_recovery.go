package main

import (
	"cmp"
	"slices"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// Revoked peers are absent from Desired. After restart their instances must
// still be reconstructed for teardown, never for admission or new connections.
// Require the same deterministic connection identity and XFRM ownership checks
// as normal recovery; a Photon-looking name alone is insufficient.
func recoverRevokedIPsecInstances(verified *corestate.VerifiedState, groups []ipsec.LinkGroupSpec, connections []ipsec.ConnectionState, sas []ipsec.SAState, links []ipsec.XFRMLinkState, instances map[string]ipsec.LinkInstance, now time.Time) error {
	peers := make(map[zone.ZonePath]bool)
	for _, conn := range connections {
		if conn.LocalIdentity == string(verified.ManagedZone) {
			peers[zone.ZonePath(conn.RemoteIdentity)] = true
		}
	}
	for _, sa := range sas {
		if sa.LocalIdentity == string(verified.ManagedZone) {
			peers[zone.ZonePath(sa.RemoteIdentity)] = true
		}
	}
	for peer := range peers {
		if !peer.Valid() || !verified.Network.IsZoneRevoked(peer, now) {
			continue
		}
		// Either side may own the inbound port generation. Expired previous
		// entries remain useful ownership hints for cleanup only.
		generations := []uint64{0}
		for _, node := range []zone.ZonePath{verified.ManagedZone, peer} {
			if state := verified.Network.Zones[node]; state != nil {
				if record := state.Records[ipsec.RecordKeyPorts]; record != nil {
					if ports, err := ipsec.ParsePortRecord(record); err == nil {
						if ports.Current != nil {
							generations = append(generations, ports.Current.Generation)
						}
						for _, previous := range ports.Previous {
							generations = append(generations, previous.Generation)
						}
					}
				}
			}
		}
		slices.SortFunc(generations, func(a, b uint64) int { return cmp.Compare(b, a) })
		generations = slices.Compact(generations)
		for _, group := range groups {
			group = group.Normalized()
			for _, path := range []string{ipsec.DefaultPathKey, "family:" + ipsec.FamilyIPv4, "family:" + ipsec.FamilyIPv6} {
				base := ipsec.TransportLinkSpec{LocalZone: verified.ManagedZone, PeerZone: peer, OverlayID: group.ID, Provider: group.Provider, PathKey: path, LinkID: ipsec.StableLinkID(verified.ManagedZone, peer, group.ID, path), Generation: generations[0]}
				if _, exists := instances[base.LinkID]; exists {
					continue
				}
				var ownedSAs []ipsec.SAState
				for _, generation := range generations {
					candidate, err := ipsec.RuntimeSpecForPortGeneration(base, group, generation)
					if err != nil {
						return err
					}
					for _, sa := range sas {
						if sa.Name == candidate.TransportID && sa.XFRMIfID == candidate.XFRMIfID {
							ownedSAs = append(ownedSAs, sa)
						}
					}
				}
				instance, found, err := ipsec.RecoverObservedLinkInstance(base, group, generations, connections, ownedSAs, links, now)
				if err != nil {
					return err
				}
				if found {
					// If the largest generation belonged to the other side's
					// port record, anchor rotation recovery to the observed one.
					if instance.StagedIKEName == "" && instance.RemoteGeneration != base.Generation {
						base.Generation = instance.RemoteGeneration
						instance, _, err = ipsec.RecoverObservedLinkInstance(base, group, generations, connections, ownedSAs, links, now)
						if err != nil {
							return err
						}
					}
					instances[instance.ID] = instance
				}
			}
		}
	}
	return nil
}
