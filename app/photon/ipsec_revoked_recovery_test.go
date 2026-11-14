package main

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestRevokedIPsecRecoveryRequiresOwnedRuntime(t *testing.T) {
	for _, scenario := range []string{"sa", "connection", "rotating", "unrevoked", "wrong_name", "wrong_identity", "wrong_ifid", "wrong_namespace", "missing_interface"} {
		t.Run(scenario, func(t *testing.T) {
			verified, _, _, _ := buildTestRoutingOwners(t)
			now := time.Unix(8000, 0)
			peer := zone.ZonePath("node-b.catofes.")
			delegation := verified.Network.Zones["catofes."].Delegations[peer]
			if scenario != "unrevoked" {
				verified.Network.Zones["catofes."].Revocations[peer] = &zone.DelegationRevocation{ChildZone: peer, ParentZone: "catofes.", RevokedAuthorityEpoch: delegation.AuthorityEpoch, RevokedAuthorityHash: delegation.AuthorityHash, RevokedAt: now.Add(-time.Second).Unix()}
			}
			value, err := json.Marshal(ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed, Current: &ipsec.PortSelection{Generation: 9, IKE: ipsec.PortBinding{Advertised: 500}, NATT: ipsec.PortBinding{Advertised: 4500}}, Previous: []ipsec.PortSelection{{Generation: 7, IKE: ipsec.PortBinding{Advertised: 500}, NATT: ipsec.PortBinding{Advertised: 4500}, ValidUntil: now.Add(-time.Hour).Unix()}}})
			if err != nil {
				t.Fatal(err)
			}
			verified.Network.Zones[peer].Records[ipsec.RecordKeyPorts] = &zone.Record{Zone: peer, Key: ipsec.RecordKeyPorts, Type: ipsec.RecordTypePorts, Value: value}
			group := testIPsecLinkGroup().Normalized()
			base := ipsec.TransportLinkSpec{LocalZone: verified.ManagedZone, PeerZone: peer, OverlayID: group.ID, Provider: group.Provider, PathKey: "family:" + ipsec.FamilyIPv4, LinkID: ipsec.StableLinkID(verified.ManagedZone, peer, group.ID, "family:"+ipsec.FamilyIPv4)}
			var sas []ipsec.SAState
			var connections []ipsec.ConnectionState
			var links []ipsec.XFRMLinkState
			generations := []uint64{9}
			if scenario == "rotating" {
				generations = append(generations, 7)
			}
			for _, generation := range generations {
				spec, err := ipsec.RuntimeSpecForPortGeneration(base, group, generation)
				if err != nil {
					t.Fatal(err)
				}
				sa := ipsec.SAState{Name: spec.TransportID, ChildSA: ipsec.ChildSAName(spec), XFRMIfID: spec.XFRMIfID, LocalIdentity: string(verified.ManagedZone), RemoteIdentity: string(peer), Established: true, RemoteEndpoint: "192.0.2.2:4500"}
				link := ipsec.XFRMLinkState{NetNS: group.NetNS, InterfaceName: spec.InterfaceName, XFRMIfID: spec.XFRMIfID, NamespaceExists: true, InterfaceExists: true}
				if spec.LocalTunnelAddr.IsValid() {
					link.Addresses = []netip.Prefix{netip.PrefixFrom(spec.LocalTunnelAddr, spec.LocalTunnelAddr.BitLen())}
				}
				switch scenario {
				case "wrong_name":
					sa.Name = "foreign"
				case "wrong_identity":
					sa.LocalIdentity = "other.catofes."
				case "wrong_ifid":
					sa.XFRMIfID++
				case "wrong_namespace":
					link.NetNS = ipsec.NetNSSpec{Kind: ipsec.NetNSName, Name: "foreign"}
				case "missing_interface":
					link.InterfaceExists = false
				}
				if scenario == "connection" {
					connections = append(connections, ipsec.ConnectionState{Name: spec.TransportID, LocalIdentity: string(verified.ManagedZone), RemoteIdentity: string(peer)})
				} else {
					sas = append(sas, sa)
				}
				links = append(links, link)
			}
			instances := make(map[string]ipsec.LinkInstance)
			if err := recoverRevokedIPsecInstances(verified, []ipsec.LinkGroupSpec{group}, connections, sas, links, instances, now); err != nil {
				t.Fatal(err)
			}
			want := scenario == "sa" || scenario == "connection" || scenario == "rotating"
			instance, found := instances[base.LinkID]
			if found != want {
				t.Fatalf("recovered=%v, want=%v: %+v", found, want, instances)
			}
			if found {
				if err := instance.Owner.Validate(instance); err != nil {
					t.Fatal(err)
				}
			}
			if scenario == "rotating" && (instance.IKEName == "" || instance.StagedIKEName == "" || instance.IKEName == instance.StagedIKEName) {
				t.Fatal("cleanup lost one of the observed generations")
			}
		})
	}
}
