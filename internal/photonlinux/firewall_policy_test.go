package photonlinux

import (
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestBuildFirewallPolicyInputHostRedirectGracePorts(t *testing.T) {
	verified := &corestate.VerifiedState{ManagedZone: "node-b.catofes."}
	now := time.Unix(6000, 0)
	ports := ipsec.PortRecord{
		Version: 1,
		Mode:    ipsec.PortModeFixed,
		Current: &ipsec.PortSelection{
			Generation: 3,
			IKE:        ipsec.PortBinding{Local: 1500, Advertised: 1500},
			NATT:       ipsec.PortBinding{Local: 14500, Advertised: 14500},
		},
		Previous: []ipsec.PortSelection{
			{
				Generation: 2,
				IKE:        ipsec.PortBinding{Local: 1400, Advertised: 1400},
				NATT:       ipsec.PortBinding{Local: 14400, Advertised: 14400},
				ValidUntil: now.Add(time.Minute).Unix(),
			},
			{
				Generation: 1,
				IKE:        ipsec.PortBinding{Local: 1300, Advertised: 1300},
				NATT:       ipsec.PortBinding{Local: 14300, Advertised: 14300},
				ValidUntil: now.Add(-time.Second).Unix(),
			},
		},
		UpdatedAt: now.Unix(),
	}
	value, err := json.Marshal(ports)
	if err != nil {
		t.Fatal(err)
	}
	verified.Network = &zone.NetworkState{Zones: map[zone.ZonePath]*zone.ZoneState{
		verified.ManagedZone: {Records: map[string]*zone.Record{ipsec.RecordKeyPorts: {Zone: verified.ManagedZone, Key: ipsec.RecordKeyPorts, Value: value, Type: ipsec.RecordTypePorts}}},
	}}
	input := BuildFirewallPolicyInput(
		firewall.FirewallInstanceSpec{ID: "host", IsHost: true},
		&routing.AuthorizedRouteSet{},
		verified,
		nil,
		NetNSConfig{},
		nil,
		now,
	)
	if len(input.AdvertisedCurrentIKEPorts) != 1 || input.AdvertisedCurrentIKEPorts[0] != 1500 {
		t.Fatalf("current IKE ports = %v, want [1500]", input.AdvertisedCurrentIKEPorts)
	}
	if len(input.AdvertisedCurrentNATTPorts) != 1 || input.AdvertisedCurrentNATTPorts[0] != 14500 {
		t.Fatalf("current NAT-T ports = %v, want [14500]", input.AdvertisedCurrentNATTPorts)
	}
	if len(input.AdvertisedPreviousIKEPorts) != 1 || input.AdvertisedPreviousIKEPorts[0] != 1400 {
		t.Fatalf("previous IKE ports = %v, want [1400]", input.AdvertisedPreviousIKEPorts)
	}
	if len(input.AdvertisedPreviousNATTPorts) != 1 || input.AdvertisedPreviousNATTPorts[0] != 14400 {
		t.Fatalf("previous NAT-T ports = %v, want [14400]", input.AdvertisedPreviousNATTPorts)
	}
}

func TestBuildFirewallPolicyInputIncludesLocalSharedAssignment(t *testing.T) {
	prefix := netip.MustParsePrefix("2a0d:2905::/96")
	ars := &routing.AuthorizedRouteSet{
		Assignments: map[netip.Prefix]*routing.AssignmentEntry{
			prefix: {
				Prefix:     prefix,
				AssignedTo: "node-a.catofes.",
				Shared:     true,
			},
		},
		AllAssignments: []*routing.AssignmentEntry{
			{Prefix: prefix, AssignedTo: "node-a.catofes.", Shared: true},
			{Prefix: prefix, AssignedTo: "node-b.catofes.", Shared: true},
		},
	}

	input := BuildFirewallPolicyInput(
		firewall.FirewallInstanceSpec{ID: "photon", NetNS: "photon"},
		ars,
		&corestate.VerifiedState{ManagedZone: "node-b.catofes."},
		nil,
		NetNSConfig{},
		nil,
		time.Now(),
	)

	if len(input.LocalAssigned) != 1 || input.LocalAssigned[0] != prefix {
		t.Fatalf("local assigned = %v, want shared prefix %s", input.LocalAssigned, prefix)
	}
}

func TestBuildFirewallPolicyInputScopesInterfacesByNetNS(t *testing.T) {
	verified := &corestate.VerifiedState{ManagedZone: "node-a.catofes."}
	links := []photonstate.LinkOutput{
		{InterfaceName: "phx11111111", NetNS: "photon", Readiness: photonstate.LinkReadiness{Interface: "ready"}},
		{InterfaceName: "phx22222222", NetNS: "h3", Readiness: photonstate.LinkReadiness{Interface: "ready"}},
	}
	namespaces := NetNSConfig{Names: map[string]ipsec.NetNSSpec{
		"default": {Kind: ipsec.NetNSName, Name: "photon"},
		"photon":  {Kind: ipsec.NetNSName, Name: "photon"},
		"h3":      {Kind: ipsec.NetNSName, Name: "h3"},
	}}
	instances := []RoutingInstance{
		{ID: "photon", NetNS: "photon", Enabled: true, Upstream: &UpstreamConfig{Enabled: true, MeshInterface: "phv2host"}},
		{ID: "h3", NetNS: "h3", Enabled: true, Upstream: &UpstreamConfig{Enabled: true, MeshInterface: "phv3host"}},
	}

	input := BuildFirewallPolicyInput(
		firewall.FirewallInstanceSpec{ID: "photon", NetNS: "default"},
		&routing.AuthorizedRouteSet{},
		verified,
		links,
		namespaces,
		instances,
		time.Now(),
	)
	if len(input.LiveInterfaces) != 1 || input.LiveInterfaces[0] != "phx11111111" {
		t.Fatalf("live interfaces = %v, want photon interface only", input.LiveInterfaces)
	}
	if len(input.UpstreamInterfaces) != 1 || input.UpstreamInterfaces[0] != "phv2host" {
		t.Fatalf("upstream interfaces = %v, want routing-owned photon interface only", input.UpstreamInterfaces)
	}
}
