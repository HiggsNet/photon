package ipsec

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestContactFallbackCrossesSourcesAndPriorities(t *testing.T) {
	now := time.Unix(5000, 0)
	points := []ContactPoint{
		{AddressID: "manual", Address: "192.0.2.1", Family: FamilyIPv4, Source: SourceManualAddress, Priority: 300, Current: true},
		{AddressID: "dns", Address: "192.0.2.2", Family: FamilyIPv4, Source: SourceManualDNS, Priority: 200, Current: true},
		{AddressID: "interface", Address: "192.0.2.3", Family: FamilyIPv4, Source: SourceDiscovery, Priority: 100, Current: true},
		{AddressID: "gossip", Address: "192.0.2.4", Family: FamilyIPv4, Source: SourceManualAddress, Priority: 99999, Fallback: true, Current: true},
	}
	for index, want := range []string{"manual", "dns", "interface", "gossip"} {
		selected := SelectContactPointsWithOptions(points, PathModeFamilyRedundant, AddressCandidateOptions{Now: now})
		if len(selected) != 1 || selected[0].AddressID != want {
			t.Fatalf("step %d selected %+v, want %s", index, selected, want)
		}
		points[index].BackoffUntil = now.Add(time.Minute)
	}
	// Recovery permits a high-priority retry, but cannot displace an observed
	// established endpoint merely because its hold-down expired.
	selected := SelectContactPointsWithOptions(points, PathModeFamilyRedundant, AddressCandidateOptions{Now: now.Add(2 * time.Minute), EstablishedContacts: map[string]bool{points[2].Key(): true}})
	if selected[0].AddressID != "interface" {
		t.Fatal("working contact displaced", selected)
	}
	// Explicit source policy still limits/order choices, with backoff ahead of it.
	points[1].BackoffUntil = time.Time{}
	selected = SelectContactPointsWithOptions(points, PathModeFamilyRedundant, AddressCandidateOptions{Now: now, SourceOrder: []string{SourceManualAddress, SourceManualDNS}})
	if selected[0].AddressID != "dns" {
		t.Fatal("source order prevented fallback", selected)
	}
}

func TestContactExplicitKindsHaveEqualDefaultRank(t *testing.T) {
	for _, source := range []string{SourceManualAddress, SourceManualDNS, SourceDiscovery} {
		points := []ContactPoint{
			{AddressID: "selected", Address: "192.0.2.2", Family: FamilyIPv4, Source: source, Priority: 200},
			{AddressID: "other", Address: "192.0.2.1", Family: FamilyIPv4, Source: SourceManualAddress, Priority: 100},
		}
		if selected := SelectContactPointsWithOptions(points, PathModeFamilyRedundant, AddressCandidateOptions{}); selected[0].AddressID != "selected" {
			t.Fatalf("source %s lost despite priority: %+v", source, selected)
		}
	}
}

func TestContactDNSFailureDoesNotDiscardOtherSources(t *testing.T) {
	addresses := &AddressRecord{Version: 1, Addresses: []AddressAdvertisement{
		{ID: "dns", Source: SourceManualDNS, Host: "missing.example", Families: []string{FamilyIPv4}, Priority: 300},
		{ID: "interface", Source: SourceDiscovery, Address: "192.0.2.1", Family: FamilyIPv4, Priority: 100},
	}}
	points, err := ResolveAddressCandidates(context.Background(), addresses, time.Unix(5000, 0), AddressCandidateOptions{DNSResolver: &sequenceDNSResolver{results: []dnsLookupResult{{err: fmt.Errorf("DNS unavailable")}}}})
	if err != nil || len(points) != 1 || points[0].ID != "interface" {
		t.Fatalf("DNS blocked fallback: %+v %v", points, err)
	}
	addresses.Addresses = addresses.Addresses[:1]
	if _, err := ResolveAddressCandidates(context.Background(), addresses, time.Unix(5000, 0), AddressCandidateOptions{DNSResolver: &sequenceDNSResolver{results: []dnsLookupResult{{err: fmt.Errorf("DNS unavailable")}}}}); err == nil {
		t.Fatal("all-failed DNS diagnostic lost")
	}
}

func TestPlannerRetainsOnlyAllowedEstablishedCurrentContact(t *testing.T) {
	now := time.Unix(5000, 0)
	ns := zone.NewNetworkState()
	local, peer := zone.ZonePath("a.example."), zone.ZonePath("b.example.")
	addIPsecNode(t, ns, local, RoleOut, nil, now)
	addresses := []AddressAdvertisement{
		{ID: "manual", Source: SourceManualAddress, Address: "192.0.2.1", Family: FamilyIPv4, Priority: 300},
		{ID: "interface", Source: SourceDiscovery, Address: "192.0.2.2", Family: FamilyIPv4, Priority: 100},
	}
	addIPsecNode(t, ns, peer, RoleIn, addresses, now)
	groups := []LinkGroupSpec{{ID: "ipsec-main"}}
	key := ContactPoint{AddressID: "manual", Address: "192.0.2.1", Generation: 1, IKEPort: 500, NATTPort: 4500}.Key()
	plan, err := PlanTransportLinks(context.Background(), ns, local, groups, LinkPlannerOptions{Now: now, ContactPointQuality: map[zone.ZonePath]map[string]ContactPointQuality{peer: {key: {BackoffUntil: now.Add(time.Minute)}}}})
	if err != nil || len(plan.Desired) != 1 {
		t.Fatalf("initial plan: %+v %v", plan, err)
	}
	spec := plan.Desired[0]
	if spec.ContactPoints[0].AddressID != "interface" {
		t.Fatal("did not fall back", spec)
	}
	sa := SAState{Name: spec.TransportID, XFRMIfID: spec.XFRMIfID, LocalIdentity: string(local), RemoteIdentity: string(peer), RemoteEndpoint: fmt.Sprintf("%s:4500", spec.ContactPoints[0].Address), Established: true}
	plan, err = PlanTransportLinks(context.Background(), ns, local, groups, LinkPlannerOptions{Now: now.Add(2 * time.Minute), EstablishedSAs: []SAState{sa}})
	if err != nil || len(plan.Desired) != 1 || plan.Desired[0].ContactPoints[0].AddressID != "interface" {
		t.Fatalf("healthy contact displaced: %+v %v", plan, err)
	}
	groups[0].AddressSourceOrder = []string{SourceManualAddress}
	plan, err = PlanTransportLinks(context.Background(), ns, local, groups, LinkPlannerOptions{Now: now.Add(2 * time.Minute), EstablishedSAs: []SAState{sa}})
	if err != nil || len(plan.Desired) != 1 || plan.Desired[0].ContactPoints[0].AddressID != "manual" {
		t.Fatalf("excluded established contact retained: %+v %v", plan, err)
	}
}
