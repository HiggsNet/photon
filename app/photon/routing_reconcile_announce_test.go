package main

import (
	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/routing"
	"net/netip"
	"testing"
	"time"
)

func TestAutoAnnounceAssignedIPsDisabled(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"10.0.0.0/24"}, nil)
	rt.Config.IPAM.AutoAnnounceAssignedIPs = false

	service := newTestDaemonFromOwners(rt, state, nil, &photonlinux.LinuxState{}, nil, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if _, err := service.autoAnnounceAssignedIPsResult(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}
	view := service.State.Common.ReadView()
	if len(view.State.Network.Zones["node-a.catofes."].Records) != 0 {
		t.Fatalf("expected no announcements when disabled, got %d", len(view.State.Network.Zones["node-a.catofes."].Records))
	}
}

func TestAutoAnnounceAssignedIPsPublishesNew(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"10.0.0.0/24"}, nil)

	service := newTestDaemonFromOwners(rt, state, nil, &photonlinux.LinuxState{}, nil, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if _, err := service.autoAnnounceAssignedIPsResult(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	view := service.State.Common.ReadView()
	rec := view.State.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected announcement record for %s", key)
	}
	ann, err := routing.ParseRouteAnnouncementRecord(rec)
	if err != nil {
		t.Fatalf("ParseRouteAnnouncementRecord: %v", err)
	}
	if !ann.Active {
		t.Fatalf("expected active announcement, got active=false")
	}
	if ann.Prefix != "10.0.0.0/24" {
		t.Fatalf("expected prefix 10.0.0.0/24, got %s", ann.Prefix)
	}
}

func TestAutoAnnounceAssignedIPsWithdrawsStale(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", nil, map[string]bool{"10.0.0.0/24": true})

	service := newTestDaemonFromOwners(rt, state, nil, &photonlinux.LinuxState{}, nil, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if _, err := service.autoAnnounceAssignedIPsResult(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	view := service.State.Common.ReadView()
	rec := view.State.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected withdrawal record for %s", key)
	}
	ann, err := routing.ParseRouteAnnouncementRecord(rec)
	if err != nil {
		t.Fatalf("ParseRouteAnnouncementRecord: %v", err)
	}
	if ann.Active {
		t.Fatalf("expected withdrawn announcement, got active=true")
	}
}

func TestAutoAnnounceAssignedIPsSkipsExisting(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"10.0.0.0/24"}, map[string]bool{"10.0.0.0/24": true})

	service := newTestDaemonFromOwners(rt, state, nil, &photonlinux.LinuxState{}, nil, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	beforeRev := uint64(service.State.Common.VerifiedRevision())
	if _, err := service.autoAnnounceAssignedIPsResult(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}
	if afterRev := uint64(service.State.Common.VerifiedRevision()); afterRev != beforeRev {
		t.Fatalf("no-op auto announce advanced revision: before=%d after=%d", beforeRev, afterRev)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	view := service.State.Common.ReadView()
	rec := view.State.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected announcement record for %s", key)
	}
	if rec.Version != 1 {
		t.Fatalf("expected no rewrite, version=%d", rec.Version)
	}
}

func TestAutoAnnounceAssignedIPsSkipsInvalidAssignment(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"192.168.0.0/24"}, nil)

	service := newTestDaemonFromOwners(rt, state, nil, &photonlinux.LinuxState{}, nil, time.Second)
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, rt.Now())
	if err != nil {
		t.Fatalf("BuildAuthorizedRouteSet: %v", err)
	}
	if len(ars.Errors) == 0 {
		t.Fatalf("expected authorization errors for un-pooled assignment")
	}
	if _, err := service.autoAnnounceAssignedIPsResult(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}

	key, _ := routing.NormalizeRouteAnnouncementKey("192.168.0.0/24")
	view := service.State.Common.ReadView()
	if view.State.Network.Zones["node-a.catofes."].Records[key] != nil {
		t.Fatalf("expected no announcement for invalid assignment")
	}
}

func TestAutoAnnounceAssignedIPsUsesAllAssignments(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"10.0.0.0/24"}, nil)
	service := newTestDaemonFromOwners(rt, state, nil, &photonlinux.LinuxState{}, nil, time.Second)
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	ars := &routing.AuthorizedRouteSet{
		Assignments: map[netip.Prefix]*routing.AssignmentEntry{
			prefix: {
				Prefix:     prefix,
				Source:     "catofes.",
				AssignedTo: "node-b.catofes.",
			},
		},
		AllAssignments: []*routing.AssignmentEntry{
			{Prefix: prefix, Source: "catofes.", AssignedTo: "node-b.catofes."},
			{Prefix: prefix, Source: "catofes.", AssignedTo: "node-a.catofes."},
		},
	}

	if _, err := service.autoAnnounceAssignedIPsResult(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}
	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.0.0/24")
	view := service.State.Common.ReadView()
	rec := view.State.Network.Zones["node-a.catofes."].Records[key]
	if rec == nil {
		t.Fatalf("expected announcement from local AllAssignments entry")
	}
	ann, err := routing.ParseRouteAnnouncementRecord(rec)
	if err != nil {
		t.Fatalf("ParseRouteAnnouncementRecord: %v", err)
	}
	if !ann.Active {
		t.Fatalf("expected active announcement")
	}
}

func TestAutoAnnounceSelectorsSeparatePersistentAndExplicitSharedRoutes(t *testing.T) {
	state, rt := buildAutoAnnounceTestState(t, "node-a.catofes.", []string{"10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"}, map[string]bool{"10.0.3.0/24": true})
	rt.Config.IPAM.AutoAnnounceAssignedIPs = false
	rt.Config.IPAM.Announce = []string{"non-shared", "tag:edge.c"}
	service := newTestDaemonFromOwners(rt, state, nil, &photonlinux.LinuxState{}, nil, time.Second)
	ars := &routing.AuthorizedRouteSet{AllAssignments: []*routing.AssignmentEntry{
		{Prefix: netip.MustParsePrefix("10.0.1.0/24"), AssignedTo: "node-a.catofes."},
		{Prefix: netip.MustParsePrefix("10.0.2.0/24"), AssignedTo: "node-a.catofes.", Shared: true, Tag: "edge.c"},
		{Prefix: netip.MustParsePrefix("10.0.3.0/24"), AssignedTo: "node-a.catofes.", Shared: true, Tag: "socks5.cn"},
	}}

	if _, err := service.autoAnnounceAssignedIPsResult(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs: %v", err)
	}
	view := service.State.Common.ReadView()
	for _, prefix := range []string{"10.0.1.0/24", "10.0.2.0/24"} {
		key, _ := routing.NormalizeRouteAnnouncementKey(prefix)
		ann, err := routing.ParseRouteAnnouncementRecord(view.State.Network.Zones["node-a.catofes."].Records[key])
		if err != nil || !ann.Active || ann.Controller != routing.RouteControllerAuto {
			t.Fatalf("auto announcement %s = %+v, error = %v", prefix, ann, err)
		}
	}
	serviceKey, _ := routing.NormalizeRouteAnnouncementKey("10.0.3.0/24")
	serviceAnn, err := routing.ParseRouteAnnouncementRecord(view.State.Network.Zones["node-a.catofes."].Records[serviceKey])
	if err != nil || !serviceAnn.Active || serviceAnn.Controller != "" {
		t.Fatalf("explicit service announcement = %+v, error = %v", serviceAnn, err)
	}

	service.App.Config.IPAM.Announce = []string{"non-shared"}
	if _, err := service.autoAnnounceAssignedIPsResult(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs after config change: %v", err)
	}
	view = service.State.Common.ReadView()
	edgeKey, _ := routing.NormalizeRouteAnnouncementKey("10.0.2.0/24")
	edgeAnn, _ := routing.ParseRouteAnnouncementRecord(view.State.Network.Zones["node-a.catofes."].Records[edgeKey])
	serviceAnn, _ = routing.ParseRouteAnnouncementRecord(view.State.Network.Zones["node-a.catofes."].Records[serviceKey])
	if edgeAnn.Active {
		t.Fatalf("removed auto selector left edge route active: %+v", edgeAnn)
	}
	if !serviceAnn.Active {
		t.Fatalf("selector reconcile withdrew explicit service route: %+v", serviceAnn)
	}

	service.App.Config.IPAM.Announce = nil
	if _, err := service.autoAnnounceAssignedIPsResult(ars); err != nil {
		t.Fatalf("autoAnnounceAssignedIPs after removing all selectors: %v", err)
	}
	view = service.State.Common.ReadView()
	localKey, _ := routing.NormalizeRouteAnnouncementKey("10.0.1.0/24")
	localAnn, _ := routing.ParseRouteAnnouncementRecord(view.State.Network.Zones["node-a.catofes."].Records[localKey])
	serviceAnn, _ = routing.ParseRouteAnnouncementRecord(view.State.Network.Zones["node-a.catofes."].Records[serviceKey])
	if localAnn.Active {
		t.Fatalf("removing all selectors left auto route active: %+v", localAnn)
	}
	if !serviceAnn.Active {
		t.Fatalf("removing all selectors withdrew explicit service route: %+v", serviceAnn)
	}
}

func TestLocalAssignedPrefixesUsesAllAssignments(t *testing.T) {
	prefix := netip.MustParsePrefix("10.0.0.0/24")
	ars := &routing.AuthorizedRouteSet{
		Assignments: map[netip.Prefix]*routing.AssignmentEntry{
			prefix: {Prefix: prefix, Source: "catofes.", AssignedTo: "node-b.catofes."},
		},
		AllAssignments: []*routing.AssignmentEntry{
			{Prefix: prefix, Source: "catofes.", AssignedTo: "node-b.catofes."},
			{Prefix: prefix, Source: "catofes.", AssignedTo: "node-a.catofes."},
		},
	}

	got := localAssignedPrefixes(ars, "node-a.catofes.")
	if len(got) != 1 || got[0] != prefix {
		t.Fatalf("localAssignedPrefixes = %+v, want [%s]", got, prefix)
	}
}

func TestExternalUpstreamSourcePrefixesExcludeSharedAssignments(t *testing.T) {
	local := netip.MustParsePrefix("2a0d:2905:1:7::/64")
	shared := netip.MustParsePrefix("2a0d:2905::/96")
	ars := &routing.AuthorizedRouteSet{
		AllAssignments: []*routing.AssignmentEntry{
			{Prefix: local, AssignedTo: "node-a.catofes."},
			{Prefix: shared, AssignedTo: "node-a.catofes.", Shared: true, Tag: "edge.c"},
		},
	}

	got := externalUpstreamSourcePrefixes(ars, "node-a.catofes.")
	want := netip.MustParsePrefix("2a0d:2905:1:7::1/64")
	if len(got) != 1 || got[0] != want {
		t.Fatalf("external source prefixes = %v, want only non-shared source %s", got, want)
	}
}
