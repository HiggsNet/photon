package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/HiggsNet/photon/internal/photonlinux"
	"net/netip"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestAnnounceAndWithdrawRouteDirect(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	if err := mutateRouteWithRuntime(rt, managed, "10.0.1.0/24", true); err != nil {
		t.Fatalf("announceRoute failed: %v", err)
	}

	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews after announce: %v", err)
	}
	key, err := routing.NormalizeRouteAnnouncementKey("10.0.1.0/24")
	if err != nil {
		t.Fatalf("NormalizeRouteAnnouncementKey: %v", err)
	}
	rec := common.State.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("announcement record not found at key %s", key)
	}
	if rec.Type != routing.RecordTypeRouteAnnouncement {
		t.Fatalf("record type = %q, want %q", rec.Type, routing.RecordTypeRouteAnnouncement)
	}
	var ann routing.RouteAnnouncementRecord
	if err := json.Unmarshal(rec.Value, &ann); err != nil {
		t.Fatalf("unmarshal announcement: %v", err)
	}
	if !ann.Active {
		t.Fatalf("ann.Active = false, want true")
	}
	if ann.Prefix != "10.0.1.0/24" {
		t.Fatalf("ann.Prefix = %q, want %q", ann.Prefix, "10.0.1.0/24")
	}
	if rec.Version != 1 {
		t.Fatalf("record version = %d, want 1", rec.Version)
	}

	if err := mutateRouteWithRuntime(rt, managed, "10.0.1.0/24", false); err != nil {
		t.Fatalf("withdrawRoute failed: %v", err)
	}

	common, _, err = loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews after withdraw: %v", err)
	}
	rec = common.State.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("withdrawal record not found at key %s", key)
	}
	if err := json.Unmarshal(rec.Value, &ann); err != nil {
		t.Fatalf("unmarshal withdrawal: %v", err)
	}
	if ann.Active {
		t.Fatalf("ann.Active = true, want false")
	}
	if rec.Version != 2 {
		t.Fatalf("record version = %d, want 2", rec.Version)
	}
}

func TestAnnounceRouteCanonicalizesPrefix(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	if err := mutateRouteWithRuntime(rt, managed, "10.0.1.1/24", true); err != nil {
		t.Fatalf("announceRoute failed: %v", err)
	}

	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	key, err := routing.NormalizeRouteAnnouncementKey("10.0.1.1/24")
	if err != nil {
		t.Fatalf("NormalizeRouteAnnouncementKey: %v", err)
	}
	rec := common.State.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("record not found at key %s", key)
	}
	var ann routing.RouteAnnouncementRecord
	if err := json.Unmarshal(rec.Value, &ann); err != nil {
		t.Fatalf("unmarshal announcement: %v", err)
	}
	if ann.Prefix != "10.0.1.0/24" {
		t.Fatalf("ann.Prefix = %q, want %q", ann.Prefix, "10.0.1.0/24")
	}
}

func TestWithdrawWithoutAnnouncementFails(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	err := mutateRouteWithRuntime(rt, managed, "10.0.2.0/24", false)
	if err == nil {
		t.Fatalf("withdrawRoute without announcement succeeded, want error")
	}
	if !strings.Contains(err.Error(), "no active route announcement") {
		t.Fatalf("error = %v, want no active route announcement", err)
	}
}

func TestReannounceAfterWithdraw(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)
	prefix := "10.0.3.0/24"

	if err := mutateRouteWithRuntime(rt, managed, prefix, true); err != nil {
		t.Fatalf("first announce failed: %v", err)
	}
	if err := mutateRouteWithRuntime(rt, managed, prefix, false); err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	if err := mutateRouteWithRuntime(rt, managed, prefix, true); err != nil {
		t.Fatalf("re-announce failed: %v", err)
	}

	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	key, err := routing.NormalizeRouteAnnouncementKey(prefix)
	if err != nil {
		t.Fatalf("NormalizeRouteAnnouncementKey: %v", err)
	}
	rec := common.State.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("record not found at key %s", key)
	}
	var ann routing.RouteAnnouncementRecord
	if err := json.Unmarshal(rec.Value, &ann); err != nil {
		t.Fatalf("unmarshal announcement: %v", err)
	}
	if !ann.Active {
		t.Fatalf("ann.Active = false, want true after re-announce")
	}
	if rec.Version != 3 {
		t.Fatalf("record version = %d, want 3", rec.Version)
	}
}

func TestAnnounceRouteInvalidPrefix(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	err := mutateRouteWithRuntime(rt, managed, "not-a-prefix", true)
	if err == nil {
		t.Fatalf("announceRoute with invalid prefix succeeded, want error")
	}
	if !strings.Contains(err.Error(), "invalid prefix") {
		t.Fatalf("error = %v, want invalid prefix", err)
	}
}

func TestAnnounceRouteRequiresWriteCapability(t *testing.T) {
	rt, managed := buildRouteTestRuntimeWithoutWriteCapability(t)

	err := mutateRouteWithRuntime(rt, managed, "10.0.1.0/24", true)
	if err == nil {
		t.Fatalf("announceRoute without write capability succeeded, want error")
	}
	if !strings.Contains(err.Error(), "authorized key lacks capability") {
		t.Fatalf("error = %v, want authorized key lacks capability", err)
	}
}

func TestWithdrawAlreadyWithdrawnFails(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)
	prefix := "10.0.4.0/24"

	if err := mutateRouteWithRuntime(rt, managed, prefix, true); err != nil {
		t.Fatalf("announce failed: %v", err)
	}
	if err := mutateRouteWithRuntime(rt, managed, prefix, false); err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	err := mutateRouteWithRuntime(rt, managed, prefix, false)
	if err == nil {
		t.Fatalf("second withdraw succeeded, want error")
	}
	if !strings.Contains(err.Error(), "already withdrawn") {
		t.Fatalf("error = %v, want already withdrawn", err)
	}
}

func TestBuildRouteShowReportListsActiveAndAllAnnouncements(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	if err := mutateRouteWithRuntime(rt, managed, "10.0.1.0/24", true); err != nil {
		t.Fatalf("announce active route: %v", err)
	}
	if err := mutateRouteWithRuntime(rt, managed, "10.0.2.0/24", true); err != nil {
		t.Fatalf("announce withdrawn route: %v", err)
	}
	if err := mutateRouteWithRuntime(rt, managed, "10.0.2.0/24", false); err != nil {
		t.Fatalf("withdraw route: %v", err)
	}

	report, err := buildRouteShowReport(rt, "", false)
	if err != nil {
		t.Fatalf("buildRouteShowReport active: %v", err)
	}
	if len(report.Announcements) != 1 {
		t.Fatalf("active announcements len = %d, want 1: %+v", len(report.Announcements), report.Announcements)
	}
	if report.Announcements[0].Prefix != "10.0.1.0/24" || !report.Announcements[0].Active {
		t.Fatalf("active announcement = %+v", report.Announcements[0])
	}

	report, err = buildRouteShowReport(rt, managed, true)
	if err != nil {
		t.Fatalf("buildRouteShowReport all: %v", err)
	}
	if len(report.Announcements) != 2 {
		t.Fatalf("all announcements len = %d, want 2: %+v", len(report.Announcements), report.Announcements)
	}
	if report.Announcements[1].Prefix != "10.0.2.0/24" || report.Announcements[1].Active {
		t.Fatalf("withdrawn announcement = %+v", report.Announcements[1])
	}
}

func TestBuildRouteShowReportIncludesAssignmentTag(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	if err := assignIPAMWithRuntimeTag(rt, managed, "10.0.4.0/24", managed, true, "edge.cn"); err != nil {
		t.Fatalf("assign tagged IPAM prefix: %v", err)
	}
	if err := mutateRouteWithRuntime(rt, managed, "10.0.4.0/24", true); err != nil {
		t.Fatalf("announce tagged route: %v", err)
	}

	report, err := buildRouteShowReport(rt, managed, false)
	if err != nil {
		t.Fatalf("buildRouteShowReport: %v", err)
	}
	if len(report.Announcements) != 1 || report.Announcements[0].Tag != "edge.cn" {
		t.Fatalf("announcements = %+v, want tag edge.cn", report.Announcements)
	}
}

func TestPrintRouteShowReportUsesFilteredVerboseTable(t *testing.T) {
	report := &inspect.RouteShowReport{
		ManagedZone: "node-a.catofes.",
		Announcements: []inspect.RouteShowRow{
			{
				Zone: "node-a.catofes.", Prefix: "10.0.1.0/24", Tag: "edge.cn", Active: true,
				Authorized: true, Controller: "service", Version: 2,
				Key: "routes/announcements/10.0.1.0_24",
			},
			{Zone: "node-b.catofes.", Prefix: "10.0.2.0/24", Active: false},
		},
	}
	var output bytes.Buffer
	if err := printRouteShowReport(&output, report, true, "node-a", true); err != nil {
		t.Fatalf("printRouteShowReport: %v", err)
	}
	for _, want := range []string{
		"announcements: 1/2",
		"PREFIX", "ZONE", "TAG", "STATE", "AUTHORIZATION", "CONTROLLER", "VERSION", "RECORD",
		"10.0.1.0/24", "node-a.catofes.", "edge.cn", "active", "authorized", "service",
		"routes/announcements/10.0.1.0_24",
	} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("output missing %q:\n%s", want, output.String())
		}
	}
	if strings.Contains(output.String(), "node-b.catofes.") {
		t.Fatalf("filter leaked node-b:\n%s", output.String())
	}
}

func TestSortRouteShowRowsUsesPrefixBeforeZone(t *testing.T) {
	rows := []inspect.RouteShowRow{
		{Zone: "a.example.", Prefix: "2001:db8:2::/64", Key: "z"},
		{Zone: "z.example.", Prefix: "10.0.0.0/8", Key: "z"},
		{Zone: "c.example.", Prefix: "2.0.0.0/8", Key: "z"},
		{Zone: "b.example.", Prefix: "2001:db8:1::/64", Key: "z"},
		{Zone: "a.example.", Prefix: "10.0.0.0/8", Key: "a"},
	}
	sortRouteShowRows(rows)
	want := []inspect.RouteShowRow{
		{Zone: "c.example.", Prefix: "2.0.0.0/8", Key: "z"},
		{Zone: "a.example.", Prefix: "10.0.0.0/8", Key: "a"},
		{Zone: "z.example.", Prefix: "10.0.0.0/8", Key: "z"},
		{Zone: "b.example.", Prefix: "2001:db8:1::/64", Key: "z"},
		{Zone: "a.example.", Prefix: "2001:db8:2::/64", Key: "z"},
	}
	if !reflect.DeepEqual(rows, want) {
		t.Fatalf("rows = %+v, want prefix-first %+v", rows, want)
	}
}

func TestPrintRouteShowReportSeparatesAndGroupsSharedAnnouncements(t *testing.T) {
	report := &inspect.RouteShowReport{
		ManagedZone: "node-a.catofes.",
		Announcements: []inspect.RouteShowRow{
			{Zone: "node-a.catofes.", Prefix: "10.0.1.0/24", Active: true, Authorized: true},
			{Zone: "node-b.catofes.", Prefix: "10.0.9.0/24", Shared: true, Active: true, Authorized: true},
			{Zone: "node-c.catofes.", Prefix: "10.0.9.0/24", Shared: true, Active: true, Authorized: true},
		},
	}
	var output bytes.Buffer
	if err := printRouteShowReport(&output, report, false, "", false); err != nil {
		t.Fatalf("printRouteShowReport: %v", err)
	}
	got := output.String()
	for _, want := range []string{
		"non_shared_announcements: 1",
		"shared_announcements: 2 (1 prefixes)",
		"node-b.catofes.",
		"node-c.catofes.",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("output missing %q:\n%s", want, got)
		}
	}
	if count := strings.Count(got, "10.0.9.0/24"); count != 1 {
		t.Fatalf("shared prefix rendered %d times, want once:\n%s", count, got)
	}
}

func TestPrintRouteShowReportRightAlignsZoneColumn(t *testing.T) {
	report := &inspect.RouteShowReport{
		Announcements: []inspect.RouteShowRow{
			{Zone: ".", Prefix: "10.0.0.0/8", Active: true, Authorized: true},
			{Zone: "node-a.catofes.", Prefix: "10.1.0.0/16", Active: true, Authorized: true},
		},
	}
	var output bytes.Buffer
	if err := printRouteShowReport(&output, report, false, "", false); err != nil {
		t.Fatalf("printRouteShowReport: %v", err)
	}
	lines := strings.Split(output.String(), "\n")
	var shortLine, longLine string
	for _, line := range lines {
		switch {
		case strings.Contains(line, "10.0.0.0/8"):
			shortLine = line
		case strings.Contains(line, "10.1.0.0/16"):
			longLine = line
		}
	}
	shortEnd := strings.LastIndex(shortLine, ".") + 1
	longStart := strings.Index(longLine, "node-a.catofes.")
	longEnd := longStart + len("node-a.catofes.")
	if shortLine == "" || longLine == "" || shortEnd != longEnd {
		t.Fatalf("ZONE cells are not right-aligned (ends %d/%d):\n%s", shortEnd, longEnd, output.String())
	}
}

func TestRouteUsesSharedAssignment(t *testing.T) {
	ars := &routing.AuthorizedRouteSet{AllAssignments: []*routing.AssignmentEntry{
		{
			Prefix:     netip.MustParsePrefix("10.0.9.0/24"),
			Source:     "catofes.",
			AssignedTo: "node-a.catofes.",
			Shared:     true,
		},
	}}
	if !routeUsesSharedAssignment(ars, "node-a.catofes.", "10.0.9.0/24") {
		t.Fatal("shared assignment was not detected")
	}
	if routeUsesSharedAssignment(ars, "node-b.catofes.", "10.0.9.0/24") {
		t.Fatal("assignment for another node was detected as shared")
	}
}

func buildRouteTestRuntime(t *testing.T) (*AppContext, zone.ZonePath) {
	t.Helper()
	return buildRouteTestRuntimeWithNetwork(t, true, nil)
}

func buildRouteTestRuntimeWithoutWriteCapability(t *testing.T) (*AppContext, zone.ZonePath) {
	t.Helper()
	return buildRouteTestRuntimeWithNetwork(t, false, nil)
}

func buildRouteTestRuntimeWithNetwork(t *testing.T, writeCap bool, mutate func(*zone.NetworkState)) (*AppContext, zone.ZonePath) {
	t.Helper()
	dir := t.TempDir()
	rootPub, rootPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(root): %v", err)
	}
	catofesPub, catofesPriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(catofes): %v", err)
	}
	zonePub, zonePriv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(zone): %v", err)
	}

	managed := zone.ZonePath("pek.catofes.")
	parent := zone.ZonePath("catofes.")

	rootAuthority := &zone.ZoneAuthority{
		Zone:      zone.RootZone,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: rootPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}
	catofesAuthority := &zone.ZoneAuthority{
		Zone:      parent,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: catofesPub,
			Capabilities: []zone.Capability{{
				Permissions: []zone.Permission{zone.PermDelegate},
			}},
		}},
	}

	perms := []zone.Permission{zone.PermDelegate}
	if writeCap {
		perms = append(perms, zone.PermWrite)
	}
	childAuthority := &zone.ZoneAuthority{
		Zone:      managed,
		Epoch:     1,
		Threshold: 1,
		Keys: []zone.AuthorizedKey{{
			Key: zonePub,
			Capabilities: []zone.Capability{{
				Permissions: perms,
			}},
		}},
	}

	catofesDelegation := &zone.Delegation{
		ZoneName:  parent,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *catofesAuthority,
	}
	if err := photoncrypto.SignDelegation(catofesDelegation, zone.RootZone, rootPriv); err != nil {
		t.Fatalf("SignDelegation(catofes): %v", err)
	}
	pekDelegation := &zone.Delegation{
		ZoneName:  managed,
		Scope:     zone.DelegationScopeDirectChild,
		Authority: *childAuthority,
	}
	if err := photoncrypto.SignDelegation(pekDelegation, parent, catofesPriv); err != nil {
		t.Fatalf("SignDelegation(pek): %v", err)
	}

	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	ns.Zones[parent] = zone.NewZoneState(parent, catofesAuthority)
	ns.Zones[managed] = zone.NewZoneState(managed, childAuthority)
	ns.Zones[zone.RootZone].Delegations[parent] = catofesDelegation
	ns.Zones[parent].Delegations[managed] = pekDelegation
	addUnsignedIPAMPoolForTest(ns, zone.RootZone, "10.0.0.0/8", zone.RootZone)
	addUnsignedIPAMPoolForTest(ns, zone.RootZone, "10.0.0.0/16", parent)
	addUnsignedRouteAssignmentForTest(ns, parent, "10.0.0.0/16", managed)
	if mutate != nil {
		mutate(ns)
	}
	configureValidation(ns)
	if err := photoncrypto.VerifyChain(ns, managed, time.Unix(1000, 0)); err != nil {
		t.Fatalf("VerifyChain: %v", err)
	}

	config := defaultAppConfig()
	config.DataDir = dir
	config.StatePath = filepath.Join(dir, "photon.db")
	rt := &AppContext{Config: config, StatePath: config.StatePath, Clock: func() time.Time { return time.Unix(1000, 0) }, DisableControl: true}
	seedPartitionedStateDB(t, rt.StatePath, &corestate.VerifiedState{
		ManagedZone: managed, Network: ns, IdentityPrivateKey: zonePriv,
	}, &corestate.GossipCheckpoint{}, &photonlinux.LinuxState{})
	return rt, managed
}

func addUnsignedRouteAssignmentForTest(ns *zone.NetworkState, source zone.ZonePath, prefix string, assignedTo zone.ZonePath) {
	canonical, err := routing.CanonicalizePrefix(prefix)
	if err != nil {
		panic(err)
	}
	key, err := routing.NormalizeIPAMAssignmentKey(prefix)
	if err != nil {
		panic(err)
	}
	value, err := json.Marshal(routing.IPAMAssignmentRecord{
		Version: 1, Prefix: canonical, AssignedTo: assignedTo, Active: true,
	})
	if err != nil {
		panic(err)
	}
	ns.Zones[source].Records[key] = &zone.Record{
		Zone: source, Key: key, Type: routing.RecordTypeIPAMAssignment, Value: value,
	}
}
