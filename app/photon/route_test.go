package main

import (
	"crypto/ed25519"
	"encoding/json"
	"github.com/HiggsNet/photon/internal/photonlinux"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestAnnounceAndWithdrawRouteDirect(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	if err := mutateRouteWithConfig(rt.Config, managed, "10.0.1.0/24", true, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("announceRoute failed: %v", err)
	}

	common, _, err := loadOfflineOwnerViews(rt.Config)
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

	if err := mutateRouteWithConfig(rt.Config, managed, "10.0.1.0/24", false, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("withdrawRoute failed: %v", err)
	}

	common, _, err = loadOfflineOwnerViews(rt.Config)
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

	if err := mutateRouteWithConfig(rt.Config, managed, "10.0.1.1/24", true, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("announceRoute failed: %v", err)
	}

	common, _, err := loadOfflineOwnerViews(rt.Config)
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

	err := mutateRouteWithConfig(rt.Config, managed, "10.0.2.0/24", false, rt.Now(), rt.Direct)
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

	if err := mutateRouteWithConfig(rt.Config, managed, prefix, true, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("first announce failed: %v", err)
	}
	if err := mutateRouteWithConfig(rt.Config, managed, prefix, false, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	if err := mutateRouteWithConfig(rt.Config, managed, prefix, true, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("re-announce failed: %v", err)
	}

	common, _, err := loadOfflineOwnerViews(rt.Config)
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

	err := mutateRouteWithConfig(rt.Config, managed, "not-a-prefix", true, rt.Now(), rt.Direct)
	if err == nil {
		t.Fatalf("announceRoute with invalid prefix succeeded, want error")
	}
	if !strings.Contains(err.Error(), "invalid prefix") {
		t.Fatalf("error = %v, want invalid prefix", err)
	}
}

func TestAnnounceRouteRequiresWriteCapability(t *testing.T) {
	rt, managed := buildRouteTestRuntimeWithoutWriteCapability(t)

	err := mutateRouteWithConfig(rt.Config, managed, "10.0.1.0/24", true, rt.Now(), rt.Direct)
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

	if err := mutateRouteWithConfig(rt.Config, managed, prefix, true, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("announce failed: %v", err)
	}
	if err := mutateRouteWithConfig(rt.Config, managed, prefix, false, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("withdraw failed: %v", err)
	}
	err := mutateRouteWithConfig(rt.Config, managed, prefix, false, rt.Now(), rt.Direct)
	if err == nil {
		t.Fatalf("second withdraw succeeded, want error")
	}
	if !strings.Contains(err.Error(), "already withdrawn") {
		t.Fatalf("error = %v, want already withdrawn", err)
	}
}

func TestBuildRouteShowReportListsActiveAndAllAnnouncements(t *testing.T) {
	rt, managed := buildRouteTestRuntime(t)

	if err := mutateRouteWithConfig(rt.Config, managed, "10.0.1.0/24", true, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("announce active route: %v", err)
	}
	if err := mutateRouteWithConfig(rt.Config, managed, "10.0.2.0/24", true, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("announce withdrawn route: %v", err)
	}
	if err := mutateRouteWithConfig(rt.Config, managed, "10.0.2.0/24", false, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("withdraw route: %v", err)
	}

	report, err := buildRouteShowReport(rt.Config, "", false, rt.Now(), rt.Direct)
	if err != nil {
		t.Fatalf("buildRouteShowReport active: %v", err)
	}
	if len(report.Announcements) != 1 {
		t.Fatalf("active announcements len = %d, want 1: %+v", len(report.Announcements), report.Announcements)
	}
	if report.Announcements[0].Prefix != "10.0.1.0/24" || !report.Announcements[0].Active {
		t.Fatalf("active announcement = %+v", report.Announcements[0])
	}

	report, err = buildRouteShowReport(rt.Config, managed, true, rt.Now(), rt.Direct)
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
	if err := assignIPAMWithConfigTag(rt.Config, managed, "10.0.4.0/24", managed, true, "edge.cn", rt.Now(), rt.Direct); err != nil {
		t.Fatalf("assign tagged IPAM prefix: %v", err)
	}
	if err := mutateRouteWithConfig(rt.Config, managed, "10.0.4.0/24", true, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("announce tagged route: %v", err)
	}

	report, err := buildRouteShowReport(rt.Config, managed, false, rt.Now(), rt.Direct)
	if err != nil {
		t.Fatalf("buildRouteShowReport: %v", err)
	}
	if len(report.Announcements) != 1 || report.Announcements[0].Tag != "edge.cn" {
		t.Fatalf("announcements = %+v, want tag edge.cn", report.Announcements)
	}
	if row := report.Announcements[0]; !row.Authorized || !row.Shared {
		t.Fatalf("tagged announcement should be authorized and shared: %+v", row)
	}
	if err := mutateRouteWithConfig(rt.Config, managed, "10.0.4.0/24", false, rt.Now(), rt.Direct); err != nil {
		t.Fatalf("withdraw tagged route: %v", err)
	}
	report, err = buildRouteShowReport(rt.Config, managed, true, rt.Now(), rt.Direct)
	if err != nil {
		t.Fatalf("buildRouteShowReport after withdrawal: %v", err)
	}
	if len(report.Announcements) != 1 {
		t.Fatalf("withdrawn announcements = %+v", report.Announcements)
	}
	if row := report.Announcements[0]; row.Active || row.Authorized || !row.Shared || row.Tag != "" {
		t.Fatalf("withdrawn route should retain shared classification without authorization or tag: %+v", row)
	}
}

func buildRouteTestRuntime(t *testing.T) (*testApp, zone.ZonePath) {
	t.Helper()
	return buildRouteTestRuntimeWithNetwork(t, true, nil)
}

func buildRouteTestRuntimeWithoutWriteCapability(t *testing.T) (*testApp, zone.ZonePath) {
	t.Helper()
	return buildRouteTestRuntimeWithNetwork(t, false, nil)
}

func buildRouteTestRuntimeWithNetwork(t *testing.T, writeCap bool, mutate func(*zone.NetworkState)) (*testApp, zone.ZonePath) {
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
	rt := &testApp{Config: config, Clock: func() time.Time { return time.Unix(1000, 0) }, Direct: true}
	seedPartitionedStateDB(t, rt.Config.StatePath, &corestate.VerifiedState{
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
