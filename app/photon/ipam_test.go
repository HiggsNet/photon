package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"github.com/HiggsNet/photon/internal/photonlinux"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
)

func TestCreateAndRevokeIPAMPoolDirect(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	if err := createIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16", "catofes."); err != nil {
		t.Fatalf("createIPAMPool failed: %v", err)
	}

	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews after create: %v", err)
	}
	key, err := routing.NormalizeIPAMPoolKey("10.0.0.0/16")
	if err != nil {
		t.Fatalf("NormalizeIPAMPoolKey: %v", err)
	}
	rec := common.State.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("pool record not found at key %s", key)
	}
	if rec.Type != routing.RecordTypeIPAMPool {
		t.Fatalf("record type = %q, want %q", rec.Type, routing.RecordTypeIPAMPool)
	}
	var pool routing.IPAMPoolRecord
	if err := json.Unmarshal(rec.Value, &pool); err != nil {
		t.Fatalf("unmarshal pool: %v", err)
	}
	if !pool.Active {
		t.Fatalf("pool.Active = false, want true")
	}
	if pool.Prefix != "10.0.0.0/16" {
		t.Fatalf("pool.Prefix = %q, want %q", pool.Prefix, "10.0.0.0/16")
	}
	if pool.DelegatedTo != "catofes." {
		t.Fatalf("pool.DelegatedTo = %q, want %q", pool.DelegatedTo, "catofes.")
	}
	if rec.Version != 1 {
		t.Fatalf("record version = %d, want 1", rec.Version)
	}

	if err := revokeIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16"); err != nil {
		t.Fatalf("revokeIPAMPool failed: %v", err)
	}

	common, _, err = loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews after revoke: %v", err)
	}
	rec = common.State.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("revoke record not found at key %s", key)
	}
	if err := json.Unmarshal(rec.Value, &pool); err != nil {
		t.Fatalf("unmarshal revoke: %v", err)
	}
	if pool.Active {
		t.Fatalf("pool.Active = true, want false")
	}
	if pool.DelegatedTo != "catofes." {
		t.Fatalf("pool.DelegatedTo = %q, want %q after revoke", pool.DelegatedTo, "catofes.")
	}
	if rec.Version != 2 {
		t.Fatalf("record version = %d, want 2", rec.Version)
	}
}

func TestAssignAndRevokeIPAMDirect(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	if err := assignIPAMWithRuntimeTag(rt, managed, "10.0.1.0/24", "node.pek.catofes.", false, ""); err != nil {
		t.Fatalf("assignIPAM failed: %v", err)
	}

	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews after assign: %v", err)
	}
	key, err := routing.NormalizeIPAMAssignmentKey("10.0.1.0/24")
	if err != nil {
		t.Fatalf("NormalizeIPAMAssignmentKey: %v", err)
	}
	rec := common.State.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("assignment record not found at key %s", key)
	}
	if rec.Type != routing.RecordTypeIPAMAssignment {
		t.Fatalf("record type = %q, want %q", rec.Type, routing.RecordTypeIPAMAssignment)
	}
	var assignment routing.IPAMAssignmentRecord
	if err := json.Unmarshal(rec.Value, &assignment); err != nil {
		t.Fatalf("unmarshal assignment: %v", err)
	}
	if !assignment.Active {
		t.Fatalf("assignment.Active = false, want true")
	}
	if assignment.Prefix != "10.0.1.0/24" {
		t.Fatalf("assignment.Prefix = %q, want %q", assignment.Prefix, "10.0.1.0/24")
	}
	if assignment.AssignedTo != "node.pek.catofes." {
		t.Fatalf("assignment.AssignedTo = %q, want %q", assignment.AssignedTo, "node.pek.catofes.")
	}

	if err := revokeIPAMAssignmentWithRuntimeTo(rt, managed, "10.0.1.0/24", ""); err != nil {
		t.Fatalf("revokeIPAMAssignment failed: %v", err)
	}

	common, _, err = loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews after revoke: %v", err)
	}
	rec = common.State.Network.Zones[managed].Records[key]
	if err := json.Unmarshal(rec.Value, &assignment); err != nil {
		t.Fatalf("unmarshal revoke: %v", err)
	}
	if assignment.Active {
		t.Fatalf("assignment.Active = true, want false")
	}
	if assignment.AssignedTo != "node.pek.catofes." {
		t.Fatalf("assignment.AssignedTo = %q, want %q after revoke", assignment.AssignedTo, "node.pek.catofes.")
	}
}

func TestIPAMCanonicalizesPrefix(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	if err := createIPAMPoolWithRuntime(rt, managed, "10.0.1.1/16", "catofes."); err != nil {
		t.Fatalf("createIPAMPool failed: %v", err)
	}

	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	key, err := routing.NormalizeIPAMPoolKey("10.0.1.1/16")
	if err != nil {
		t.Fatalf("NormalizeIPAMPoolKey: %v", err)
	}
	rec := common.State.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("record not found at key %s", key)
	}
	var pool routing.IPAMPoolRecord
	if err := json.Unmarshal(rec.Value, &pool); err != nil {
		t.Fatalf("unmarshal pool: %v", err)
	}
	if pool.Prefix != "10.0.0.0/16" {
		t.Fatalf("pool.Prefix = %q, want %q", pool.Prefix, "10.0.0.0/16")
	}
}

func TestRevokeIPAMPoolWithoutRecordFails(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	err := revokeIPAMPoolWithRuntime(rt, managed, "10.0.2.0/24")
	if err == nil {
		t.Fatalf("revokeIPAMPool without record succeeded, want error")
	}
	if !strings.Contains(err.Error(), "no active") {
		t.Fatalf("error = %v, want no active", err)
	}
}

func TestRevokeIPAMAssignmentWithoutRecordFails(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	err := revokeIPAMAssignmentWithRuntimeTo(rt, managed, "10.0.2.0/24", "")
	if err == nil {
		t.Fatalf("revokeIPAMAssignment without record succeeded, want error")
	}
	if !strings.Contains(err.Error(), "no active") {
		t.Fatalf("error = %v, want no active", err)
	}
}

func TestRevokeAlreadyRevokedPoolFails(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	if err := createIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16", "catofes."); err != nil {
		t.Fatalf("createIPAMPool failed: %v", err)
	}
	if err := revokeIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16"); err != nil {
		t.Fatalf("first revoke failed: %v", err)
	}
	err := revokeIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16")
	if err == nil {
		t.Fatalf("second revoke succeeded, want error")
	}
	if !strings.Contains(err.Error(), "already revoked") {
		t.Fatalf("error = %v, want already revoked", err)
	}
}

func TestRevokeAlreadyRevokedAssignmentFails(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	if err := assignIPAMWithRuntimeTag(rt, managed, "10.0.1.0/24", "node.pek.catofes.", false, ""); err != nil {
		t.Fatalf("assignIPAM failed: %v", err)
	}
	if err := revokeIPAMAssignmentWithRuntimeTo(rt, managed, "10.0.1.0/24", ""); err != nil {
		t.Fatalf("first revoke failed: %v", err)
	}
	err := revokeIPAMAssignmentWithRuntimeTo(rt, managed, "10.0.1.0/24", "")
	if err == nil {
		t.Fatalf("second revoke succeeded, want error")
	}
	if !strings.Contains(err.Error(), "already revoked") {
		t.Fatalf("error = %v, want already revoked", err)
	}
}

func TestIPAMMissingCapability(t *testing.T) {
	rt, managed := buildIPAMTestRuntimeWithoutIPAMCapability(t)

	err := createIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16", "catofes.")
	if err == nil {
		t.Fatalf("createIPAMPool without capability succeeded, want error")
	}
	if !strings.Contains(err.Error(), "lacks allocate-ip") {
		t.Fatalf("error = %v, want lacks allocate-ip", err)
	}
}

func TestCreateIPAMPoolRejectsOwnerMismatch(t *testing.T) {
	rt, managed := buildIPAMTestRuntimeWithNetwork(t, true, func(network *zone.NetworkState) {
		removeIPAMPoolForTest(network, "catofes.", "10.0.0.0/16")
	})

	err := createIPAMPoolWithRuntime(rt, managed, "10.0.1.0/24", managed)
	if err == nil {
		t.Fatalf("createIPAMPoolWithRuntime succeeded, want owner mismatch")
	}
	if !strings.Contains(err.Error(), "ipam_pool_owner_mismatch") {
		t.Fatalf("error = %v, want ipam_pool_owner_mismatch", err)
	}
}

func TestAssignIPAMRejectsImplicitAncestorPool(t *testing.T) {
	rt, managed := buildIPAMTestRuntimeWithNetwork(t, true, func(network *zone.NetworkState) {
		removeIPAMPoolForTest(network, "catofes.", "10.0.0.0/16")
	})

	err := assignIPAMWithRuntimeTag(rt, managed, "10.0.1.0/24", managed, false, "")
	if err == nil {
		t.Fatalf("assignIPAMWithRuntime succeeded, want pool mismatch")
	}
	if !strings.Contains(err.Error(), "ipam_assignment_pool_mismatch") {
		t.Fatalf("error = %v, want ipam_assignment_pool_mismatch", err)
	}
}

func TestListIPAMAssignments(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	// Pool covering the assignment is required by BuildAuthorizedRouteSet.
	if err := createIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16", "catofes."); err != nil {
		t.Fatalf("createIPAMPool failed: %v", err)
	}
	if err := assignIPAMWithRuntimeTag(rt, managed, "10.0.1.0/24", "node.pek.catofes.", false, ""); err != nil {
		t.Fatalf("assignIPAM failed: %v", err)
	}

	var output bytes.Buffer
	if err := listIPAMAssignmentsWithRuntimeTo(&output, rt, ""); err != nil {
		t.Fatalf("listIPAMAssignments failed: %v", err)
	}
	for _, want := range []string{"assignments: 1", "PREFIX", "SOURCE", "ASSIGNED_TO", "MODE", "TAG", "10.0.1.0/24", "exclusive"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("assignment table missing %q:\n%s", want, output.String())
		}
	}
	if strings.HasPrefix(strings.TrimSpace(output.String()), "[") {
		t.Fatalf("assignment output is still JSON:\n%s", output.String())
	}

	output.Reset()
	if err := listIPAMAssignmentsWithRuntimeTo(&output, rt, "node.pek.catofes."); err != nil {
		t.Fatalf("listIPAMAssignments with filter failed: %v", err)
	}
	if !strings.Contains(output.String(), "assignments: 1") {
		t.Fatalf("filtered assignment table:\n%s", output.String())
	}

	output.Reset()
	err := listIPAMAssignmentsWithRuntimeTo(&output, rt, "other.catofes.")
	if err != nil {
		t.Fatalf("listIPAMAssignments with non-matching filter failed: %v", err)
	}
	if !strings.Contains(output.String(), "assignments: 0") {
		t.Fatalf("empty assignment table:\n%s", output.String())
	}
}

func TestIPAMGetExplainsPoolChainAndAssignment(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	if err := assignIPAMWithRuntimeTag(rt, managed, "10.0.1.0/24", "node.pek.catofes.", false, ""); err != nil {
		t.Fatalf("assignIPAM failed: %v", err)
	}

	report, err := buildIPAMGetReport(rt, "10.0.1.42")
	if err != nil {
		t.Fatalf("buildIPAMGetReport: %v", err)
	}
	if report.Query != "10.0.1.42/32" {
		t.Fatalf("Query = %q, want 10.0.1.42/32", report.Query)
	}
	if report.BestPool == nil || report.BestPool.DelegatedTo != string(managed) {
		t.Fatalf("BestPool = %+v, want delegated to managed", report.BestPool)
	}
	if len(report.Assignments) != 1 || report.Assignments[0].AssignedTo != "node.pek.catofes." {
		t.Fatalf("Assignments = %+v, want node assignment", report.Assignments)
	}
	if report.AssignedTo == nil || *report.AssignedTo != "node.pek.catofes." {
		t.Fatalf("AssignedTo = %v, want node.pek.catofes.", report.AssignedTo)
	}

	var output bytes.Buffer
	if err := writeIPAMGetReport(&output, report); err != nil {
		t.Fatalf("writeIPAMGetReport: %v", err)
	}
	for _, want := range []string{"query: 10.0.1.42/32", "pools:", "BEST", "assignments: 1", "ASSIGNED_TO", "routes:", "diagnostics:"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("IPAM get table missing %q:\n%s", want, output.String())
		}
	}
}

func TestIPAMGetReportsUnassignedAddress(t *testing.T) {
	rt, _ := buildIPAMTestRuntime(t)
	report, err := buildIPAMGetReport(rt, "10.0.9.1")
	if err != nil {
		t.Fatalf("buildIPAMGetReport: %v", err)
	}
	if !ipamDiagnosticsContain(report.Diagnostics, "ipam_unassigned") {
		t.Fatalf("Diagnostics = %+v, want ipam_unassigned", report.Diagnostics)
	}
}

func TestIPAMGetReportsSharedAssignment(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	if err := assignIPAMWithRuntimeTag(rt, managed, "10.0.3.0/24", "node.pek.catofes.", true, ""); err != nil {
		t.Fatalf("assignIPAM shared failed: %v", err)
	}

	report, err := buildIPAMGetReport(rt, "10.0.3.42")
	if err != nil {
		t.Fatalf("buildIPAMGetReport: %v", err)
	}
	if len(report.Assignments) != 1 || !report.Assignments[0].Shared {
		t.Fatalf("Assignments = %+v, want one shared assignment", report.Assignments)
	}
	if report.AssignedTo != nil {
		t.Fatalf("AssignedTo = %v, want nil for shared assignment", report.AssignedTo)
	}
}

func TestIPAMGetReportsNoPool(t *testing.T) {
	rt, _ := buildIPAMTestRuntime(t)
	report, err := buildIPAMGetReport(rt, "192.0.2.1")
	if err != nil {
		t.Fatalf("buildIPAMGetReport: %v", err)
	}
	if !ipamDiagnosticsContain(report.Diagnostics, "ipam_no_pool") {
		t.Fatalf("Diagnostics = %+v, want ipam_no_pool", report.Diagnostics)
	}
}

func TestBuildIPAMMineReport(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	if err := createIPAMPoolWithRuntime(rt, managed, "10.0.0.0/16", managed); err != nil {
		t.Fatalf("createIPAMPool failed: %v", err)
	}
	if err := assignIPAMWithRuntimeTag(rt, managed, "10.0.1.0/24", managed, false, ""); err != nil {
		t.Fatalf("assignIPAM failed: %v", err)
	}
	if err := assignIPAMWithRuntimeTag(rt, managed, "10.0.2.0/24", "node.pek.catofes.", false, ""); err != nil {
		t.Fatalf("assignIPAM other failed: %v", err)
	}

	report, err := buildIPAMMineReport(rt)
	if err != nil {
		t.Fatalf("buildIPAMMineReport failed: %v", err)
	}
	if report.ManagedZone != string(managed) {
		t.Fatalf("ManagedZone = %q, want %q", report.ManagedZone, managed)
	}
	if len(report.Assignments) != 1 {
		t.Fatalf("Assignments len = %d, want 1: %+v", len(report.Assignments), report.Assignments)
	}
	if report.Assignments[0].Prefix != "10.0.1.0/24" || report.Assignments[0].Source != string(managed) {
		t.Fatalf("Assignments[0] = %+v, want local 10.0.1.0/24", report.Assignments[0])
	}
	if len(report.Pools) != 2 {
		t.Fatalf("Pools len = %d, want 2: %+v", len(report.Pools), report.Pools)
	}
	seenPublished := false
	seenDelegated := false
	for _, pool := range report.Pools {
		if stringSliceContains(pool.Relation, "usable_by_managed_zone") {
			t.Fatalf("pool relation = %v, should not include usable_by_managed_zone", pool.Relation)
		}
		if pool.Source == string(managed) && stringSliceContains(pool.Relation, "published_by_managed_zone") {
			seenPublished = true
		}
		if pool.DelegatedTo == string(managed) && stringSliceContains(pool.Relation, "delegated_to_managed_zone") {
			seenDelegated = true
		}
	}
	if !seenPublished || !seenDelegated {
		t.Fatalf("Pools = %+v, want published and delegated relations", report.Pools)
	}

	var output bytes.Buffer
	if err := writeIPAMMineReport(&output, report); err != nil {
		t.Fatalf("writeIPAMMineReport: %v", err)
	}
	for _, want := range []string{"managed_zone: pek.catofes.", "assignments: 1", "PREFIX", "MODE", "pools: 2", "DELEGATED_TO", "RELATION"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("IPAM mine table missing %q:\n%s", want, output.String())
		}
	}
	if strings.HasPrefix(strings.TrimSpace(output.String()), "{") {
		t.Fatalf("IPAM mine output is still JSON:\n%s", output.String())
	}
}

func TestSharedAssignmentRoundTrip(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)

	if err := assignIPAMWithRuntimeTag(rt, managed, "10.0.1.0/24", "node.pek.catofes.", true, ""); err != nil {
		t.Fatalf("assignIPAM shared failed: %v", err)
	}

	common, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews after assign: %v", err)
	}
	key, err := routing.NormalizeIPAMAssignmentKey("10.0.1.0/24")
	if err != nil {
		t.Fatalf("NormalizeIPAMAssignmentKey: %v", err)
	}
	key += "#node.pek.catofes"
	rec := common.State.Network.Zones[managed].Records[key]
	if rec == nil {
		t.Fatalf("assignment record not found")
	}
	var assignment routing.IPAMAssignmentRecord
	if err := json.Unmarshal(rec.Value, &assignment); err != nil {
		t.Fatalf("unmarshal assignment: %v", err)
	}
	if !assignment.Shared {
		t.Fatalf("expected Shared=true, got false")
	}

	// Revoke and verify Shared flag is preserved in the revocation record.
	if err := revokeIPAMAssignmentWithRuntimeTo(rt, managed, "10.0.1.0/24", ""); err != nil {
		t.Fatalf("revokeIPAMAssignment failed: %v", err)
	}

	common, _, err = loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews after revoke: %v", err)
	}
	rec = common.State.Network.Zones[managed].Records[key]
	if err := json.Unmarshal(rec.Value, &assignment); err != nil {
		t.Fatalf("unmarshal revoke: %v", err)
	}
	if assignment.Active {
		t.Fatalf("expected Active=false after revoke")
	}
	if !assignment.Shared {
		t.Fatalf("expected Shared=true preserved after revoke")
	}
}

func TestSharedAssignmentTagRoundTrip(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	if err := assignIPAMWithRuntimeTag(rt, managed, "10.0.4.0/24", managed, true, "socks5.cn"); err != nil {
		t.Fatalf("assignIPAMWithRuntimeTag: %v", err)
	}
	report, err := buildIPAMMineReport(rt)
	if err != nil {
		t.Fatal(err)
	}
	if len(report.Assignments) != 1 || report.Assignments[0].Tag != "socks5.cn" || !report.Assignments[0].Shared {
		t.Fatalf("assignments = %+v", report.Assignments)
	}
	if err := revokeIPAMAssignmentWithRuntimeTo(rt, managed, "10.0.4.0/24", managed); err != nil {
		t.Fatalf("revoke tagged assignment: %v", err)
	}
}

func TestSortIPAMAssignmentRowsUsesPrefixThenAssignedZone(t *testing.T) {
	rows := []inspect.IPAMAssignmentRow{
		{Prefix: "2001:db8::/32", AssignedTo: "a.example."},
		{Prefix: "10.0.0.0/8", AssignedTo: "z.example."},
		{Prefix: "2.0.0.0/8", AssignedTo: "c.example."},
		{Prefix: "10.0.0.0/8", AssignedTo: "a.example."},
	}
	sortIPAMAssignmentRows(rows)
	want := []string{
		"2.0.0.0/8 c.example.",
		"10.0.0.0/8 a.example.",
		"10.0.0.0/8 z.example.",
		"2001:db8::/32 a.example.",
	}
	for i, row := range rows {
		if got := row.Prefix + " " + row.AssignedTo; got != want[i] {
			t.Fatalf("row %d = %q, want %q (all rows: %+v)", i, got, want[i], rows)
		}
	}
}

func stringSliceContains(values []string, want string) bool {
	return slices.Contains(values, want)
}

func ipamDiagnosticsContain(values []inspect.IPAMGetDiagnosticRow, want string) bool {
	for _, value := range values {
		if value.Code == want {
			return true
		}
	}
	return false
}

func buildIPAMTestRuntime(t *testing.T) (*AppContext, zone.ZonePath) {
	t.Helper()
	return buildIPAMTestRuntimeWithNetwork(t, true, nil)
}

func buildIPAMTestRuntimeWithoutIPAMCapability(t *testing.T) (*AppContext, zone.ZonePath) {
	t.Helper()
	return buildIPAMTestRuntimeWithNetwork(t, false, nil)
}

func buildIPAMTestRuntimeWithNetwork(t *testing.T, ipamCap bool, mutate func(*zone.NetworkState)) (*AppContext, zone.ZonePath) {
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

	perms := []zone.Permission{zone.PermWrite}
	if ipamCap {
		perms = append(perms, zone.PermAllocateIP)
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
	addUnsignedIPAMPoolForTest(ns, parent, "10.0.0.0/16", managed)
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

func addUnsignedIPAMPoolForTest(ns *zone.NetworkState, source zone.ZonePath, prefix string, delegatedTo zone.ZonePath) {
	canonical, err := routing.CanonicalizePrefix(prefix)
	if err != nil {
		panic(err)
	}
	key, err := routing.NormalizeIPAMPoolKey(prefix)
	if err != nil {
		panic(err)
	}
	value, err := json.Marshal(routing.IPAMPoolRecord{Version: 1, Prefix: canonical, DelegatedTo: delegatedTo, Active: true})
	if err != nil {
		panic(err)
	}
	ns.Zones[source].Records[key] = &zone.Record{Zone: source, Key: key, Type: routing.RecordTypeIPAMPool, Value: value}
}

func removeIPAMPoolForTest(ns *zone.NetworkState, source zone.ZonePath, prefix string) {
	key, err := routing.NormalizeIPAMPoolKey(prefix)
	if err != nil {
		panic(err)
	}
	delete(ns.Zones[source].Records, key)
}
