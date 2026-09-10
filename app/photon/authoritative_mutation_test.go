package main

import (
	"context"
	"strings"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

func TestDaemonIPAMMutationUsesCommittedAuthorityNotDifferentDiskState(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	committed, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(committed): %v", err)
	}
	parent := managed.Parent()
	removeIPAMPoolForTest(committed.State.Network, parent, "10.0.0.0/16")

	service := newTestDaemonFromOwners(rt, committed.State, committed.Gossip, runtime, gossipStartupConfigFromAppConfig(rt.Config, committed.State), time.Second)
	beforeRevision := uint64(service.StateStore.common.VerifiedRevision())
	result, syncNow, _ := service.handleEvent(daemonEvent{
		Type: daemonEventIPAMMutation,
		IPAM: &ipamMutationRequest{
			Operation: ipamOperationAssignmentCreate,
			Zone:      managed, Prefix: "10.0.1.0/24", Target: managed,
		},
	})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "ipam_assignment_pool_mismatch") {
		t.Fatalf("IPAM mutation error = %v, want daemon committed pool mismatch", result.Error)
	}
	if syncNow {
		t.Fatal("rejected mutation requested sync")
	}
	if got := uint64(service.StateStore.common.VerifiedRevision()); got != beforeRevision {
		t.Fatalf("revision changed on rejection: before=%d after=%d", beforeRevision, got)
	}
	key, _ := routing.NormalizeIPAMAssignmentKey("10.0.1.0/24")
	after := service.StateStore.common.ReadView()
	if after.State.Network.Zones[managed].Records[key] != nil {
		t.Fatal("rejected assignment entered committed state")
	}
	disk, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(disk): %v", err)
	}
	if disk.State.Network.Zones[managed].Records[key] != nil {
		t.Fatal("rejected assignment entered disk state")
	}
}

func TestDaemonIPAMMutationPersistsCommittedDecisionWhenDiskIsOlder(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	committed, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(committed): %v", err)
	}
	olderDisk, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(older disk): %v", err)
	}
	removeIPAMPoolForTest(olderDisk.State.Network, managed.Parent(), "10.0.0.0/16")
	replacePersistedCommonForTest(t, rt, olderDisk.State)

	service := newTestDaemonFromOwners(rt, committed.State, committed.Gossip, runtime, gossipStartupConfigFromAppConfig(rt.Config, committed.State), time.Second)
	result, _, _ := service.handleEvent(daemonEvent{
		Type: daemonEventIPAMMutation,
		IPAM: &ipamMutationRequest{
			Operation: ipamOperationAssignmentCreate,
			Zone:      managed, Prefix: "10.0.1.0/24", Target: managed,
		},
	})
	if result.Error != nil {
		t.Fatalf("IPAM mutation rejected committed authority: %v", result.Error)
	}
	if result.Version != 1 {
		t.Fatalf("version = %d, want 1", result.Version)
	}
	key, _ := routing.NormalizeIPAMAssignmentKey("10.0.1.0/24")
	committedAfter := service.StateStore.common.ReadView()
	if committedAfter.State.Network.Zones[managed].Records[key] == nil {
		t.Fatal("accepted assignment was not published by the common store")
	}
}

func TestDaemonRouteMutationRejectsUsingCommittedActiveStateNotDisk(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	view, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	state, err := applyAuthoritativeVerifiedTestIntent(view.State, commonIPAMIntentForTest(t, ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      managed, Prefix: "10.0.4.0/24", Target: managed,
	}), rt.Now())
	if err != nil {
		t.Fatalf("apply assignment: %v", err)
	}
	state, err = applyAuthoritativeVerifiedTestIntent(state, commonRouteIntent(routeMutationRequest{
		Zone: managed, Prefix: "10.0.4.0/24", Active: true,
	}), rt.Now())
	if err != nil {
		t.Fatalf("apply active route: %v", err)
	}
	activeDisk := corestate.NewStore(state, nil).ReadView().State
	state, err = applyAuthoritativeVerifiedTestIntent(state, commonRouteIntent(routeMutationRequest{
		Zone: managed, Prefix: "10.0.4.0/24", Active: false,
	}), rt.Now().Add(time.Second))
	if err != nil {
		t.Fatalf("withdraw committed route: %v", err)
	}
	replacePersistedCommonForTest(t, rt, activeDisk)

	service := newTestDaemonFromOwners(rt, state, view.Gossip, runtime, gossipStartupConfigFromAppConfig(rt.Config, state), time.Second)
	beforeRevision := uint64(service.StateStore.common.VerifiedRevision())
	result, _, _ := service.handleEvent(daemonEvent{
		Type:  daemonEventRouteMutation,
		Route: &routeMutationRequest{Zone: managed, Prefix: "10.0.4.0/24", Active: false},
	})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "already withdrawn") {
		t.Fatalf("route mutation error = %v, want committed already-withdrawn rejection", result.Error)
	}
	afterRevision := uint64(service.StateStore.common.VerifiedRevision())
	if afterRevision != beforeRevision || service.ipsecDirty || service.routingDirty || service.firewallDirty {
		t.Fatalf("rejected route changed daemon state: revision %d -> %d dirty=%v/%v/%v", beforeRevision, afterRevision, service.ipsecDirty, service.routingDirty, service.firewallDirty)
	}
	key, _ := routing.NormalizeRouteAnnouncementKey("10.0.4.0/24")
	disk, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(disk): %v", err)
	}
	ann, err := routing.ParseRouteAnnouncementRecord(disk.State.Network.Zones[managed].Records[key])
	if err != nil || !ann.Active {
		t.Fatalf("rejected daemon mutation changed disk active route: ann=%+v err=%v", ann, err)
	}
}

func TestDaemonMutationRejectsUsingCommittedAssignmentsNotDisk(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	committed, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(committed): %v", err)
	}
	disk, err := applyAuthoritativeVerifiedTestIntent(committed.State, commonIPAMIntentForTest(t, ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      managed, Prefix: "10.0.5.0/24", Target: managed,
	}), rt.Now())
	if err != nil {
		t.Fatalf("apply disk assignment: %v", err)
	}
	replacePersistedCommonForTest(t, rt, disk)

	service := newTestDaemonFromOwners(rt, committed.State, committed.Gossip, runtime, gossipStartupConfigFromAppConfig(rt.Config, committed.State), time.Second)
	beforeRevision := uint64(service.StateStore.common.VerifiedRevision())
	result, _, _ := service.handleEvent(daemonEvent{
		Type: daemonEventServiceMutation,
		Service: &serviceMutationRequest{
			Operation: serviceOperationPublish,
			Endpoints: []photonservice.SOCKS5Endpoint{{Region: "test", Address: "10.0.5.10", Port: 1080}},
		},
	})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "service_address_unauthorized") {
		t.Fatalf("service mutation error = %v, want committed assignment rejection", result.Error)
	}
	afterRevision := uint64(service.StateStore.common.VerifiedRevision())
	if afterRevision != beforeRevision || service.ipsecDirty || service.routingDirty || service.firewallDirty {
		t.Fatalf("rejected service changed daemon state: revision %d -> %d dirty=%v/%v/%v", beforeRevision, afterRevision, service.ipsecDirty, service.routingDirty, service.firewallDirty)
	}
	key, _ := photonservice.RecordKey(socks5RecordName)
	reloaded, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews(disk): %v", err)
	}
	if reloaded.State.Network.Zones[managed].Records[key] != nil {
		t.Fatal("rejected service mutation entered disk state")
	}
}

func TestDaemonTypedDryRunDoesNotCommit(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	view, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	service := newTestDaemonFromOwners(rt, view.State, view.Gossip, runtime, gossipStartupConfigFromAppConfig(rt.Config, view.State), time.Second)
	before := uint64(service.StateStore.common.VerifiedRevision())
	result, syncNow, _ := service.handleEvent(daemonEvent{
		Type: daemonEventIPAMMutation,
		IPAM: &ipamMutationRequest{
			Operation: ipamOperationAssignmentCreate,
			Zone:      managed, Prefix: "10.0.2.0/24", Target: managed, DryRun: true,
		},
	})
	if result.Error != nil {
		t.Fatalf("dry-run mutation: %v", result.Error)
	}
	if syncNow {
		t.Fatal("dry-run requested sync")
	}
	if got := uint64(service.StateStore.common.VerifiedRevision()); got != before {
		t.Fatalf("dry-run revision changed: before=%d after=%d", before, got)
	}
	key, _ := routing.NormalizeIPAMAssignmentKey("10.0.2.0/24")
	after := service.StateStore.common.ReadView()
	if after.State.Network.Zones[managed].Records[key] != nil {
		t.Fatal("dry-run record entered committed state")
	}
}

func TestExplicitDirectAndDaemonIPAMUseSameDomainValidation(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	view, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	removeIPAMPoolForTest(view.State.Network, managed.Parent(), "10.0.0.0/16")
	request := ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      managed, Prefix: "10.0.3.0/24", Target: zone.ZonePath(managed),
	}
	_, directErr := applyAuthoritativeVerifiedTestIntent(view.State, commonIPAMIntentForTest(t, request), rt.Now())
	service := newTestDaemonFromOwners(rt, view.State, view.Gossip, runtime, gossipStartupConfigFromAppConfig(rt.Config, view.State), time.Second)
	result, _, _ := service.handleEvent(daemonEvent{Type: daemonEventIPAMMutation, IPAM: &request})
	if directErr == nil || result.Error == nil {
		t.Fatalf("validation results direct=%v daemon=%v, want both rejected", directErr, result.Error)
	}
	if directErr.Error() != result.Error.Error() {
		t.Fatalf("validation diverged: direct=%q daemon=%q", directErr, result.Error)
	}
}

func commonIPAMIntentForTest(t *testing.T, request ipamMutationRequest) corestate.LocalIntent {
	t.Helper()
	intent, err := commonIPAMIntent(request)
	if err != nil {
		t.Fatalf("commonIPAMIntent: %v", err)
	}
	return intent
}

func applyAuthoritativeVerifiedTestIntent(state *corestate.VerifiedState, intent corestate.LocalIntent, now time.Time) (*corestate.VerifiedState, error) {
	store := corestate.NewStore(state, nil)
	if _, err := store.ApplyLocalIntent(context.Background(), intent, now); err != nil {
		return nil, err
	}
	return store.ReadView().State, nil
}

func applyAuthoritativeTestIntentAs(state *corestate.VerifiedState, managedZone zone.ZonePath, privateKey []byte, intent corestate.LocalIntent, now time.Time) error {
	store := corestate.NewStoreWithCheckpoint(&corestate.VerifiedState{
		ManagedZone:          managedZone,
		Network:              state.Network,
		TrustedRootPublicKey: append([]byte(nil), state.Network.Zones[zone.RootZone].Authority.Keys[0].Key...),
		RootPrivateKey:       append([]byte(nil), state.RootPrivateKey...),
		IdentityPrivateKey:   append([]byte(nil), privateKey...),
	}, nil, nil)
	if _, err := store.ApplyLocalIntent(context.Background(), intent, now); err != nil {
		return err
	}
	state.Network = store.ReadView().State.Network
	return nil
}

// replacePersistedCommonForTest intentionally makes the detached disk owner
// differ from a daemon's in-memory common owner. These tests exercise that
// conflict boundary, so write the current common schema instead of reviving
// the legacy aggregate buckets.
func replacePersistedCommonForTest(t *testing.T, rt *AppContext, verified *corestate.VerifiedState) {
	t.Helper()
	store, err := corestate.OpenBoltStore(rt.StatePath, 0o600, daemonBoltLockTimeout)
	if err != nil {
		t.Fatalf("OpenBoltStore: %v", err)
	}
	defer store.Close()
	candidate, revision, _, found, err := store.LoadCommon()
	if err != nil || !found {
		t.Fatalf("LoadCommon = found %v err %v", found, err)
	}
	verified = corestate.NewStore(verified, nil).ReadView().State
	verified.TrustedRootPublicKey = append([]byte(nil), candidate.Verified.TrustedRootPublicKey...)
	if err := store.CommitCommon(context.Background(), &corestate.CommitCandidate{
		Verified: verified,
		Gossip:   candidate.Gossip,
	}, corestate.ChangeSet{VerifiedRevision: revision + 1, NetworkChanged: true}); err != nil {
		t.Fatalf("CommitCommon: %v", err)
	}
}

func TestUnavailableMutationControlFailsClosedWithoutDiskWrite(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	rt.DisableControl = false
	t.Setenv("PHOTON_CONTROL_SOCKET", rt.StatePath+".missing.sock")
	request := ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      managed, Prefix: "10.0.9.0/24", Target: managed,
	}
	if _, controlled, err := mutateIPAMViaControl(rt, request); err == nil || !controlled {
		t.Fatalf("mutateIPAMViaControl controlled/error = %t/%v, want fail-closed control error", controlled, err)
	}
	key, _ := routing.NormalizeIPAMAssignmentKey(request.Prefix)
	view, _, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	if view.State.Network.Zones[managed].Records[key] != nil {
		t.Fatal("socket-unavailable mutation wrote the local DB")
	}
}

func TestTypedIPAMControlMethodCommitsDaemonValidatedRequest(t *testing.T) {
	rt, managed := buildIPAMTestRuntime(t)
	view, runtime, err := loadOfflineOwnerViews(rt)
	if err != nil {
		t.Fatalf("loadOfflineOwnerViews: %v", err)
	}
	service := newTestDaemonFromOwners(rt, view.State, view.Gossip, runtime, gossipStartupConfigFromAppConfig(rt.Config, view.State), time.Second)
	ctx := t.Context()
	go pumpDaemonEvents(ctx, service)

	response := controlRequestViaPipe(t, service, controlRequest{
		Method: "ipam_mutate",
		IPAM: &ipamMutationRequest{
			Operation: ipamOperationAssignmentCreate,
			Zone:      managed, Prefix: "10.0.8.0/24", Target: managed,
		},
	})
	if !response.OK || response.Version != 1 {
		t.Fatalf("ipam_mutate response = %+v", response)
	}
	key, _ := routing.NormalizeIPAMAssignmentKey("10.0.8.0/24")
	committed := service.StateStore.common.ReadView()
	if committed.State.Network.Zones[managed].Records[key] == nil {
		t.Fatal("typed control mutation did not enter committed state")
	}
}

func TestDaemonRawRecordPutRejectsReservedNamespaceWithoutRevision(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	service := newTestDaemonFromOwners(
		&AppContext{Config: defaultAppConfig(), Clock: time.Now}, verified, checkpoint, runtime, config, time.Second,
	)
	before := uint64(service.StateStore.common.VerifiedRevision())
	result, syncNow, _ := service.handleEvent(daemonEvent{
		Type: daemonEventRecordPut,
		RecordPut: &daemonRecordPut{
			Zone: zone.ZonePath("node-b.catofes."),
			Key:  routing.RecordKeyPrefixRoutes + "10.0.0.0_24",
			Type: "application.fake",
		},
	})
	if result.Error == nil || !strings.Contains(result.Error.Error(), "daemon-owned") {
		t.Fatalf("reserved record_put error = %v", result.Error)
	}
	if syncNow {
		t.Fatal("rejected raw record requested sync")
	}
	if got := uint64(service.StateStore.common.VerifiedRevision()); got != before {
		t.Fatalf("revision changed on reserved raw record: before=%d after=%d", before, got)
	}
}
