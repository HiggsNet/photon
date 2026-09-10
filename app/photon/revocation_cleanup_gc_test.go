package main

import (
	"context"
	"slices"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func addRevocationTombstoneForTest(t *testing.T, network *zone.NetworkState, child, parent zone.ZonePath) {
	t.Helper()
	parentState := network.Zones[parent]
	if parentState == nil {
		t.Fatalf("parent zone not found: %s", parent)
	}
	if parentState.Revocations == nil {
		parentState.Revocations = make(map[zone.ZonePath]*zone.DelegationRevocation)
	}
	parentState.Revocations[child] = &zone.DelegationRevocation{
		ChildZone: child, ParentZone: parent, RevokedAuthorityEpoch: 1, RevokedAt: 100,
	}
	delete(parentState.Delegations, child)
}

func TestDaemonPurgeDryRunMergesCommonAndLinuxRuntimePlan(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	now := time.Unix(123, 0)
	verified.Network.Zones["leaf.node-b.catofes."] = zone.NewZoneState("leaf.node-b.catofes.", nil)
	addRevocationTombstoneForTest(t, verified.Network, "node-b.catofes.", "catofes.")
	observationLinks := map[string]linkInstanceState{
		"link-b":     {ID: "link-b", PeerZone: "node-b.catofes."},
		"link-leaf":  {ID: "link-leaf", PeerZone: "leaf.node-b.catofes."},
		"link-other": {ID: "link-other", PeerZone: "node-c.catofes."},
	}
	checkpoint.Peers = map[string]corestate.PeerCheckpoint{
		"node-b.catofes.": {FailureCount: 1}, "leaf.node-b.catofes.": {FailureCount: 1}, "node-c.catofes.": {FailureCount: 1},
	}
	service := newTestDaemonFromOwners(
		&AppContext{Clock: func() time.Time { return now }}, verified, checkpoint, runtime, config, defaultDaemonInterval,
	)
	setTestIPsecObservation(service, observationLinks, nil)

	plan, err := service.handleRecoveryPurgeRevokedEvent(context.Background(), "", false)
	if err != nil {
		t.Fatalf("handleRecoveryPurgeRevokedEvent(dry-run): %v", err)
	}
	if !slices.Equal(plan.Zones, []zone.ZonePath{"leaf.node-b.catofes.", "node-b.catofes."}) ||
		!slices.Equal(plan.LinkInstances, []string{"link-b", "link-leaf"}) ||
		!slices.Equal(plan.SyncPeers, []string{"leaf.node-b.catofes.", "node-b.catofes."}) {
		t.Fatalf("merged purge plan = %+v", plan)
	}
	common := service.StateStore.common.ReadView()
	currentLinks, _ := readTestIPsecObservation(service)
	if common.State.Network.Zones["node-b.catofes."] == nil || currentLinks["link-b"].ID == "" {
		t.Fatal("dry-run mutated common or Linux runtime state")
	}
}
