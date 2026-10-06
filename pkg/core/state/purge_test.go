package state

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestStorePurgeRevokedDeletesCommonStateAndKeepsTombstone(t *testing.T) {
	now := time.Unix(1000, 0)
	install, _ := identityInstallFixture(t)
	network := zone.CloneNetworkState(install.Network)
	network.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nil)
	network.Zones["leaf.node-b.catofes."] = zone.NewZoneState("leaf.node-b.catofes.", nil)
	parent := network.Zones["catofes."]
	parent.Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone: "node-b.catofes.", ParentZone: "catofes.", RevokedAuthorityEpoch: 1, RevokedAt: now.Unix(),
	}
	delete(parent.Delegations, "node-b.catofes.")
	sink := &memoryCommitSink{}
	store := NewStoreWithCheckpoint(&VerifiedState{
		ManagedZone:          install.ManagedZone,
		Network:              network,
		TrustedRootPublicKey: install.TrustedRootPublicKey,
		IdentityPrivateKey:   install.IdentityPrivateKey,
	}, &GossipCheckpoint{Peers: map[string]PeerCheckpoint{
		"node-b.catofes.":      {FailureCount: 1},
		"leaf.node-b.catofes.": {FailureCount: 2},
		"node-c.catofes.":      {FailureCount: 3},
	}}, sink.Commit, sink.CommitCheckpoints)

	plan, err := store.PlanPurgeRevoked(now, "node-b.catofes.")
	if err != nil {
		t.Fatalf("PlanPurgeRevoked: %v", err)
	}
	wantZones := []zone.ZonePath{"leaf.node-b.catofes.", "node-b.catofes."}
	wantPeers := []string{"leaf.node-b.catofes.", "node-b.catofes."}
	if !slices.Equal(plan.Zones, wantZones) || !slices.Equal(plan.CheckpointPeers, wantPeers) {
		t.Fatalf("plan = %+v, want zones %v peers %v", plan, wantZones, wantPeers)
	}
	result, err := store.PurgeRevoked(context.Background(), now, "node-b.catofes.")
	if err != nil {
		t.Fatalf("PurgeRevoked: %v", err)
	}
	if !result.Committed || result.Changes.VerifiedRevision != 1 || !result.Changes.NetworkChanged ||
		!result.Changes.GossipCheckpointChanged || !result.Changes.SecurityPriority || !slices.Equal(result.Changes.ChangedZones, wantZones) {
		t.Fatalf("result = %+v", result)
	}
	view := store.ReadView()
	if view.State.Network.Zones["node-b.catofes."] != nil || view.State.Network.Zones["leaf.node-b.catofes."] != nil ||
		view.Gossip.Peers["node-b.catofes."].FailureCount != 0 || view.Gossip.Peers["leaf.node-b.catofes."].FailureCount != 0 ||
		view.Gossip.Peers["node-c.catofes."].FailureCount != 3 || view.State.Network.Zones["catofes."].Revocations["node-b.catofes."] == nil {
		t.Fatalf("purged view = %+v", view)
	}
}

func TestStorePurgeRevokedRefusesManagedIdentity(t *testing.T) {
	now := time.Unix(1000, 0)
	install, _ := identityInstallFixture(t)
	parent := install.Network.Zones["catofes."]
	parent.Revocations[install.ManagedZone] = &zone.DelegationRevocation{
		ChildZone: install.ManagedZone, ParentZone: "catofes.", RevokedAuthorityEpoch: 1, RevokedAt: now.Unix(),
	}
	delete(parent.Delegations, install.ManagedZone)
	store := NewStore(&VerifiedState{ManagedZone: install.ManagedZone, Network: install.Network}, nil, nil)
	if _, err := store.PurgeRevoked(context.Background(), now, install.ManagedZone); err == nil {
		t.Fatal("PurgeRevoked accepted the managed identity zone")
	}
	if store.ReadView().State.Network.Zones[install.ManagedZone] == nil {
		t.Fatal("rejected purge removed managed identity")
	}
}

func TestStorePurgeRevokedPersistenceFailureDoesNotPublish(t *testing.T) {
	now := time.Unix(1000, 0)
	install, _ := identityInstallFixture(t)
	network := zone.CloneNetworkState(install.Network)
	network.Zones["node-b.catofes."] = zone.NewZoneState("node-b.catofes.", nil)
	network.Zones["catofes."].Revocations["node-b.catofes."] = &zone.DelegationRevocation{
		ChildZone: "node-b.catofes.", ParentZone: "catofes.", RevokedAt: now.Unix(),
	}
	wantErr := errors.New("disk unavailable")
	store := NewStore(&VerifiedState{ManagedZone: install.ManagedZone, Network: network}, (&memoryCommitSink{err: wantErr}).Commit, (&memoryCommitSink{err: wantErr}).CommitCheckpoints)
	if _, err := store.PurgeRevoked(context.Background(), now, "node-b.catofes."); !errors.Is(err, wantErr) {
		t.Fatalf("PurgeRevoked error = %v, want %v", err, wantErr)
	}
	view := store.ReadView()
	if view.Revision != 0 || view.State.Network.Zones["node-b.catofes."] == nil {
		t.Fatalf("persistence failure published purge: %+v", view)
	}
}
