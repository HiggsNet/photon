package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"slices"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

func TestStoreApplyLocalRecordIntentVersionsAndRetainsNoPointers(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, identityPrivate, _ := managedAuthorityFixture(t, true)
	commitSink := &memoryCommitSink{}
	store := NewStore(&VerifiedState{ManagedZone: "node-a.catofes.", Network: network, IdentityPrivateKey: identityPrivate}, commitSink.Commit)
	value := []byte("v1")
	first, err := store.ApplyLocalIntent(context.Background(), PutRecordIntent{
		Zone: "node-a.catofes.", Key: "config", Type: "text", Value: value,
	}, now)
	if err != nil {
		t.Fatalf("ApplyLocalIntent(v1): %v", err)
	}
	if !first.Committed || first.Record == nil || first.Record.Version != 1 || first.Changes.SecurityPriority {
		t.Fatalf("first result = %+v", first)
	}
	value[0] = 'X'
	first.Record.Value[0] = 'Y'

	second, err := store.ApplyLocalIntent(context.Background(), PutRecordIntent{
		Zone: "node-a.catofes.", Key: "config", Type: "text", Value: []byte("v2"),
	}, now.Add(time.Second))
	if err != nil {
		t.Fatalf("ApplyLocalIntent(v2): %v", err)
	}
	if second.Record.Version != 2 {
		t.Fatalf("second version = %d, want 2", second.Record.Version)
	}
	view := store.ReadView()
	managed := view.State.Network.Zones["node-a.catofes."]
	if string(managed.Records["config"].Value) != "v2" || len(managed.RecordHistory["config"]) != 1 || string(managed.RecordHistory["config"][0].Value) != "v1" {
		t.Fatalf("record/history = %#v/%#v", managed.Records["config"], managed.RecordHistory["config"])
	}
	if commitSink.commits != 2 || view.Revision != 2 {
		t.Fatalf("commits/revision = %d/%d", commitSink.commits, view.Revision)
	}
	if !bytes.Equal(commitSink.state.Verified.IdentityPrivateKey, identityPrivate) || !bytes.Equal(view.State.IdentityPrivateKey, identityPrivate) {
		t.Fatal("raw identity private key was not retained in commitSink/read state")
	}
	view.State.IdentityPrivateKey[0] ^= 0xff
	if !bytes.Equal(store.ReadView().State.IdentityPrivateKey, identityPrivate) {
		t.Fatal("read view private key was not detached")
	}
}

func TestStoreApplyLocalIntentsCommitsOnceAndRollsBackAsBatch(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, identityPrivate, _ := managedAuthorityFixture(t, true)
	sink := &memoryCommitSink{}
	store := NewStore(&VerifiedState{ManagedZone: "node-a.catofes.", Network: network, IdentityPrivateKey: identityPrivate}, sink.Commit)

	batch, err := store.ApplyLocalIntents(context.Background(), []LocalIntent{
		PutRecordIntent{Zone: "node-a.catofes.", Key: "endpoint-a", Type: "text", Value: []byte("a")},
		PutRecordIntent{Zone: "node-a.catofes.", Key: "endpoint-b", Type: "text", Value: []byte("b")},
	}, now)
	if err != nil {
		t.Fatalf("ApplyLocalIntents: %v", err)
	}
	if !batch.Committed || batch.Changes.VerifiedRevision != 1 || sink.commits != 1 || len(batch.Results) != 2 {
		t.Fatalf("batch = %+v commits=%d", batch, sink.commits)
	}

	_, err = store.ApplyLocalIntents(context.Background(), []LocalIntent{
		PutRecordIntent{Zone: "node-a.catofes.", Key: "would-rollback", Type: "text", Value: []byte("x")},
		PutRecordIntent{Zone: "node-a.catofes.", Key: "sync/endpoint/udp", Type: "text", Value: []byte("reserved")},
	}, now.Add(time.Second))
	if !errors.Is(err, ErrReservedRecordIntent) {
		t.Fatalf("failed batch error = %v, want ErrReservedRecordIntent", err)
	}
	view := store.ReadView()
	if view.Revision != 1 || sink.commits != 1 || view.State.Network.Zones["node-a.catofes."].Records["would-rollback"] != nil {
		t.Fatalf("failed batch published: revision=%d commits=%d", view.Revision, sink.commits)
	}
}

func TestStoreApplyLocalIntentsAtRevisionRejectsStalePlan(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, identityPrivate, _ := managedAuthorityFixture(t, true)
	sink := &memoryCommitSink{}
	store := NewStore(&VerifiedState{ManagedZone: "node-a.catofes.", Network: network, IdentityPrivateKey: identityPrivate}, sink.Commit)
	if _, err := store.ApplyLocalIntent(context.Background(), PutRecordIntent{
		Zone: "node-a.catofes.", Key: "current", Type: "text", Value: []byte("current"),
	}, now); err != nil {
		t.Fatal(err)
	}

	_, err := store.ApplyLocalIntentsAtRevision(context.Background(), []LocalIntent{PutRecordIntent{
		Zone: "node-a.catofes.", Key: "stale", Type: "text", Value: []byte("stale"),
	}}, now, 0)
	if !errors.Is(err, ErrVerifiedRevisionStale) {
		t.Fatalf("stale plan error = %v, want ErrVerifiedRevisionStale", err)
	}
	view := store.ReadView()
	if view.Revision != 1 || view.State.Network.Zones["node-a.catofes."].Records["stale"] != nil || sink.commits != 1 {
		t.Fatalf("stale plan changed state: revision=%d commits=%d", view.Revision, sink.commits)
	}
}

func TestStoreProtocolRecordIntentValidatesTupleAndNoop(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, identityPrivate, _ := managedAuthorityFixture(t, true)
	store := NewStore(&VerifiedState{ManagedZone: "node-a.catofes.", Network: network, IdentityPrivateKey: identityPrivate}, nil)
	intent := PutProtocolRecordIntent{
		Kind: ProtocolRecordGossipEndpoint, Zone: "node-a.catofes.", Key: "sync/endpoint/udp", Type: "sync.endpoint", Value: []byte(`{"endpoints":[]}`),
	}
	first, err := store.ApplyLocalIntent(context.Background(), intent, now)
	if err != nil || !first.Committed || first.Record == nil {
		t.Fatalf("first protocol intent = %+v, %v", first, err)
	}
	second, err := store.ApplyLocalIntent(context.Background(), intent, now.Add(time.Second))
	if err != nil || second.Committed || second.Record == nil || second.Record.Version != first.Record.Version {
		t.Fatalf("protocol no-op = %+v, %v", second, err)
	}
	invalid := intent
	invalid.Type = "text"
	if _, err := store.ApplyLocalIntent(context.Background(), invalid, now); err == nil {
		t.Fatal("invalid protocol key/type tuple was accepted")
	}
	if view := store.ReadView(); view.Revision != 1 {
		t.Fatalf("no-op/invalid tuple advanced revision to %d", view.Revision)
	}
}

func TestStoreApplyLocalIntentRejectsMissingAndUnauthorizedKey(t *testing.T) {
	network, _, _, _ := managedAuthorityFixture(t, true)
	store := NewStore(&VerifiedState{Network: network}, nil)
	intent := PutRecordIntent{Zone: "node-a.catofes.", Key: "config", Type: "text", Value: []byte("value")}
	if _, err := store.ApplyLocalIntent(context.Background(), intent, time.Unix(1000, 0)); err == nil {
		t.Fatal("missing private key was accepted")
	}
	_, otherPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(other): %v", err)
	}
	store = NewStore(&VerifiedState{Network: network, IdentityPrivateKey: otherPrivate}, nil)
	if _, err := store.ApplyLocalIntent(context.Background(), intent, time.Unix(1000, 0)); err == nil {
		t.Fatal("unauthorized signer was accepted")
	}
	if view := store.ReadView(); view.Revision != 0 || view.State.Network.Zones["node-a.catofes."].Records["config"] != nil {
		t.Fatalf("failed signing published state: %+v", view)
	}
}

func TestStoreApplyLocalDelegationThenRevocationCleansPeerCheckpoint(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, _, parentPrivate := managedAuthorityFixture(t, true)
	childPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}
	childAuthority := &zone.ZoneAuthority{Zone: "new.catofes.", Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{
		Key: childPublic, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}},
	}}}
	store := NewStoreWithCheckpoint(&VerifiedState{Network: network, ManagedZone: "catofes.", IdentityPrivateKey: parentPrivate}, &GossipCheckpoint{Peers: map[string]PeerCheckpoint{
		"new.catofes.":      {LastSyncUnix: 1},
		"leaf.new.catofes.": {LastSyncUnix: 1},
		"other.catofes.":    {LastSyncUnix: 1},
	}}, nil)
	issued, err := store.ApplyLocalIntent(context.Background(), PutDelegationIntent{Parent: "catofes.", Authority: childAuthority}, now)
	if err != nil {
		t.Fatalf("PutDelegation: %v", err)
	}
	if issued.Delegation == nil || issued.Changes.SecurityPriority {
		t.Fatalf("issued result = %+v", issued)
	}
	if !slices.Equal(issued.Changes.ChangedZones, []zone.ZonePath{"catofes.", "new.catofes."}) {
		t.Fatalf("issued changed zones = %v, want parent and child", issued.Changes.ChangedZones)
	}
	issuedView := store.ReadView()
	if child := issuedView.State.Network.Zones["new.catofes."]; child == nil || child.Authority == nil || child.Authority.Epoch != 1 {
		t.Fatalf("issued child authority = %+v, want installed epoch 1", child)
	}
	revoked, err := store.ApplyLocalIntent(context.Background(), RevokeDelegationIntent{
		Parent: "catofes.", Child: "new.catofes.", Reason: "compromised",
	}, now.Add(time.Second))
	if err != nil {
		t.Fatalf("RevokeDelegation: %v", err)
	}
	if revoked.Revocation == nil || !revoked.Changes.SecurityPriority || !revoked.Changes.GossipCheckpointChanged {
		t.Fatalf("revoked result = %+v", revoked)
	}
	view := store.ReadView()
	parent := view.State.Network.Zones["catofes."]
	if parent.Delegations["new.catofes."] != nil || parent.Revocations["new.catofes."] == nil {
		t.Fatalf("parent delegation/revocation = %#v/%#v", parent.Delegations["new.catofes."], parent.Revocations["new.catofes."])
	}
	if _, ok := view.Gossip.Peers["new.catofes."]; ok {
		t.Fatal("revoked peer metadata retained")
	}
	if _, ok := view.Gossip.Peers["leaf.new.catofes."]; ok {
		t.Fatal("revoked descendant metadata retained")
	}
	if _, ok := view.Gossip.Peers["other.catofes."]; !ok {
		t.Fatal("unrelated peer metadata removed")
	}
	if view.Revision != 2 {
		t.Fatalf("verified revision = %d, want 2", view.Revision)
	}
}

func TestStoreApplyLocalDelegationRefreshPreservesChildContent(t *testing.T) {
	now := time.Unix(1000, 0)
	network, _, _, parentPrivate := managedAuthorityFixture(t, true)
	childPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("GenerateKey(child): %v", err)
	}
	child := "new.catofes."
	authorityV1 := &zone.ZoneAuthority{Zone: zone.ZonePath(child), Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{
		Key: childPublic, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}},
	}}}
	store := NewStore(&VerifiedState{Network: network, ManagedZone: "catofes.", IdentityPrivateKey: parentPrivate}, nil)
	if _, err := store.ApplyLocalIntent(context.Background(), PutDelegationIntent{Parent: "catofes.", Authority: authorityV1}, now); err != nil {
		t.Fatalf("PutDelegation(v1): %v", err)
	}

	store.mu.Lock()
	store.state.Network.Zones[zone.ZonePath(child)].Records["identity"] = &zone.Record{Zone: zone.ZonePath(child), Key: "identity", Version: 1}
	store.state.Network.Zones[zone.ZonePath(child)].RecordHistory["identity"] = []*zone.Record{{Zone: zone.ZonePath(child), Key: "identity", Version: 0}}
	store.mu.Unlock()
	authorityV2 := cloneAuthority(authorityV1)
	authorityV2.Epoch = 2
	if _, err := store.ApplyLocalIntent(context.Background(), PutDelegationIntent{Parent: "catofes.", Authority: authorityV2}, now.Add(time.Second)); err != nil {
		t.Fatalf("PutDelegation(v2): %v", err)
	}

	view := store.ReadView()
	got := view.State.Network.Zones[zone.ZonePath(child)]
	if got == nil || got.Authority == nil || got.Authority.Epoch != 2 {
		t.Fatalf("refreshed child authority = %+v, want epoch 2", got)
	}
	if got.Records["identity"] == nil || len(got.RecordHistory["identity"]) != 1 {
		t.Fatalf("child content was not preserved: records=%+v history=%+v", got.Records, got.RecordHistory)
	}
}

func TestStoreApplyLocalIntentPersistenceFailureDoesNotPublish(t *testing.T) {
	network, _, identityPrivate, _ := managedAuthorityFixture(t, true)
	wantErr := errors.New("local commit failed")
	commitSink := &memoryCommitSink{err: wantErr}
	store := NewStore(&VerifiedState{Network: network, IdentityPrivateKey: identityPrivate}, commitSink.Commit)
	_, err := store.ApplyLocalIntent(context.Background(), PutRecordIntent{
		Zone: "node-a.catofes.", Key: "config", Type: "text", Value: []byte("value"),
	}, time.Unix(1000, 0))
	if !errors.Is(err, wantErr) {
		t.Fatalf("ApplyLocalIntent error = %v, want %v", err, wantErr)
	}
	view := store.ReadView()
	if view.Revision != 0 || view.State.Network.Zones["node-a.catofes."].Records["config"] != nil {
		t.Fatalf("commitSink failure published local intent: %+v", view)
	}
}

func TestStoreRejectsLocalRootAuthorityUpdate(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	ns := zone.NewNetworkState()
	ns.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, photoncrypto.ConfiguredRootAuthority(pub))
	store := NewStore(&VerifiedState{ManagedZone: zone.RootZone, Network: ns, TrustedRootPublicKey: pub, RootPrivateKey: priv}, nil)
	next := cloneAuthority(ns.Zones[zone.RootZone].Authority)
	next.Epoch++
	if _, err := store.ApplyLocalIntent(context.Background(), UpdateRootAuthorityIntent{Authority: next}, time.Now()); err == nil {
		t.Fatal("root update accepted")
	}
	if got := store.ReadView(); got.Revision != 0 || got.State.Network.Zones[zone.RootZone].Authority.Epoch != 1 {
		t.Fatal("rejected update changed root")
	}
}
