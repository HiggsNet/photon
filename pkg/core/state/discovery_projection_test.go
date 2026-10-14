package state

import (
	"context"
	"fmt"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func TestDiscoveryProjectionPreservesChainAndTimeChecks(t *testing.T) {
	network, _, _, _ := managedAuthorityFixture(t, true)
	path := zone.ZonePath("node-a.catofes.")
	// Verification must still accept the stored parent-proof fallback, and
	// reject it when the signing root key expires without a state revision.
	delete(network.Zones["catofes."].Delegations, path)
	network.Zones[zone.RootZone].Authority.Keys[0].NotAfter = 200
	store := NewStore(&VerifiedState{ManagedZone: "local.catofes.", Network: network}, nil, nil)
	for _, now := range []time.Time{time.Unix(100, 0), time.Unix(201, 0)} {
		for _, peerID := range []string{"", path.String()} {
			got := store.ReadDiscovery(peerID)
			err := photoncrypto.VerifyChain(got.Network, path, now)
			want := photoncrypto.VerifyChain(network, path, now)
			if fmt.Sprint(err) != fmt.Sprint(want) || (now.Unix() == 100 && err != nil) || (now.Unix() == 201 && err == nil) {
				t.Fatalf("projection chain at %v = %v, full network = %v", now, err, want)
			}
		}
	}
}

func TestScopedDiscoveryRetainsSignedAncestorRevocations(t *testing.T) {
	network, _, _, parentPrivate := managedAuthorityFixture(t, true)
	path := zone.ZonePath("node-a.catofes.")
	revocation := &zone.DelegationRevocation{ParentZone: "catofes.", ChildZone: path,
		RevokedAuthorityEpoch: 1, RevokedAuthorityHash: photoncrypto.AuthorityHash(network.Zones[path].Authority), RevokedAt: 150}
	if err := photoncrypto.SignDelegationRevocation(revocation, "catofes.", parentPrivate); err != nil {
		t.Fatal(err)
	}
	network.Zones["catofes."].Revocations[path] = revocation
	store := NewStore(&VerifiedState{Network: network}, nil, nil)
	for _, selected := range []zone.ZonePath{path, "child.node-a.catofes."} {
		view := store.ReadDiscovery(selected.String())
		for _, at := range []int64{149, 150} {
			now := time.Unix(at, 0)
			if got := view.Network.IsZoneRevoked(selected, now); got != network.IsZoneRevoked(selected, now) || got != (at == 150) {
				t.Fatalf("ancestor revocation at %d = %v", at, got)
			}
		}
	}
	view := store.ReadDiscovery(path.String())
	if err := photoncrypto.VerifyChain(view.Network, path, time.Unix(150, 0)); err != zone.ErrZoneRevoked {
		t.Fatalf("signed revocation was not retained for chain verification: %v", err)
	}
	view.Network.Zones["catofes."].Revocations[path].Signature[0] ^= 0xff
	if err := photoncrypto.VerifyChain(view.Network, path, time.Unix(150, 0)); err == nil || err == zone.ErrZoneRevoked {
		t.Fatalf("tampered revocation signature was not reverified: %v", err)
	}
}

func TestReadDiscoveryRetainsDigestsAndDetachesCurrentState(t *testing.T) {
	candidate := checkpointBenchmarkCandidate()
	path := zone.ZonePath("node-0.catofes.")
	network := candidate.Verified.Network
	network.Zones["catofes."] = zone.NewZoneState("catofes.", &zone.ZoneAuthority{Zone: "catofes.", Epoch: 1})
	network.Zones["catofes."].Delegations[path] = &zone.Delegation{ZoneName: path, Signature: []byte("delegation")}
	network.Zones[path].ParentProof = []*zone.Delegation{{ZoneName: path, Signature: []byte("proof")}}
	network.Zones[path].Authority.Keys = []zone.AuthorizedKey{{Key: []byte("public"), Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}}}}
	network.Zones[path].Revocations["child.node-0.catofes."] = &zone.DelegationRevocation{Signature: []byte("revocation")}
	network.GlobalRoot = []byte("root")
	candidate.Gossip.Peers[path.String()] = PeerCheckpoint{
		ObservedGraceEndpoints: []ObservedGraceEndpoint{{Endpoint: "192.0.2.1:33434"}},
		LastFailure:            &PeerFailure{Message: "failure"},
		RejectedObjects:        map[zone.ZonePath]RejectedObject{path: {RootHash: []byte("rejected")}},
	}
	store := NewStoreWithCheckpoint(candidate.Verified, candidate.Gossip, nil, nil)
	before := store.ReadView()
	all := store.ReadDiscovery("")
	if !reflect.DeepEqual(ZoneDigests(all.Network), store.ReadCatalog().Digests) {
		t.Fatal("discovery without history changed current catalog digests")
	}
	for _, zs := range all.Network.Zones {
		if zs.RecordHistory != nil {
			t.Fatal("discovery retained record history")
		}
	}
	peer := store.ReadDiscovery(path.String())
	if len(peer.Network.Zones) != 3 || len(peer.Peers) != 1 || len(peer.Network.Zones[path].Records) != 10 {
		t.Fatalf("scoped discovery copied unrelated data: zones=%d peers=%d", len(peer.Network.Zones), len(peer.Peers))
	}
	if peer.Network.Zones["catofes."].Records != nil {
		t.Fatal("ancestor records are not needed to verify the peer chain")
	}
	peer.Network.GlobalRoot[0] ^= 0xff
	zs := peer.Network.Zones[path]
	zs.Authority.Keys[0].Key[0] ^= 0xff
	zs.Authority.Keys[0].Capabilities[0].Permissions[0] = zone.PermDelegate
	zs.ParentProof[0].Signature[0] ^= 0xff
	zs.Records["record-0"].Value[0] ^= 0xff
	zs.Revocations["child.node-0.catofes."].Signature[0] ^= 0xff
	peer.Network.Zones["catofes."].Delegations[path].Signature[0] ^= 0xff
	cp := peer.Peers[path.String()]
	cp.LastFailure.Message = "changed"
	cp.ObservedGraceEndpoints[0].Endpoint = "changed"
	cp.RejectedObjects[path].RootHash[0] ^= 0xff
	delete(peer.Peers, path.String())
	all.Network.Zones[path].Records["record-1"].Value[0] ^= 0xff
	if !reflect.DeepEqual(before, store.ReadView()) {
		t.Fatal("a retained projection mutation reached committed state")
	}
	if unknown := store.ReadDiscovery("missing.catofes."); unknown.Network.Zones["missing.catofes."] != nil || len(unknown.Peers) != 0 {
		t.Fatal("projection invented a missing peer")
	}
}

func TestStoreObjectReadsPreserveHistoryAndFutureRevocation(t *testing.T) {
	path := zone.ZonePath("node-a.catofes.")
	candidate := commonBoltTestCandidate(1)
	network := candidate.Verified.Network
	network.Zones["catofes."] = zone.NewZoneState("catofes.", nil)
	network.Zones["catofes."].Delegations[path] = &zone.Delegation{ZoneName: path, Signature: []byte("proof")}
	network.Zones["catofes."].Revocations[path] = &zone.DelegationRevocation{ParentZone: "catofes.", ChildZone: path, RevokedAt: 200}
	zs := network.Zones[path]
	zs.Records["value"] = &zone.Record{Zone: path, Key: "value", Version: 3, Value: []byte("current")}
	zs.RecordHistory["value"] = []*zone.Record{
		{Zone: path, Key: "value", Version: 1, Value: []byte("first")},
		{Zone: path, Key: "value", Version: 2, Value: []byte("second")},
	}
	store := NewStore(candidate.Verified, nil, nil)
	for _, version := range []uint64{0, 1, 2, 3, 4} {
		got, err := store.ReadRecordSnapshot(path, "value", version)
		want, wantErr := RecordSnapshotFor(network, path, "value", version)
		if !reflect.DeepEqual(got, want) || fmt.Sprint(err) != fmt.Sprint(wantErr) {
			t.Fatalf("record v%d = %#v/%v, want %#v/%v", version, got, err, want, wantErr)
		}
		if got != nil {
			got.Record.Value[0] ^= 0xff
		}
	}
	snapshot, revoked, err := store.ReadZoneSnapshot(path, time.Unix(199, 0))
	want, _ := Snapshot(network, path)
	if err != nil || revoked || !reflect.DeepEqual(snapshot, want) || snapshot.RecordHistory != nil {
		t.Fatalf("zone snapshot before revocation = %#v/%v/%v", snapshot, revoked, err)
	}
	snapshot.Records["value"].Value[0] ^= 0xff
	snapshot.ParentProof[0].Signature[0] ^= 0xff
	again, _, _ := store.ReadZoneSnapshot(path, time.Unix(199, 0))
	if !reflect.DeepEqual(again, want) {
		t.Fatal("wire snapshot mutation reached the store")
	}
	if snapshot, revoked, err := store.ReadZoneSnapshot(path, time.Unix(200, 0)); err != nil || !revoked || snapshot != nil {
		t.Fatalf("future revocation was not evaluated on the next read: %#v/%v/%v", snapshot, revoked, err)
	}
}

func TestProjectedReadsAreDetachedDuringConcurrentCommits(t *testing.T) {
	network, _, private, _ := managedAuthorityFixture(t, true)
	path := zone.ZonePath("node-a.catofes.")
	store := NewStore(&VerifiedState{ManagedZone: path, Network: network, IdentityPrivateKey: private}, nil, nil)
	put := func(i int) error {
		_, err := store.ApplyLocalIntent(context.Background(), PutRecordIntent{
			Zone: path, Key: "current", Type: "text", Value: []byte(fmt.Sprintf("value-%d", i)),
		}, time.Unix(int64(1000+i), 0))
		return err
	}
	if err := put(0); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 1; i <= 40; i++ {
			if err := put(i); err != nil {
				t.Errorf("concurrent commit: %v", err)
				return
			}
		}
	}()
	for i := 0; i < 80; i++ {
		view := store.ReadDiscovery(path.String())
		view.Network.Zones[path].Records["current"].Value[0] ^= 0xff
		snapshot, _, err := store.ReadZoneSnapshot(path, time.Unix(1000, 0))
		if err != nil {
			t.Fatal(err)
		}
		snapshot.Records["current"].Value[0] ^= 0xff
		record, err := store.ReadRecordSnapshot(path, "current", 0)
		if err != nil {
			t.Fatal(err)
		}
		record.Record.Value[0] ^= 0xff
	}
	wg.Wait()
	if got := string(store.ReadDiscovery(path.String()).Network.Zones[path].Records["current"].Value); got != "value-40" {
		t.Fatalf("projection mutation damaged committed record: %q", got)
	}
}
