package host

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

// Exercise the actual store rejection checkpoint and production catalog filter:
// an unchanged remote digest must remain discoverable when only local trust or
// time prevented verification. No scheduler, validator or network result is mocked.
func TestGossipCatalogRetriesAfterVerificationDependenciesChange(t *testing.T) {
	now := time.Unix(1000, 0)
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	const parent, child zone.ZonePath = "catofes.", "gateway.catofes."
	network := zone.NewNetworkState()
	rootAuthority := photoncrypto.ConfiguredRootAuthority(public)
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	for _, path := range []zone.ZonePath{parent, child} {
		authority := zone.ZoneAuthority{Zone: path, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: public, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate}}}}}}
		delegation := &zone.Delegation{ZoneName: path, Authority: authority}
		if err := photoncrypto.SignDelegation(delegation, path.Parent(), private); err != nil {
			t.Fatal(err)
		}
		network.Zones[path.Parent()].Delegations[path] = delegation
		network.Zones[path] = zone.NewZoneState(path, &authority)
	}
	take := func(source *zone.NetworkState, path zone.ZonePath) *corestate.ZoneSnapshot {
		t.Helper()
		snapshot, err := corestate.Snapshot(source, path)
		if err != nil {
			t.Fatal(err)
		}
		return snapshot
	}
	root := func(snapshot *corestate.ZoneSnapshot) []byte {
		return corestate.ZoneRoot(corestate.ZoneStateFromSnapshot(snapshot))
	}
	apply := func(store *corestate.Store, snapshot *corestate.ZoneSnapshot, at time.Time) error {
		t.Helper()
		result, err := store.ApplyRemoteBatch(context.Background(), "bootstrap", []corestate.RemoteSnapshot{{Snapshot: snapshot, ExpectedRoot: root(snapshot)}}, at)
		if err != nil || len(result.Outcomes) != 1 {
			t.Fatalf("apply transaction: %+v, %v", result, err)
		}
		return result.Outcomes[0].Err
	}
	visible := func(store *corestate.Store, snapshot *corestate.ZoneSnapshot, at time.Time) bool {
		t.Helper()
		view := store.ReadView()
		_, filtered := FilterGossipCatalogPage(GossipDiscoveryInput{Network: view.State.Network, Peers: view.Gossip.Peers}, "bootstrap", &corestate.CatalogPage{Entries: []corestate.ZoneDigest{{Zone: snapshot.Zone, RootHash: root(snapshot)}}}, at)
		return len(filtered.Entries) == 1
	}
	t.Run("missing-parent", func(t *testing.T) {
		target := zone.CloneNetworkState(network)
		target.Zones[parent] = zone.NewZoneState(parent, nil)
		delete(target.Zones, child)
		store := corestate.NewStore(&corestate.VerifiedState{Network: target, TrustedRootPublicKey: public}, nil, nil)
		defer store.Close()
		snapshot := take(network, child)
		digest := root(snapshot)
		err := apply(store, snapshot, now)
		var pending photoncrypto.VerificationPendingError
		if !errors.Is(err, corestate.ErrUntrustedZone) || !errors.As(err, &pending) || !visible(store, snapshot, now) || store.VerifiedRevision() != 0 {
			t.Fatalf("missing parent must reject without suppressing discovery: %v", err)
		}
		if err := apply(store, take(network, parent), now); err != nil {
			t.Fatal(err)
		}
		if !visible(store, snapshot, now) || !bytes.Equal(digest, root(snapshot)) {
			t.Fatal("parent recovery suppressed or changed the child digest")
		}
		if err := apply(store, snapshot, now); err != nil {
			t.Fatalf("same child root could not converge after parent: %v", err)
		}
	})
	t.Run("future-revocation-and-invalid-signature", func(t *testing.T) {
		source := zone.CloneNetworkState(network)
		old := source.Zones[parent].Delegations[child]
		revocation := &zone.DelegationRevocation{ParentZone: parent, ChildZone: child, RevokedAuthorityEpoch: old.AuthorityEpoch, RevokedAuthorityHash: append([]byte(nil), old.AuthorityHash...), RevokedAt: now.Add(4 * time.Second).Unix()}
		if err := photoncrypto.SignDelegationRevocation(revocation, parent, private); err != nil {
			t.Fatal(err)
		}
		source.Zones[parent].Revocations[child] = revocation
		updated := *old
		updated.Authority.Epoch++
		if err := photoncrypto.SignDelegation(&updated, parent, private); err != nil {
			t.Fatal(err)
		}
		source.Zones[parent].Delegations[child] = &updated
		snapshot := take(source, parent)
		store := corestate.NewStore(&corestate.VerifiedState{Network: network, TrustedRootPublicKey: public}, nil, nil)
		defer store.Close()
		err := apply(store, snapshot, now)
		var pending photoncrypto.VerificationPendingError
		if !errors.As(err, &pending) || store.VerifiedRevision() != 0 || !visible(store, snapshot, now) {
			t.Fatalf("future revocation must fail without long rejection cache: %v", err)
		}
		active := now.Add(4 * time.Second)
		if err := apply(store, snapshot, active); err != nil || store.VerifiedRevision() != 1 {
			t.Fatalf("same root failed after activation: %v", err)
		}

		// Once active, a real bad signature remains a deterministic rejection
		// and retains the existing ten-minute discovery suppression.
		snapshot.Revocations[child].Signature[0] ^= 0xff
		bad := corestate.NewStore(&corestate.VerifiedState{Network: network, TrustedRootPublicKey: public}, nil, nil)
		defer bad.Close()
		err = apply(bad, snapshot, active)
		if err == nil || errors.As(err, &pending) || visible(bad, snapshot, active) || bad.VerifiedRevision() != 0 {
			t.Fatalf("invalid signature was not retained as a rejection: %v", err)
		}
		if !visible(bad, snapshot, active.Add(corestate.RejectedObjectTTL)) {
			t.Fatal("deterministic rejection no longer expires at the existing TTL")
		}
	})
}
