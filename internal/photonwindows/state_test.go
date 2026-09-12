package photonwindows

import (
	"context"
	"crypto/ed25519"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	bolt "go.etcd.io/bbolt"
)

func TestOpenStateRestoresCommonRevisionAndDetachedView(t *testing.T) {
	path, network, rootPublic, identityPrivate := saveCommonState(t, 7)
	source, err := OpenState(path, "node-a.catofes.", rootPublic, time.Second)
	if err != nil {
		t.Fatalf("OpenState: %v", err)
	}
	defer source.Close()
	first, err := source.ReadView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if first.Revision != 7 || first.State.ManagedZone != "node-a.catofes." {
		t.Fatalf("view = %#v", first)
	}
	delete(first.State.Network.Zones, first.State.ManagedZone)
	first.State.IdentityPrivateKey[0] ^= 0xff
	second, err := source.ReadView(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if second.State.Network.Zones[second.State.ManagedZone] == nil || network.Zones[second.State.ManagedZone] == nil {
		t.Fatal("caller mutation escaped into common Store")
	}
	if !second.State.IdentityPrivateKey.Equal(identityPrivate) {
		t.Fatal("caller private-key mutation escaped into common Store")
	}
}

func TestOpenStateRejectsConfigTrustMismatch(t *testing.T) {
	path, _, rootPublic, _ := saveCommonState(t, 3)
	if _, err := OpenState(path, "other.catofes.", rootPublic, time.Second); err == nil || !strings.Contains(err.Error(), "managed zone mismatch") {
		t.Fatalf("managed-zone error = %v", err)
	}
	wrongPublic, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(path, "node-a.catofes.", wrongPublic, time.Second); err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("root-pin error = %v", err)
	}
}

func TestOpenStateRejectsLegacyZoneDatabase(t *testing.T) {
	network, rootPublic, _ := signedNetwork(t)
	path := filepath.Join(t.TempDir(), "legacy.db")
	legacy, err := zone.OpenBoltStore(path, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	if err := legacy.SaveNetwork(network); err != nil {
		t.Fatal(err)
	}
	if err := legacy.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := OpenState(path, "node-a.catofes.", rootPublic, time.Second); err == nil || !strings.Contains(err.Error(), "common schema is absent") {
		t.Fatalf("legacy database error = %v", err)
	}
}

func TestOpenStateOwnsExclusiveBoltHandle(t *testing.T) {
	path, _, rootPublic, _ := saveCommonState(t, 2)
	source, err := OpenState(path, "node-a.catofes.", rootPublic, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	competing, err := corestate.OpenBoltStore(path, 0o600, 20*time.Millisecond)
	if competing != nil {
		_ = competing.Close()
	}
	if !errors.Is(err, bolt.ErrTimeout) {
		t.Fatalf("competing open error = %v, want timeout", err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	if source.Store() != nil {
		t.Fatal("closed source still exposes common Store")
	}
	if _, err := source.ReadView(context.Background()); !errors.Is(err, corestate.ErrVerifiedStoreClosed) {
		t.Fatalf("read after close error = %v", err)
	}
	reopened, err := OpenState(path, "node-a.catofes.", rootPublic, time.Second)
	if err != nil {
		t.Fatalf("reopen after close: %v", err)
	}
	if err := reopened.Close(); err != nil {
		t.Fatal(err)
	}
}

func saveCommonState(t *testing.T, revision corestate.VerifiedRevision) (string, *zone.NetworkState, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	network, rootPublic, identityPrivate := signedNetwork(t)
	path := filepath.Join(t.TempDir(), "photon.db")
	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &corestate.CommitCandidate{
		Verified: &corestate.VerifiedState{
			ManagedZone:          "node-a.catofes.",
			Network:              network,
			TrustedRootPublicKey: rootPublic,
			IdentityPrivateKey:   identityPrivate,
		},
		Gossip: &corestate.GossipCheckpoint{},
	}
	if err := store.CommitCommon(context.Background(), candidate, corestate.ChangeSet{VerifiedRevision: revision, NetworkChanged: true}); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return path, network, rootPublic, identityPrivate
}

func signedNetwork(t *testing.T) (*zone.NetworkState, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	rootPublic, rootPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	identityPublic, identityPrivate, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	permissions := []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate, zone.PermAllocateIP}}}
	rootAuthority := &zone.ZoneAuthority{Zone: zone.RootZone, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: rootPublic, Capabilities: permissions}}}
	parentAuthority := zone.ZoneAuthority{Zone: "catofes.", Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: identityPublic, Capabilities: permissions}}}
	managedAuthority := zone.ZoneAuthority{Zone: "node-a.catofes.", Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: identityPublic, Capabilities: permissions}}}
	parentDelegation := &zone.Delegation{ZoneName: "catofes.", Authority: parentAuthority}
	if err := photoncrypto.SignDelegation(parentDelegation, zone.RootZone, rootPrivate); err != nil {
		t.Fatal(err)
	}
	managedDelegation := &zone.Delegation{ZoneName: "node-a.catofes.", Authority: managedAuthority}
	if err := photoncrypto.SignDelegation(managedDelegation, "catofes.", identityPrivate); err != nil {
		t.Fatal(err)
	}
	network := zone.NewNetworkState()
	network.Zones[zone.RootZone] = zone.NewZoneState(zone.RootZone, rootAuthority)
	network.Zones[zone.RootZone].Delegations["catofes."] = parentDelegation
	network.Zones["catofes."] = zone.NewZoneState("catofes.", &parentAuthority)
	network.Zones["catofes."].Delegations["node-a.catofes."] = managedDelegation
	network.Zones["node-a.catofes."] = zone.NewZoneState("node-a.catofes.", &managedAuthority)
	return network, rootPublic, identityPrivate
}
