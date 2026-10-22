package photonwindows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/json"
	"errors"
	"os"
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

func TestOpenStateUpgradesRC6CommonLayoutPreservingRevision(t *testing.T) {
	path, _, rootPublic, _ := saveCommonState(t, 7)
	db, err := bolt.Open(path, 0o600, nil)
	if err != nil {
		t.Fatal(err)
	}
	var before []byte
	// Recreate RC.6's aggregate common payload, retaining its signed contents.
	err = db.Update(func(tx *bolt.Tx) error {
		candidate, _, _, _, err := corestate.LoadBoltState(tx)
		if err != nil {
			return err
		}
		before, err = json.Marshal(candidate.Verified)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(map[string]any{
			"managed_zone":            candidate.Verified.ManagedZone,
			"network":                 candidate.Verified.Network,
			"trusted_root_public_key": candidate.Verified.TrustedRootPublicKey,
			"root_private_key":        candidate.Verified.RootPrivateKey,
			"identity_private_key":    candidate.Verified.IdentityPrivateKey,
		})
		if err != nil {
			return err
		}
		common := tx.Bucket([]byte("photon:common-state"))
		verified := common.Bucket([]byte("verified"))
		if err := verified.DeleteBucket([]byte("zones")); err != nil {
			return err
		}
		if err := verified.Put([]byte("payload"), payload); err != nil {
			return err
		}
		var version [8]byte
		binary.BigEndian.PutUint64(version[:], 1)
		return common.Bucket([]byte("meta")).Put([]byte("schema-version"), version[:])
	})
	closeErr := db.Close()
	if err != nil {
		t.Fatal(err)
	}
	if closeErr != nil {
		t.Fatal(closeErr)
	}
	for startup := 0; startup < 2; startup++ {
		source, err := OpenState(path, "node-a.catofes.", rootPublic, time.Second)
		if err != nil {
			t.Fatalf("startup %d: %v", startup, err)
		}
		view := source.Store().ReadView()
		after, marshalErr := json.Marshal(view.State)
		if err := source.Close(); err != nil {
			t.Fatal(err)
		}
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		if view.Revision != 7 || !bytes.Equal(before, after) {
			t.Fatal("layout upgrade or reopen changed verified contents or revision")
		}
		if startup == 0 {
			db, err := bolt.Open(path, 0o600, &bolt.Options{ReadOnly: true})
			if err != nil {
				t.Fatal(err)
			}
			err = db.View(func(tx *bolt.Tx) error {
				_, revision, report, found, err := corestate.LoadBoltState(tx)
				if err == nil && (!found || report.LegacyVerifiedLayout || revision != 7) {
					t.Error("Windows startup did not persist the upgraded common layout")
				}
				return err
			})
			closeErr := db.Close()
			if err != nil {
				t.Fatal(err)
			}
			if closeErr != nil {
				t.Fatal(closeErr)
			}
			beforeFile, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() {
				afterFile, err := os.ReadFile(path)
				if err != nil {
					t.Error(err)
				} else if !bytes.Equal(beforeFile, afterFile) {
					t.Error("reopening an upgraded Windows state rewrote its database")
				}
			})
		}
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

func signedNetwork(t testing.TB) (*zone.NetworkState, ed25519.PublicKey, ed25519.PrivateKey) {
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
	rootAuthority := photoncrypto.ConfiguredRootAuthority(rootPublic)
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
