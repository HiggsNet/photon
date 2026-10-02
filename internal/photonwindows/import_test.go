package photonwindows

import (
	"bytes"
	"crypto/ed25519"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/share"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

func importNetwork(t *testing.T) (*zone.NetworkState, ed25519.PublicKey, ed25519.PrivateKey) {
	t.Helper()
	network, root, private := signedNetwork(t)
	for path, zs := range network.Zones {
		if path != zone.RootZone {
			zs.ParentProof = []*zone.Delegation{network.Zones[path.Parent()].Delegations[path]}
		}
	}
	for _, zs := range network.Zones {
		zs.Delegations = nil
	}
	return network, root, private
}

func TestImportStatePersistsAndStartsConsole(t *testing.T) {
	network, root, private := importNetwork(t)
	config := &Config{State: StateConfig{Path: filepath.Join(t.TempDir(), "state", "photon.db")}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: root, GossipListen: "127.0.0.1:0"}
	bundle := &share.JoinBundle{Version: 1, Zone: config.ManagedZone, RootPublicKey: root, Network: network}
	key := &share.PrivateKeyFile{Type: "photon.ed25519.private.v1", PublicKey: private.Public().(ed25519.PublicKey), PrivateKey: private}
	if err := ImportState(t.Context(), config, bundle, key); err != nil {
		t.Fatal(err)
	}
	state, err := OpenState(config.State.Path, config.ManagedZone, root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	view, err := state.ReadView(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if view.Revision != 1 || !bytes.Equal(view.State.IdentityPrivateKey, private) {
		t.Fatal("identity/revision not persisted")
	}
	if err := state.Close(); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(config.State.Path)
	if err != nil {
		t.Fatal(err)
	}
	if err := ImportState(t.Context(), config, bundle, key); err == nil {
		t.Fatal("existing state overwritten")
	}
	after, err := os.ReadFile(config.State.Path)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatal("existing state changed")
	}
	_, stop := startConsole(t, config)
	stop()
}

func TestImportStateRejectsUntrustedInputWithoutCreatingDatabase(t *testing.T) {
	for _, name := range []string{"root", "zone", "signature", "unauthorized-key", "corrupt-seed", "version", "expired", "extra-zone", "record"} {
		t.Run(name, func(t *testing.T) {
			network, root, private := importNetwork(t)
			config := &Config{State: StateConfig{Path: filepath.Join(t.TempDir(), "photon.db")}, ManagedZone: "node-a.catofes.", TrustedRootPublicKey: root}
			bundle := &share.JoinBundle{Version: 1, Zone: config.ManagedZone, RootPublicKey: append([]byte(nil), root...), Network: network}
			key := &share.PrivateKeyFile{Type: "photon.ed25519.private.v1", PublicKey: private.Public().(ed25519.PublicKey), PrivateKey: private}
			switch name {
			case "root":
				bundle.RootPublicKey[0] ^= 1
			case "zone":
				bundle.Zone = "other.catofes."
			case "signature":
				network.Zones[config.ManagedZone].ParentProof[0].Signature[0] ^= 1
			case "unauthorized-key":
				key.PublicKey, key.PrivateKey, _ = ed25519.GenerateKey(nil)
			case "corrupt-seed":
				key.PrivateKey[0] ^= 1
			case "version":
				bundle.Version++
			case "expired":
				proof := network.Zones[config.ManagedZone].ParentProof[0]
				expired := time.Now().Add(-time.Hour)
				proof.ExpiresAt = &expired
				if err := photoncrypto.SignDelegation(proof, config.ManagedZone.Parent(), private); err != nil {
					t.Fatal(err)
				}
			case "extra-zone":
				network.Zones["other."] = zone.NewZoneState("other.", nil)
			case "record":
				network.Zones[config.ManagedZone].Records["fake"] = &zone.Record{}
			}
			if err := ImportState(t.Context(), config, bundle, key); err == nil {
				t.Fatal("invalid identity accepted")
			}
			if _, err := os.Stat(config.State.Path); !os.IsNotExist(err) {
				t.Fatalf("destination created: %v", err)
			}
		})
	}
}
