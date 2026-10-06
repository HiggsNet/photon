package photonwindows

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/HiggsNet/photon/pkg/core/share"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// ImportState initializes a new common database from an existing Photon join
// bundle and key. It never updates or replaces a pre-existing destination.
func ImportState(ctx context.Context, config *Config, bundle *share.JoinBundle, key *share.PrivateKeyFile) (err error) {
	if ctx == nil {
		ctx = context.Background()
	}
	if config == nil || config.State.Path == "" || !config.ManagedZone.Valid() || config.ManagedZone.IsRoot() {
		return errors.New("state path and non-root managed zone are required")
	}
	if bundle == nil || bundle.Version != 1 {
		return errors.New("join bundle version must be 1")
	}
	if bundle.Zone != config.ManagedZone {
		return errors.New("join bundle zone does not match managed_zone")
	}
	if !bytes.Equal(bundle.RootPublicKey, config.TrustedRootPublicKey) {
		return errors.New("join bundle root does not match trusted_root_public_key")
	}
	if err := key.Validate(); err != nil {
		return err
	}
	// Linux join bundles contain only the ancestor authorities and their proofs.
	// Reject arbitrary network snapshots: InstallIdentity verifies the identity
	// chain, not unrelated zones or records smuggled alongside it.
	if bundle.Network == nil {
		return errors.New("join bundle network is missing")
	}
	ancestors := bundle.Zone.Ancestors()
	if len(bundle.Network.Zones) != len(ancestors) || len(bundle.Network.GlobalRoot) != 0 {
		return errors.New("join bundle must contain only the root-to-managed authority chain")
	}
	for _, path := range ancestors {
		zs := bundle.Network.Zones[path]
		proofCount := 1
		if path == zone.RootZone {
			proofCount = 0
		}
		if zs == nil || zs.Path != path || len(zs.ParentProof) != proofCount ||
			len(zs.Delegations) != 0 || len(zs.Revocations) != 0 || len(zs.Records) != 0 ||
			len(zs.RecordHistory) != 0 || len(zs.MerkleRoot) != 0 {
			return errors.New("join bundle must contain only authorities and parent proofs")
		}
	}
	// Validate the full chain, private key authorization and root pin before
	// creating any destination file. Persistence uses the common schema only.
	common := corestate.NewStore(nil, nil, nil)
	defer common.Close()
	result, err := common.InstallIdentity(ctx, corestate.IdentityInstall{
		ManagedZone: bundle.Zone, Network: bundle.Network,
		TrustedRootPublicKey: bundle.RootPublicKey, IdentityPrivateKey: key.PrivateKey,
	}, time.Now())
	if err != nil {
		return fmt.Errorf("verify join bundle: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(config.State.Path), 0o700); err != nil {
		return err
	}
	file, err := os.OpenFile(config.State.Path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return fmt.Errorf("create new Photon state: %w", err)
	}
	defer func() {
		if err != nil {
			err = errors.Join(err, os.Remove(config.State.Path))
		}
	}()
	if err = file.Close(); err != nil {
		return err
	}
	store, err := corestate.OpenBoltStore(config.State.Path, 0o600, time.Second)
	if err != nil {
		return err
	}
	view := common.ReadView()
	err = store.CommitCommon(ctx, &corestate.CommitCandidate{Verified: view.State, Gossip: view.Gossip}, result.Changes)
	return errors.Join(err, store.Close())
}
