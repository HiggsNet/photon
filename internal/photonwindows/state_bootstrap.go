package photonwindows

import (
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// OpenOrInitializeState restores existing state strictly. Only an absent file
// with configured bootstrap peers can acquire a new, authority-less identity.
// Joining and adoption remain owned by the common GossipDriver and Store.
func OpenOrInitializeState(config *Config, lockTimeout time.Duration) (*State, error) {
	if config == nil || config.State.Path == "" {
		return nil, errors.New("Windows state path is required")
	}
	_, err := os.Lstat(config.State.Path)
	if err == nil {
		return OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, lockTimeout)
	}
	if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if len(config.Gateway.BootstrapHints) == 0 {
		return nil, errors.New("new Photon state requires at least one gateway.bootstrap_hints peer for auto-join; existing state was not initialized")
	}
	_, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		return nil, err
	}
	defer clear(private)
	candidate, err := corestate.NewPendingIdentity(config.ManagedZone, config.TrustedRootPublicKey, private)
	if err != nil {
		return nil, err
	}
	defer clear(candidate.Verified.IdentityPrivateKey)
	err = initializeStateFile(context.Background(), config.State.Path, candidate, corestate.ChangeSet{VerifiedRevision: 0, NetworkChanged: true, SecurityPriority: true}, lockTimeout)
	if err != nil && !errors.Is(err, os.ErrExist) {
		return nil, err
	}
	// A concurrent creator may have won publication. Restore that exact owner;
	// never overwrite it, even if its trust settings differ or it is corrupt.
	return OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, lockTimeout)
}

// initializeStateFile stages one complete common database, with private-file
// permissions set before Bolt writes any identity, then publishes exclusively.
// Import and cold auto-join share this single persistent initialization path.
func initializeStateFile(ctx context.Context, path string, candidate *corestate.CommitCandidate, changes corestate.ChangeSet, lockTimeout time.Duration) (err error) {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	file, err := os.CreateTemp(filepath.Dir(path), ".photon-state-*")
	if err != nil {
		return err
	}
	defer func() {
		if removeErr := os.Remove(file.Name()); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
			err = errors.Join(err, fmt.Errorf("remove state staging file: %w", removeErr))
		}
	}()
	defer file.Close()
	if err := protectNewStateFile(file.Name()); err != nil {
		return fmt.Errorf("protect new Photon state: %w", err)
	}
	if err := file.Close(); err != nil {
		return err
	}
	store, err := corestate.OpenBoltStore(file.Name(), 0600, lockTimeout)
	if err != nil {
		return err
	}
	err = store.CommitCommon(ctx, candidate, changes)
	if err = errors.Join(err, store.Close()); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := publishNewStateFile(file.Name(), path); err != nil {
		return fmt.Errorf("create new Photon state: %w", err)
	}
	return nil
}
