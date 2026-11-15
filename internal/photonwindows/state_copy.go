package photonwindows

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	bolt "go.etcd.io/bbolt"
)

// CopyState keeps the exclusive database lock until the protected copy is published.
func CopyState(config *Config, destination string) (err error) {
	state, err := OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, state.Close()) }()
	temp, err := os.CreateTemp(filepath.Dir(destination), ".photon-state-copy-*")
	if err != nil {
		return err
	}
	defer os.Remove(temp.Name())
	defer temp.Close()
	if err := protectNewStateFile(temp.Name()); err != nil {
		return fmt.Errorf("protect identity copy: %w", err)
	}
	if err := state.bolt.View(func(tx *bolt.Tx) error {
		_, err := tx.WriteTo(temp)
		return err
	}); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	return publishNewStateFile(temp.Name(), destination)
}
