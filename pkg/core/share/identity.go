package share

import (
	"bytes"
	"crypto/ed25519"
	"errors"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// JoinBundle is the portable authorization chain issued by Photon join/delegate.
type JoinBundle struct {
	Version       uint8              `json:"version"`
	Zone          zone.ZonePath      `json:"zone"`
	RootPublicKey ed25519.PublicKey  `json:"root_public_key"`
	Network       *zone.NetworkState `json:"network"`
}

// PrivateKeyFile is the existing Photon JSON key format, shared by both CLIs.
type PrivateKeyFile struct {
	Type       string             `json:"type"`
	PublicKey  ed25519.PublicKey  `json:"public_key"`
	PrivateKey ed25519.PrivateKey `json:"private_key"`
}

func (key *PrivateKeyFile) Validate() error {
	if key == nil {
		return errors.New("private key is nil")
	}
	if key.Type != "photon.ed25519.private.v1" {
		return errors.New("unsupported key file type")
	}
	if len(key.PrivateKey) != ed25519.PrivateKeySize || len(key.PublicKey) != ed25519.PublicKeySize {
		return errors.New("invalid ed25519 key file")
	}
	derived := ed25519.NewKeyFromSeed(key.PrivateKey.Seed())
	if !bytes.Equal(derived, key.PrivateKey) || !bytes.Equal(derived.Public().(ed25519.PublicKey), key.PublicKey) {
		return errors.New("private key does not match public key")
	}
	return nil
}
