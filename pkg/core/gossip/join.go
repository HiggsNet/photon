package gossip

import (
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// JoinRequest is the portable request submitted to a parent zone administrator.
type JoinRequest struct {
	Version   uint8             `json:"version"`
	Zone      zone.ZonePath     `json:"zone"`
	PublicKey ed25519.PublicKey `json:"public_key"`
}

// NewJoinRequest constructs a validated request with a detached public key.
func NewJoinRequest(path zone.ZonePath, pub ed25519.PublicKey) (*JoinRequest, error) {
	request := &JoinRequest{Version: 1, Zone: path, PublicKey: append(ed25519.PublicKey(nil), pub...)}
	if err := ValidateJoinRequest(request); err != nil {
		return nil, err
	}
	return request, nil
}

// ValidateJoinRequest checks requests received from external callers.
func ValidateJoinRequest(request *JoinRequest) error {
	if request == nil {
		return errors.New("join request is nil")
	}
	if request.Version != 1 {
		return fmt.Errorf("unsupported join request version: %d", request.Version)
	}
	if !request.Zone.Valid() || request.Zone == zone.RootZone {
		return fmt.Errorf("invalid join zone: %s", request.Zone)
	}
	if len(request.PublicKey) != ed25519.PublicKeySize {
		return errors.New("join request public key is invalid")
	}
	return nil
}
