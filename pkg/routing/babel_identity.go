package routing

import (
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

const (
	RecordTypeBabelIdentity = "routing.babel.identities.v1"
	RecordKeyBabelIdentity  = "routing/babel/identities"
	MaxBabelIdentities      = 64
	MaxBabelIdentityLease   = 24 * time.Hour
)

// BabelIdentityRecord binds complete observed 64-bit Babel IDs to its signed
// record's zone. Empty RouterIDs withdraws the binding. ExpiresAt is necessary:
// generic zone records have no expiry, and BIRD randomizes IDs on restart.
// Publishing this optional record never changes existing BIRD configuration.
type BabelIdentityRecord struct {
	Version   int      `json:"version"`
	RouterIDs []string `json:"router_ids"`
	ExpiresAt int64    `json:"expires_at"`
}

func (r BabelIdentityRecord) IDs() ([][8]byte, error) {
	if r.Version != 1 || len(r.RouterIDs) > MaxBabelIdentities || r.ExpiresAt <= 0 {
		return nil, errors.New("invalid Babel identity record")
	}
	ids := make([][8]byte, 0, len(r.RouterIDs))
	seen := make(map[[8]byte]bool)
	for _, text := range r.RouterIDs {
		raw, err := hex.DecodeString(text)
		if err != nil || len(raw) != 8 || strings.ToLower(text) != text {
			return nil, fmt.Errorf("invalid full Babel Router ID %q", text)
		}
		var id [8]byte
		copy(id[:], raw)
		if id == [8]byte{} || seen[id] {
			return nil, errors.New("zero or duplicate Babel Router ID")
		}
		seen[id] = true
		ids = append(ids, id)
	}
	return ids, nil
}

// ParseBabelIdentityRecord checks structure and the explicit lease, not trust.
// Consumers must verify the record's signature, root pin and current chain.
func ParseBabelIdentityRecord(record *zone.Record, now time.Time) (*BabelIdentityRecord, error) {
	if record == nil || record.Type != RecordTypeBabelIdentity || record.Key != RecordKeyBabelIdentity || !record.Zone.Valid() || len(record.Value) > 4096 {
		return nil, errors.New("invalid Babel identity record envelope")
	}
	var value BabelIdentityRecord
	if err := json.Unmarshal(record.Value, &value); err != nil {
		return nil, err
	}
	if _, err := value.IDs(); err != nil {
		return nil, err
	}
	if record.Timestamp <= 0 || value.ExpiresAt <= record.Timestamp || value.ExpiresAt-record.Timestamp > int64(MaxBabelIdentityLease/time.Second) || now.Unix() < record.Timestamp || now.Unix() >= value.ExpiresAt {
		return nil, errors.New("Babel identity lease is not current")
	}
	return &value, nil
}

// StableBabelRouterID is a full-width Windows leaf ID derived from verified
// identity material. Its signed publication is still required for origin
// admission; hashing or matching the low BIRD 32 bits never grants permission.
func StableBabelRouterID(path zone.ZonePath, root ed25519.PublicKey, instance string) ([8]byte, error) {
	var id [8]byte
	if !path.Valid() || len(root) != ed25519.PublicKeySize || instance == "" || strings.ContainsRune(instance, 0) {
		return id, errors.New("invalid stable Babel identity input")
	}
	digest := photoncrypto.Hash([]byte("photon-babel-router-id-v1\x00"), root, []byte(path), []byte{0}, []byte(instance))
	copy(id[:], digest[:8])
	if id == [8]byte{} {
		id[7] = 1
	}
	return id, nil
}
