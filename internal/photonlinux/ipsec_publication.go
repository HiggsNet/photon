package photonlinux

import (
	"encoding/base64"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// PublicTransportKeyRecord projects a stored transport key into its public protocol record.
func PublicTransportKeyRecord(key *photonstate.IPsecTransportKeyState) *ipsec.TransportKeyRecord {
	record := &ipsec.TransportKeyRecord{
		Version:     1,
		Kind:        key.Kind,
		Algorithm:   key.Algorithm,
		Fingerprint: key.Fingerprint,
		NotBefore:   key.NotBefore,
		NotAfter:    key.NotAfter,
		UpdatedAt:   key.UpdatedAt,
	}
	if record.Kind == "" {
		record.Kind = ipsec.TransportKeyRawPublicKey
	}
	if record.Algorithm == "" {
		record.Algorithm = ipsec.AlgorithmEd25519
	}
	if record.Fingerprint == "" {
		record.Fingerprint = ipsec.TransportKeyFingerprint(record.Algorithm, key.PublicKey)
	}
	if record.UpdatedAt == 0 {
		record.UpdatedAt = record.NotBefore
	}
	record.PublicKey = base64.StdEncoding.EncodeToString(key.PublicKey)
	return record
}
