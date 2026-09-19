package photonlinux

import (
	"encoding/base64"

	"github.com/HiggsNet/photon/pkg/core/zone"

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

// InjectIPsecKeyMaterial attaches copied local key material and decoded peer public keys.
func InjectIPsecKeyMaterial(network *zone.NetworkState, localKey *photonstate.IPsecTransportKeyState, desired []ipsec.TransportLinkSpec) []ipsec.TransportLinkSpec {
	out := make([]ipsec.TransportLinkSpec, len(desired))
	for i, spec := range desired {
		if localKey != nil && len(localKey.PrivateKey) > 0 {
			spec.LocalPrivateKey = append([]byte(nil), localKey.PrivateKey...)
			spec.LocalPrivateKeyAlgorithm = localKey.Algorithm
		}
		if network != nil {
			peerZone := network.Zones[spec.PeerZone]
			if peerZone == nil {
				out[i] = spec
				continue
			}
			if record := peerZone.Records[ipsec.RecordKeyTransportKey]; record != nil {
				if keyRecord, err := ipsec.ParseTransportKeyRecord(record); err == nil {
					if pub, err := ipsec.DecodeTransportPublicKey(*keyRecord); err == nil {
						spec.PeerPublicKey = pub
					}
				}
			}
		}
		out[i] = spec
	}
	return out
}
