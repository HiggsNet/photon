package photonwindows

import (
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// Bind the SA to the local public transport intent too. An unrelated network
// revision may be accepted, but a local key/profile/overlay withdrawal must not
// retain an SA just because the gateway's identity is still authorized.
func localTransportAuthorization(config *Config, view corestate.View, now time.Time) ([32]byte, error) {
	var digest [32]byte
	if view.State == nil || view.State.Network == nil {
		return digest, errors.New("local transport: no verified state")
	}
	if err := photoncrypto.VerifyChain(view.State.Network, config.ManagedZone, now); err != nil {
		return digest, err
	}
	local := view.State.Network.Zones[config.ManagedZone]
	if local == nil {
		return digest, errors.New("local transport: no local authority")
	}
	hash := sha256.New()
	for _, key := range []string{ipsec.RecordKeyProfile, ipsec.RecordKeyTransportKey, ipsec.RecordKeyAddresses, ipsec.RecordKeyPorts, ipsec.OverlayIntentRecordKey(config.Overlay.ID)} {
		record := local.Records[key]
		if record == nil || record.Key != key || record.Zone != config.ManagedZone {
			return digest, errors.New("local transport: required record withdrawn")
		}
		if err := photoncrypto.VerifyRecord(record, local.Authority, now); err != nil {
			return digest, err
		}
		_, _ = hash.Write(binary.BigEndian.AppendUint64(nil, uint64(len(record.Value))))
		_, _ = hash.Write(record.Value)
	}
	key, err := ipsec.ParseTransportKeyRecord(local.Records[ipsec.RecordKeyTransportKey])
	if err != nil {
		return digest, err
	}
	if key.NotBefore > now.Unix() || key.NotAfter != 0 && now.Unix() >= key.NotAfter {
		return digest, errors.New("local transport: key outside validity period")
	}
	copy(digest[:], hash.Sum(nil))
	return digest, nil
}
