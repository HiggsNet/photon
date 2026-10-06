package photonwindows

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
)

// EnsureLocalBabelIdentity publishes the Windows leaf's complete deterministic
// ID through the shared signed-record owner. No independent secret or state
// bucket is created. A foreign/manual identity is not overwritten implicitly.
// The Babel lifecycle caller renews the lease before it expires; publication
// by itself does not advertise a route or authorize Wintun packet delivery.
func (source *State) EnsureLocalBabelIdentity(ctx context.Context, config *Config, now time.Time) ([8]byte, error) {
	var zero [8]byte
	if source == nil || config == nil {
		return zero, errors.New("Babel: state/config absent")
	}
	id, err := routing.StableBabelRouterID(config.ManagedZone, config.TrustedRootPublicKey, config.Overlay.ID)
	if err != nil {
		return zero, err
	}
	source.mu.RLock()
	defer source.mu.RUnlock()
	if source.closed {
		return zero, corestate.ErrVerifiedStoreClosed
	}
	view := source.common.ReadView()
	if view.State == nil || view.State.ManagedZone != config.ManagedZone || !bytes.Equal(view.State.TrustedRootPublicKey, config.TrustedRootPublicKey) {
		return zero, errors.New("Babel: identity configuration mismatch")
	}
	if err := photoncrypto.VerifyPinnedRoot(view.State.Network, config.TrustedRootPublicKey); err != nil {
		return zero, err
	}
	if err := photoncrypto.VerifyChain(view.State.Network, config.ManagedZone, now); err != nil {
		return zero, err
	}
	local := view.State.Network.Zones[config.ManagedZone]
	text := hex.EncodeToString(id[:])
	if record := local.Records[routing.RecordKeyBabelIdentity]; record != nil {
		if record.Zone != config.ManagedZone || now.Unix() < record.Timestamp || photoncrypto.VerifyRecord(record, local.Authority, now) != nil {
			return zero, errors.New("Babel: existing binding is untrusted")
		}
		previous, err := routing.ParseBabelIdentityRecord(record, time.Unix(record.Timestamp, 0))
		if err != nil || len(previous.RouterIDs) != 1 || previous.RouterIDs[0] != text {
			return zero, errors.New("Babel: existing binding requires explicit identity migration")
		}
		if previous.ExpiresAt > now.Add(30*time.Minute).Unix() {
			if source.common.VerifiedRevision() != view.Revision {
				return zero, corestate.ErrVerifiedRevisionStale
			}
			return id, nil
		}
	}
	value, err := json.Marshal(routing.BabelIdentityRecord{Version: 1, RouterIDs: []string{text}, ExpiresAt: now.Add(time.Hour).Unix()})
	if err != nil {
		return zero, err
	}
	_, err = source.common.ApplyLocalIntentsAtRevision(ctx, []corestate.LocalIntent{corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordBabelIdentity, Zone: config.ManagedZone, Key: routing.RecordKeyBabelIdentity, Type: routing.RecordTypeBabelIdentity, Value: value}}, now, view.Revision)
	if err != nil {
		return zero, err
	}
	return id, nil
}
