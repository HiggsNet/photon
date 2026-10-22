package photonwindows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	bolt "go.etcd.io/bbolt"
)

// LocalTransportIdentity is separate from the common zone signing identity.
// The private key is detached and must never be published or logged.
type LocalTransportIdentity struct {
	ID         string
	PrivateKey ed25519.PrivateKey
}

type transportIdentityDisk struct {
	PrivateKey []byte                   `json:"private_key"`
	Record     ipsec.TransportKeyRecord `json:"record"`
}

var windowsTransportBucket = []byte("photon-windows-transport-v1")
var windowsTransportKey = []byte("identity")

// EnsureLocalTransport persists a distinct transport secret before publishing
// its signed public records through the common Store. Existing foreign records
// are never overwritten. A crash between the two commits resumes with the same
// private key; a stale source revision publishes nothing.
func (source *State) EnsureLocalTransport(ctx context.Context, config *Config, now time.Time, plan GatewayPlan, localEndpoint netip.AddrPort) (LocalTransportIdentity, error) {
	var out LocalTransportIdentity
	if source == nil || config == nil {
		return out, errors.New("local transport: state/config absent")
	}
	if !localEndpoint.IsValid() || localEndpoint.Port() == 0 {
		return out, errors.New("local transport: actual bound UDP endpoint required")
	}
	source.mu.RLock()
	defer source.mu.RUnlock()
	if source.closed {
		return out, corestate.ErrVerifiedStoreClosed
	}
	if err := ctx.Err(); err != nil {
		return out, err
	}
	view := source.common.ReadView()
	if view.State == nil || view.State.ManagedZone != config.ManagedZone || !bytes.Equal(view.State.TrustedRootPublicKey, config.TrustedRootPublicKey) {
		return out, errors.New("local transport: identity configuration mismatch")
	}
	plan = RevalidateGatewayPlan(config, view, plan, now)
	if plan.Selected == nil || plan.Rejected != "" {
		return out, errors.New("local transport: no current authorized gateway")
	}
	if err := photoncrypto.VerifyChain(view.State.Network, config.ManagedZone, now); err != nil {
		return out, err
	}
	local := view.State.Network.Zones[config.ManagedZone]
	if local == nil || len(view.State.IdentityPrivateKey) != ed25519.PrivateKeySize {
		return out, errors.New("local transport: signing identity absent")
	}
	identityPublic := view.State.IdentityPrivateKey.Public().(ed25519.PublicKey)

	var disk transportIdentityDisk
	found := false
	err := source.bolt.View(func(tx *bolt.Tx) error {
		bucket := tx.Bucket(windowsTransportBucket)
		if bucket == nil || bucket.Get(windowsTransportKey) == nil {
			return nil
		}
		found = true
		if err := json.Unmarshal(bucket.Get(windowsTransportKey), &disk); err != nil {
			return errors.New("local transport: corrupt persisted identity")
		}
		return nil
	})
	if err != nil {
		return out, err
	}
	if !found {
		// A Linux/imported record without its Windows-owned private key is not
		// permission to rotate the node's transport identity on startup.
		if local.Records[ipsec.RecordKeyTransportKey] != nil || local.Records[ipsec.RecordKeyProfile] != nil || local.Records[ipsec.RecordKeyAddresses] != nil || local.Records[ipsec.RecordKeyPorts] != nil {
			return out, errors.New("local transport: existing public identity has no Windows private key; explicit migration required")
		}
		key, record, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, 0, identityPublic)
		if err != nil {
			return out, err
		}
		disk = transportIdentityDisk{PrivateKey: key.PrivateKey, Record: *record}
	}
	private, err := validateTransportIdentity(disk, identityPublic, now)
	if err != nil {
		return out, err
	}

	peer := view.State.Network.Zones[plan.Selected.Zone]
	peerOverlay, err := ipsec.ParseOverlayIntentRecord(peer.Records[ipsec.OverlayIntentRecordKey(config.Overlay.ID)])
	if err != nil {
		return out, err
	}
	overlay := *peerOverlay
	switch overlay.TunnelAddress.Mode {
	case ipsec.TunnelAddressDerivedLinkLocal, ipsec.TunnelAddressDerivedPool, ipsec.TunnelAddressDisabled:
	default:
		return out, errors.New("local transport: gateway tunnel mode requires explicit allocation")
	}
	overlay.PolicyTags = nil
	overlay.UpdatedAt = disk.Record.UpdatedAt
	// The Windows leaf supports both underlay families and the existing
	// family-redundant profile; it advertises no listener/address ownership.
	profile := ipsec.ProfileRecord{Version: 1, Enabled: true, Provider: ipsec.ProviderStrongSwan, IKEIdentity: string(config.ManagedZone), TransportKeyFingerprint: disk.Record.Fingerprint, Role: ipsec.RoleOut, AddressFamilies: []string{ipsec.FamilyIPv4, ipsec.FamilyIPv6}, PathModes: []string{ipsec.PathModeFamilyRedundant}, NAT: ipsec.NATProfile{Hint: ipsec.NATHintBehindNAT, InboundReachable: ipsec.NATReachableFalse}}
	if err := profile.Validate(config.ManagedZone); err != nil {
		return out, err
	}
	if err := overlay.Validate(config.Overlay.ID); err != nil {
		return out, err
	}
	addresses := ipsec.AddressRecord{Version: 1, Addresses: []ipsec.AddressAdvertisement{}}
	binding := ipsec.PortBinding{Local: localEndpoint.Port(), Advertised: localEndpoint.Port()}
	ports := ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed, Current: &ipsec.PortSelection{Generation: 1, IKE: binding, NATT: binding}}
	var intents []corestate.LocalIntent
	for _, record := range []struct {
		key, kind string
		value     any
	}{
		{ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, disk.Record},
		{ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, profile},
		{ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, addresses},
		{ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ports},
		{ipsec.OverlayIntentRecordKey(config.Overlay.ID), ipsec.RecordTypeOverlayIntent, overlay},
	} {
		encoded, err := json.Marshal(record.value)
		if err != nil {
			return out, err
		}
		if existing := local.Records[record.key]; existing != nil {
			if existing.Zone != config.ManagedZone || existing.Key != record.key || existing.Type != record.kind || photoncrypto.VerifyRecord(existing, local.Authority, now) != nil {
				return out, fmt.Errorf("local transport: invalid existing %s", record.key)
			}
			if record.kind == ipsec.RecordTypeAddresses {
				previous, err := ipsec.ParseAddressRecord(existing)
				if err != nil || len(previous.Addresses) != 0 {
					return out, errors.New("local transport: existing address publication is not Windows outbound-only")
				}
				continue
			}
			if record.kind == ipsec.RecordTypePorts {
				previous, err := ipsec.ParsePortRecord(existing)
				if err != nil || !windowsSharedPortRecord(previous) {
					return out, errors.New("local transport: existing port publication is not a Windows shared socket")
				}
				if previous.Current.IKE.Local == localEndpoint.Port() {
					continue
				}
				// A new actual socket port replaces only our constrained fixed
				// single-socket publication; custom/manual port records fail closed.
				intents = append(intents, corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordIPsec, Zone: config.ManagedZone, Key: record.key, Type: record.kind, Value: encoded})
				continue
			}
			// Existing overlays can carry user-owned policy tags or timestamp.
			// Preserve them if their actual tunnel/path configuration matches.
			if record.kind == ipsec.RecordTypeOverlayIntent {
				previous, err := ipsec.ParseOverlayIntentRecord(existing)
				if err != nil {
					return out, err
				}
				comparable := *previous
				comparable.PolicyTags, comparable.UpdatedAt = nil, overlay.UpdatedAt
				value, _ := json.Marshal(comparable)
				if !bytes.Equal(value, encoded) {
					return out, errors.New("local transport: existing overlay differs from selected gateway")
				}
				continue
			}
			var current, wanted any
			if json.Unmarshal(existing.Value, &current) != nil || json.Unmarshal(encoded, &wanted) != nil {
				return out, fmt.Errorf("local transport: invalid existing %s", record.key)
			}
			currentBytes, _ := json.Marshal(current)
			wantedBytes, _ := json.Marshal(wanted)
			if !bytes.Equal(currentBytes, wantedBytes) {
				return out, fmt.Errorf("local transport: existing %s differs from Windows identity", record.key)
			}
			continue
		}
		intents = append(intents, corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordIPsec, Zone: config.ManagedZone, Key: record.key, Type: record.kind, Value: encoded})
	}
	if !found {
		encoded, err := json.Marshal(disk)
		if err != nil {
			return out, err
		}
		err = source.bolt.Update(func(tx *bolt.Tx) (bool, error) {
			if err := ctx.Err(); err != nil {
				return false, err
			}
			_, revision, _, _, err := corestate.LoadBoltState(tx)
			if err != nil {
				return false, err
			}
			if revision != view.Revision {
				return false, corestate.ErrVerifiedRevisionStale
			}
			bucket, err := tx.CreateBucketIfNotExists(windowsTransportBucket)
			if err != nil {
				return false, err
			}
			if bucket.Get(windowsTransportKey) != nil {
				return false, errors.New("local transport: concurrent identity creation; retry")
			}
			return true, bucket.Put(windowsTransportKey, encoded)
		})
		if err != nil {
			return out, err
		}
	}
	if len(intents) > 0 {
		if _, err := source.common.ApplyLocalIntentsAtRevision(ctx, intents, now, view.Revision); err != nil {
			return out, err
		}
	} else if source.common.VerifiedRevision() != view.Revision {
		return out, corestate.ErrVerifiedRevisionStale
	}
	return LocalTransportIdentity{ID: string(config.ManagedZone), PrivateKey: bytes.Clone(private)}, nil
}

func windowsSharedPortRecord(record *ipsec.PortRecord) bool {
	if record == nil || record.Version != 1 || record.Mode != ipsec.PortModeFixed || record.Range != nil || record.Current == nil || len(record.Previous) != 0 || record.UpdatedAt != 0 {
		return false
	}
	current := record.Current
	return current.Generation == 1 && current.ValidUntil == 0 && current.IKE.Local != 0 && current.IKE.Local == current.IKE.Advertised && current.IKE.Observed == 0 && current.NATT == current.IKE
}

func validateTransportIdentity(disk transportIdentityDisk, identityPublic ed25519.PublicKey, now time.Time) (ed25519.PrivateKey, error) {
	fail := errors.New("local transport: invalid, expired, or mismatched persisted transport key")
	if disk.Record.Validate() != nil || disk.Record.Algorithm != ipsec.AlgorithmEd25519 || (disk.Record.NotBefore != 0 && now.Unix() < disk.Record.NotBefore) || (disk.Record.NotAfter != 0 && now.Unix() >= disk.Record.NotAfter) {
		return nil, fail
	}
	key, err := x509.ParsePKCS8PrivateKey(disk.PrivateKey)
	if err != nil {
		return nil, fail
	}
	private, ok := key.(ed25519.PrivateKey)
	if !ok {
		return nil, fail
	}
	public, err := ipsec.DecodeTransportPublicKey(disk.Record)
	if err != nil || !bytes.Equal(private.Public().(ed25519.PublicKey), public) || bytes.Equal(public, identityPublic) {
		return nil, fail
	}
	return private, nil
}
