package photonwindows

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	bolt "go.etcd.io/bbolt"
)

func transportIdentityFixture(t *testing.T) (*State, *Config, GatewayPlan, time.Time) {
	t.Helper()
	path, network, root, private := saveCommonState(t, 7)
	now := time.Now().Truncate(time.Second)
	peer := zone.ZonePath("gateway.catofes.")
	authority := *network.Zones["node-a.catofes."].Authority
	authority.Zone = peer
	delegation := &zone.Delegation{ZoneName: peer, Authority: authority}
	if err := photoncrypto.SignDelegation(delegation, "catofes.", private); err != nil {
		t.Fatal(err)
	}
	network.Zones["catofes."].Delegations[peer] = delegation
	network.Zones[peer] = zone.NewZoneState(peer, &authority)
	_, key, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	put := func(key, kind string, value any) {
		encoded, _ := json.Marshal(value)
		record := &zone.Record{Zone: peer, Key: key, Type: kind, Value: encoded, Version: 1, Timestamp: now.Unix()}
		if err := photoncrypto.SignRecord(record, private); err != nil {
			t.Fatal(err)
		}
		network.Zones[peer].Records[key] = record
	}
	put(ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, key)
	put(ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{Version: 1, Enabled: true, Provider: ipsec.ProviderStrongSwan, Role: ipsec.RoleIn, IKEIdentity: string(peer), TransportKeyFingerprint: key.Fingerprint, AddressFamilies: []string{ipsec.FamilyIPv4}, PathModes: []string{ipsec.PathModeFamilyRedundant}})
	put(ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{Version: 1, Addresses: []ipsec.AddressAdvertisement{{ID: "public", Source: ipsec.SourceManualAddress, Address: "192.0.2.10", Family: ipsec.FamilyIPv4}}})
	put(ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed, Current: &ipsec.PortSelection{Generation: 1, IKE: ipsec.PortBinding{Advertised: 500}, NATT: ipsec.PortBinding{Advertised: 4500}}})
	put(ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{Version: 1, OverlayID: "main", Provider: ipsec.ProviderStrongSwan, PathKeys: []string{"family:ipv4"}, TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDisabled}})
	store, err := corestate.OpenBoltStore(path, 0o600, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &corestate.CommitCandidate{Verified: &corestate.VerifiedState{ManagedZone: "node-a.catofes.", TrustedRootPublicKey: root, IdentityPrivateKey: private, Network: network}, Gossip: &corestate.GossipCheckpoint{}}
	if err := store.CommitCommon(context.Background(), candidate, corestate.ChangeSet{VerifiedRevision: 8, NetworkChanged: true}); err != nil {
		t.Fatal(err)
	}
	store.Close()
	config := &Config{ManagedZone: "node-a.catofes.", TrustedRootPublicKey: root, State: StateConfig{Path: path}, Overlay: OverlayConfig{ID: "main", SplitRoutes: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, Gateway: GatewayConfig{AllowedZones: []zone.ZonePath{peer}}}
	source, err := OpenState(path, config.ManagedZone, root, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { source.Close() })
	plan := PlanGateway(t.Context(), config, source.Store().ReadView(), now)
	if plan.Selected == nil {
		t.Fatalf("fixture plan failed: %s", plan.Rejected)
	}
	return source, config, plan, now
}

func TestLocalTransportPersistsSignsAndRestarts(t *testing.T) {
	source, config, plan, now := transportIdentityFixture(t)
	identity, err := source.EnsureLocalTransport(t.Context(), config, now, plan)
	if err != nil {
		t.Fatal(err)
	}
	view := source.Store().ReadView()
	if identity.ID != string(config.ManagedZone) || bytes.Equal(identity.PrivateKey, view.State.IdentityPrivateKey) {
		t.Fatal("transport reused signing identity")
	}
	local := view.State.Network.Zones[config.ManagedZone]
	for _, key := range []string{ipsec.RecordKeyProfile, ipsec.RecordKeyTransportKey, ipsec.OverlayIntentRecordKey("main")} {
		if err := photoncrypto.VerifyRecord(local.Records[key], local.Authority, now); err != nil {
			t.Fatal(err)
		}
	}
	published, _ := ipsec.ParseTransportKeyRecord(local.Records[ipsec.RecordKeyTransportKey])
	public, _ := ipsec.DecodeTransportPublicKey(*published)
	if !bytes.Equal(public, identity.PrivateKey.Public().(ed25519.PublicKey)) {
		t.Fatal("published key differs")
	}
	revision := view.Revision
	plan = PlanGateway(t.Context(), config, view, now)
	second, err := source.EnsureLocalTransport(t.Context(), config, now.Add(time.Second), plan)
	if err != nil || !bytes.Equal(identity.PrivateKey, second.PrivateKey) || source.Store().VerifiedRevision() != revision {
		t.Fatalf("idempotence failed: %v", err)
	}
	second.PrivateKey[0] ^= 1
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	plan = PlanGateway(t.Context(), config, reopened.Store().ReadView(), now)
	third, err := reopened.EnsureLocalTransport(t.Context(), config, now, plan)
	if err != nil || !bytes.Equal(identity.PrivateKey, third.PrivateKey) || reopened.Store().VerifiedRevision() != revision {
		t.Fatalf("restart changed identity: %v", err)
	}
}

func TestLocalTransportResumesPrivateCommitBeforePublic(t *testing.T) {
	source, config, plan, now := transportIdentityFixture(t)
	key, record, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, 0)
	if err != nil {
		t.Fatal(err)
	}
	disk := transportIdentityDisk{PrivateKey: key.PrivateKey, Record: *record}
	encoded, _ := json.Marshal(disk)
	if err := source.bolt.Update(func(tx *bolt.Tx) (bool, error) {
		bucket, err := tx.CreateBucketIfNotExists(windowsTransportBucket)
		if err != nil {
			return false, err
		}
		return true, bucket.Put(windowsTransportKey, encoded)
	}); err != nil {
		t.Fatal(err)
	}
	if err := source.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer reopened.Close()
	identity, err := reopened.EnsureLocalTransport(t.Context(), config, now, plan)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(identity.PrivateKey.Public().(ed25519.PublicKey), key.PublicKey) {
		t.Fatal("restart rotated persisted unpublished key")
	}
}

func TestLocalTransportRejectsForeignOrStaleRecords(t *testing.T) {
	for _, scenario := range []string{"foreign-key", "stale-plan", "mismatched-private", "identity-key", "sequential-pool", "closed-persistence"} {
		t.Run(scenario, func(t *testing.T) {
			source, config, plan, now := transportIdentityFixture(t)
			view := source.Store().ReadView()
			switch scenario {
			case "foreign-key":
				_, record, _ := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, 0)
				encoded, _ := json.Marshal(record)
				_, err := source.Store().ApplyLocalIntent(t.Context(), corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordIPsec, Zone: config.ManagedZone, Key: ipsec.RecordKeyTransportKey, Type: ipsec.RecordTypeTransportKey, Value: encoded}, now)
				if err != nil {
					t.Fatal(err)
				}
				plan = PlanGateway(t.Context(), config, source.Store().ReadView(), now)
			case "stale-plan":
				plan.Revision--
			case "mismatched-private", "identity-key":
				key, record, _ := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, 0)
				other, _, _ := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, 0)
				if scenario == "mismatched-private" {
					key.PrivateKey = other.PrivateKey
				} else {
					key.PrivateKey, _ = x509.MarshalPKCS8PrivateKey(view.State.IdentityPrivateKey)
					record, _ = ipsec.NewTransportKeyRecord(ipsec.AlgorithmEd25519, view.State.IdentityPrivateKey.Public().(ed25519.PublicKey), now, 0)
				}
				encoded, _ := json.Marshal(transportIdentityDisk{PrivateKey: key.PrivateKey, Record: *record})
				if err := source.bolt.Update(func(tx *bolt.Tx) (bool, error) {
					b, e := tx.CreateBucketIfNotExists(windowsTransportBucket)
					if e != nil {
						return false, e
					}
					return true, b.Put(windowsTransportKey, encoded)
				}); err != nil {
					t.Fatal(err)
				}
			case "sequential-pool":
				// Publish a correctly signed but unsupported allocation mode.
				peer := plan.Selected.Zone
				record := view.State.Network.Zones[peer].Records[ipsec.OverlayIntentRecordKey("main")]
				intent, _ := ipsec.ParseOverlayIntentRecord(record)
				intent.TunnelAddress = ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressSequentialPool, Family: ipsec.FamilyIPv4, Pool: netip.MustParsePrefix("10.10.0.0/16")}
				encoded, _ := json.Marshal(intent)
				_, err := source.Store().ApplyLocalIntent(t.Context(), corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordIPsec, Zone: peer, Key: record.Key, Type: record.Type, Value: encoded}, now)
				if err != nil {
					t.Fatal(err)
				}
				plan = PlanGateway(t.Context(), config, source.Store().ReadView(), now)
			case "closed-persistence":
				source.bolt.Close()
			}
			before := source.Store().VerifiedRevision()
			if identity, err := source.EnsureLocalTransport(t.Context(), config, now, plan); err == nil || identity.PrivateKey != nil {
				t.Fatal("unsafe identity accepted")
			}
			if source.Store().VerifiedRevision() != before {
				t.Fatal("failure published partial public records")
			}
		})
	}
}

func TestLocalTransportDerivedTunnelAndPreservedIntent(t *testing.T) {
	for _, spec := range []ipsec.TunnelAddressSpec{
		{Mode: ipsec.TunnelAddressDerivedLinkLocal, Family: ipsec.FamilyIPv6},
		{Mode: ipsec.TunnelAddressDerivedPool, Family: ipsec.FamilyIPv4, Pool: netip.MustParsePrefix("10.20.0.0/16")},
	} {
		t.Run(string(spec.Mode), func(t *testing.T) {
			source, config, plan, now := transportIdentityFixture(t)
			peer := plan.Selected.Zone
			intent := ipsec.OverlayIntentRecord{Version: 1, OverlayID: "main", Provider: ipsec.ProviderStrongSwan, PathKeys: []string{"family:ipv4"}, TunnelAddress: spec, UpdatedAt: now.Unix()}
			put := func(path zone.ZonePath, value ipsec.OverlayIntentRecord) {
				t.Helper()
				encoded, _ := json.Marshal(value)
				if _, err := source.Store().ApplyLocalIntent(t.Context(), corestate.PutProtocolRecordIntent{Kind: corestate.ProtocolRecordIPsec, Zone: path, Key: ipsec.OverlayIntentRecordKey("main"), Type: ipsec.RecordTypeOverlayIntent, Value: encoded}, now); err != nil {
					t.Fatal(err)
				}
			}
			put(peer, intent)
			intent.PolicyTags = []string{"user-owned-tag"}
			put(config.ManagedZone, intent)
			before := bytes.Clone(source.Store().ReadView().State.Network.Zones[config.ManagedZone].Records[ipsec.OverlayIntentRecordKey("main")].Value)
			plan = PlanGateway(t.Context(), config, source.Store().ReadView(), now)
			if _, err := source.EnsureLocalTransport(t.Context(), config, now, plan); err != nil {
				t.Fatal(err)
			}
			after := source.Store().ReadView().State.Network.Zones[config.ManagedZone].Records[ipsec.OverlayIntentRecordKey("main")].Value
			if !bytes.Equal(before, after) {
				t.Fatal("existing intent changed")
			}
			group := ipsec.LinkGroupSpec{ID: "main", Provider: ipsec.ProviderStrongSwan, TunnelAddressSpec: spec}
			local, remote, err := group.DeriveTunnelAddressesForLink(config.ManagedZone, peer, "", "family:ipv4", 0, 0)
			if err != nil || !local.IsValid() || local == remote {
				t.Fatalf("derived addresses overlap: %v", err)
			}
			reverseRemote, reverseLocal, err := group.DeriveTunnelAddressesForLink(peer, config.ManagedZone, "", "family:ipv4", 0, 0)
			if err != nil || local != reverseLocal || remote != reverseRemote {
				t.Fatal("peer derivation did not mirror addresses")
			}
		})
	}
}
