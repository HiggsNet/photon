package photonwindows

import (
	"crypto/ed25519"
	"encoding/json"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestGatewayCandidatesRequireSignedTransportFacts(t *testing.T) {
	for _, scenario := range []string{"valid", "hint-only", "bad-signature", "wrong-identity", "wrong-fingerprint", "expired-key", "expired-address", "wrong-overlay", "outbound-only", "expired-authority", "revoked"} {
		t.Run(scenario, func(t *testing.T) {
			network, root, private := signedNetwork(t)
			now := time.Now()
			peer := zone.ZonePath("node-a.catofes.")
			config := &Config{ManagedZone: "windows.catofes.", TrustedRootPublicKey: root, Overlay: OverlayConfig{ID: "main"}, Gateway: GatewayConfig{AllowedZones: []zone.ZonePath{peer}, BootstrapHints: []BootstrapHint{{Peer: peer, Address: "192.0.2.99:4500"}}}}
			_, key, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, now, time.Hour)
			if err != nil {
				t.Fatal(err)
			}
			profile := ipsec.ProfileRecord{Version: 1, Enabled: true, Provider: ipsec.ProviderStrongSwan, IKEIdentity: string(peer), TransportKeyFingerprint: key.Fingerprint, Role: ipsec.RoleIn, AddressFamilies: []string{ipsec.FamilyIPv4}, PathModes: []string{ipsec.PathModeFamilyRedundant}}
			addresses := ipsec.AddressRecord{Version: 1, UpdatedAt: now.Unix(), Addresses: []ipsec.AddressAdvertisement{{ID: "public", Source: ipsec.SourceManualAddress, Address: "192.0.2.1", Family: ipsec.FamilyIPv4, TTLSeconds: 60}}}
			switch scenario {
			case "wrong-identity":
				profile.IKEIdentity = "other."
			case "wrong-fingerprint":
				profile.TransportKeyFingerprint = "wrong"
			case "expired-key":
				key.NotBefore = now.Add(-time.Hour).Unix()
				key.NotAfter = now.Unix()
			case "expired-address":
				addresses.UpdatedAt = now.Add(-2 * time.Minute).Unix()
			case "outbound-only":
				profile.Role = ipsec.RoleOut
			}
			put := func(name, kind string, value any) {
				t.Helper()
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				record := &zone.Record{Zone: peer, Key: name, Type: kind, Value: data, Version: 1, Timestamp: now.Unix()}
				if err := photoncrypto.SignRecord(record, ed25519.PrivateKey(private)); err != nil {
					t.Fatal(err)
				}
				network.Zones[peer].Records[name] = record
			}
			put(ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, profile)
			put(ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, addresses)
			put(ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, key)
			put(ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed, Current: &ipsec.PortSelection{Generation: 1, IKE: ipsec.PortBinding{Advertised: 500}, NATT: ipsec.PortBinding{Advertised: 4500}}})
			put(ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{Version: 1, OverlayID: "main", Provider: ipsec.ProviderStrongSwan, PathKeys: []string{ipsec.DefaultPathKey}, TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDisabled}})
			switch scenario {
			case "hint-only":
				network.Zones[peer].Records = nil
			case "bad-signature":
				network.Zones[peer].Records[ipsec.RecordKeyAddresses].Signature[0] ^= 1
			case "wrong-overlay":
				delete(network.Zones[peer].Records, ipsec.OverlayIntentRecordKey("main"))
			case "expired-authority":
				network.Zones[peer].Authority.Keys[0].NotAfter = now.Add(-time.Second).Unix()
			case "revoked":
				revocation := &zone.DelegationRevocation{ChildZone: peer, ParentZone: peer.Parent(), RevokedAuthorityEpoch: 1, RevokedAt: now.Unix()}
				if err := photoncrypto.SignDelegationRevocation(revocation, peer.Parent(), private); err != nil {
					t.Fatal(err)
				}
				network.Zones[peer.Parent()].Revocations[peer] = revocation
			}
			view := corestate.View{Revision: 1, State: &corestate.VerifiedState{Network: network}}
			got := GatewayCandidates(config, view, now)
			if len(got) != 1 {
				t.Fatal("missing diagnosis")
			}
			if scenario != "valid" {
				if got[0].Rejected == "" || len(got[0].Contacts) != 0 {
					t.Fatalf("invalid candidate accepted: %+v", got)
				}
				return
			}
			if got[0].Rejected != "" || len(got[0].Contacts) != 1 || got[0].Contacts[0].Address != "192.0.2.1" {
				t.Fatalf("valid candidate: %+v", got)
			}
			// Same revision, later time: signed address TTL must be re-evaluated.
			if later := GatewayCandidates(config, view, now.Add(2*time.Minute)); later[0].Rejected == "" {
				t.Fatal("expired contact retained without revision change")
			}
		})
	}
}
