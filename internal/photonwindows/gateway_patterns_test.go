package photonwindows

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"reflect"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// Use real signed authority chains and advertisements: selectors must never
// replace the cryptographic, transport-role or overlay admission boundaries.
type gatewayPatternFixture struct {
	config  *Config
	view    corestate.View
	now     time.Time
	private ed25519.PrivateKey
}

func newGatewayPatternFixture(t *testing.T) *gatewayPatternFixture {
	t.Helper()
	network, root, private := signedNetwork(t)
	f := &gatewayPatternFixture{config: &Config{ManagedZone: "windows.catofes.", TrustedRootPublicKey: root, Overlay: OverlayConfig{ID: "main"}, Gateway: GatewayConfig{AllowedZones: []zone.ZonePath{"*.catofes."}}}, view: corestate.View{Revision: 1, State: &corestate.VerifiedState{Network: network}}, now: time.Now().Truncate(time.Second), private: private}
	f.addGateway(t, "node-a.catofes.")
	return f
}
func (f *gatewayPatternFixture) put(t *testing.T, peer zone.ZonePath, key, kind string, value any) {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	record := &zone.Record{Zone: peer, Key: key, Type: kind, Value: data, Version: 1, Timestamp: f.now.Unix()}
	if err := photoncrypto.SignRecord(record, f.private); err != nil {
		t.Fatal(err)
	}
	f.view.State.Network.Zones[peer].Records[key] = record
}
func (f *gatewayPatternFixture) ensureAuthority(t *testing.T, peer zone.ZonePath) {
	t.Helper()
	network := f.view.State.Network
	if network.Zones[peer] != nil {
		return
	}
	f.ensureAuthority(t, peer.Parent())
	authority := &zone.ZoneAuthority{Zone: peer, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: f.private.Public().(ed25519.PublicKey), Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite, zone.PermDelegate}}}}}}
	delegation := &zone.Delegation{ZoneName: peer, Authority: *authority}
	if err := photoncrypto.SignDelegation(delegation, peer.Parent(), f.private); err != nil {
		t.Fatal(err)
	}
	network.Zones[peer.Parent()].Delegations[peer] = delegation
	network.Zones[peer] = zone.NewZoneState(peer, authority)
}
func (f *gatewayPatternFixture) addGateway(t *testing.T, peer zone.ZonePath) {
	t.Helper()
	f.ensureAuthority(t, peer)
	_, key, err := ipsec.GenerateTransportKeyRecord(ipsec.AlgorithmEd25519, f.now, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	f.put(t, peer, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, ipsec.ProfileRecord{Version: 1, Enabled: true, Provider: ipsec.ProviderStrongSwan, IKEIdentity: string(peer), TransportKeyFingerprint: key.Fingerprint, Role: ipsec.RoleIn, AddressFamilies: []string{ipsec.FamilyIPv4}, PathModes: []string{ipsec.PathModeFamilyRedundant}})
	f.put(t, peer, ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, key)
	f.put(t, peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{Version: 1, UpdatedAt: f.now.Unix(), Addresses: []ipsec.AddressAdvertisement{{ID: "signed", Source: ipsec.SourceManualAddress, Address: "192.0.2.1", Family: ipsec.FamilyIPv4, TTLSeconds: 60}}})
	f.put(t, peer, ipsec.RecordKeyPorts, ipsec.RecordTypePorts, ipsec.PortRecord{Version: 1, Mode: ipsec.PortModeFixed, Current: &ipsec.PortSelection{Generation: 1, IKE: ipsec.PortBinding{Advertised: 500}, NATT: ipsec.PortBinding{Advertised: 4500}}})
	f.put(t, peer, ipsec.OverlayIntentRecordKey("main"), ipsec.RecordTypeOverlayIntent, ipsec.OverlayIntentRecord{Version: 1, OverlayID: "main", Provider: ipsec.ProviderStrongSwan, PathKeys: []string{ipsec.DefaultPathKey}, TunnelAddress: ipsec.TunnelAddressSpec{Mode: ipsec.TunnelAddressDisabled}})
}
func gatewayPatternZones(candidates []GatewayCandidate) []zone.ZonePath {
	var result []zone.ZonePath
	for _, candidate := range candidates {
		result = append(result, candidate.Zone)
	}
	return result
}

func TestGatewayPatternsPreserveLiteralPriorityAndDeduplicateSortedMatches(t *testing.T) {
	f := newGatewayPatternFixture(t)
	f.addGateway(t, "a.catofes.")
	f.addGateway(t, "b.catofes.")
	f.addGateway(t, f.config.ManagedZone)
	f.config.Gateway.AllowedZones = []zone.ZonePath{"b.catofes.", "*.catofes.", "a.catofes.", "missing.catofes."}
	want := []zone.ZonePath{"b.catofes.", "a.catofes.", "node-a.catofes.", "missing.catofes."}
	for range 8 {
		got := GatewayCandidates(f.config, f.view, f.now)
		if !reflect.DeepEqual(gatewayPatternZones(got), want) {
			t.Fatalf("selector ordering/dedup: %v", gatewayPatternZones(got))
		}
		if got[0].Rejected != "" || got[len(got)-1].Rejected == "" {
			t.Fatal("literal priority or missing identity diagnostic changed")
		}
		plan := planGateway(context.Background(), f.config, f.view, f.now, nil)
		if plan.Selected == nil || plan.Selected.Zone != "b.catofes." {
			t.Fatalf("literal priority did not select one stable active candidate: %+v", plan)
		}
	}
	f.config.Gateway.AllowedZones = []zone.ZonePath{"missing.catofes.", "*.catofes."}
	got := GatewayCandidates(f.config, f.view, f.now)
	if len(got) != 4 || got[0].Zone != "missing.catofes." || got[0].Rejected == "" {
		t.Fatal("exact missing selector no longer has its configured diagnostic position")
	}
}

func TestGatewayPatternsStarAndSuffixUseConcreteKnownIdentities(t *testing.T) {
	f := newGatewayPatternFixture(t)
	f.addGateway(t, f.config.ManagedZone)
	f.addGateway(t, "leaf.deep.catofes.")
	f.view.State.Network.Zones["outside.example."] = zone.NewZoneState("outside.example.", nil)
	f.config.Gateway.AllowedZones = []zone.ZonePath{"*"}
	got := GatewayCandidates(f.config, f.view, f.now)
	for _, candidate := range got {
		if candidate.Zone.IsRoot() || candidate.Zone == f.config.ManagedZone || !candidate.Zone.Valid() {
			t.Fatalf("glob produced a root, self or selector identity: %+v", candidate)
		}
		if candidate.Zone == "catofes." && candidate.Rejected == "" {
			t.Fatal("known zone without IPsec records was trusted")
		}
	}
	if len(got) != 5 {
		t.Fatalf("'*' should diagnose all five concrete nonroot/nonself identities: %v", gatewayPatternZones(got))
	}
	f.config.Gateway.AllowedZones = []zone.ZonePath{"leaf.*.catofes."}
	got = GatewayCandidates(f.config, f.view, f.now)
	if len(got) != 1 || got[0].Zone != "leaf.deep.catofes." || got[0].Rejected != "" {
		t.Fatalf("suffix glob did not follow shared path.Match semantics: %+v", got)
	}
	f.config.Gateway.AllowedZones = []zone.ZonePath{"*.catofes."}
	got = GatewayCandidates(f.config, f.view, f.now)
	if !reflect.DeepEqual(gatewayPatternZones(got), []zone.ZonePath{"deep.catofes.", "leaf.deep.catofes.", "node-a.catofes."}) {
		t.Fatalf("'*' must also match dot-separated prefixes, without matching another suffix: %v", gatewayPatternZones(got))
	}
}

func TestGatewayPatternsRetainEverySignedAdmissionGate(t *testing.T) {
	const peer zone.ZonePath = "node-a.catofes."
	for _, scenario := range []string{"valid", "wrong-root", "unsigned", "missing-profile", "hint-only", "wrong-overlay", "outbound", "disabled", "revoked", "expired-delegation", "expired-transport", "expired-address", "expired-authority"} {
		t.Run(scenario, func(t *testing.T) {
			f := newGatewayPatternFixture(t)
			network := f.view.State.Network
			records := network.Zones[peer].Records
			switch scenario {
			case "wrong-root":
				f.config.TrustedRootPublicKey, _, _ = ed25519.GenerateKey(nil)
			case "unsigned":
				records[ipsec.RecordKeyAddresses].Signature = nil
			case "missing-profile":
				delete(records, ipsec.RecordKeyProfile)
			case "hint-only":
				network.Zones[peer].Records = nil
				f.config.Gateway.BootstrapHints = []BootstrapHint{{Peer: peer, Address: "192.0.2.99:4500"}}
			case "wrong-overlay":
				delete(records, ipsec.OverlayIntentRecordKey("main"))
			case "outbound", "disabled":
				profile, err := ipsec.ParseProfileRecord(records[ipsec.RecordKeyProfile])
				if err != nil {
					t.Fatal(err)
				}
				if scenario == "outbound" {
					profile.Role = ipsec.RoleOut
				} else {
					profile.Enabled = false
				}
				f.put(t, peer, ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, profile)
			case "revoked":
				old := network.Zones[peer.Parent()].Delegations[peer]
				revocation := &zone.DelegationRevocation{ChildZone: peer, ParentZone: peer.Parent(), RevokedAuthorityEpoch: old.AuthorityEpoch, RevokedAuthorityHash: append([]byte(nil), old.AuthorityHash...), RevokedAt: f.now.Unix()}
				if err := photoncrypto.SignDelegationRevocation(revocation, peer.Parent(), f.private); err != nil {
					t.Fatal(err)
				}
				network.Zones[peer.Parent()].Revocations[peer] = revocation
			case "expired-delegation":
				delegation := network.Zones[peer.Parent()].Delegations[peer]
				expired := f.now.Add(-time.Second)
				delegation.ExpiresAt = &expired
				if err := photoncrypto.SignDelegation(delegation, peer.Parent(), f.private); err != nil {
					t.Fatal(err)
				}
			case "expired-transport":
				key, err := ipsec.ParseTransportKeyRecord(records[ipsec.RecordKeyTransportKey])
				if err != nil {
					t.Fatal(err)
				}
				key.NotAfter = f.now.Unix()
				f.put(t, peer, ipsec.RecordKeyTransportKey, ipsec.RecordTypeTransportKey, key)
			case "expired-address":
				addresses, err := ipsec.ParseAddressRecord(records[ipsec.RecordKeyAddresses])
				if err != nil {
					t.Fatal(err)
				}
				addresses.UpdatedAt = f.now.Add(-2 * time.Minute).Unix()
				f.put(t, peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, addresses)
			case "expired-authority":
				authority := network.Zones[peer].Authority
				authority.Keys[0].NotAfter = f.now.Add(-time.Second).Unix()
				delegation := network.Zones[peer.Parent()].Delegations[peer]
				delegation.Authority = *authority
				if err := photoncrypto.SignDelegation(delegation, peer.Parent(), f.private); err != nil {
					t.Fatal(err)
				}
			}
			got := GatewayCandidates(f.config, f.view, f.now)
			if len(got) != 1 || got[0].Zone != peer {
				t.Fatalf("lost concrete gateway diagnosis: %+v", got)
			}
			if scenario == "valid" {
				if got[0].Rejected != "" || len(got[0].Contacts) != 1 || got[0].Contacts[0].Address != "192.0.2.1" {
					t.Fatalf("valid wildcard gateway: %+v", got)
				}
			} else if got[0].Rejected == "" || len(got[0].Contacts) != 0 || len(got[0].PublicKey) != 0 {
				t.Fatalf("wildcard or hint bypassed %s: %+v", scenario, got)
			}
		})
	}
}

func TestGatewayPatternsReevaluateNewViewsAndRetireRemovedOrDisabledNodes(t *testing.T) {
	f := newGatewayPatternFixture(t)
	before := planGateway(context.Background(), f.config, f.view, f.now, nil)
	if before.Selected == nil || before.Selected.Zone != "node-a.catofes." {
		t.Fatal("initial gateway unavailable")
	}
	// Publish a new detached view, as a Gossip revision would. No cached list
	// or pre-expanded config may be necessary to discover the new identity.
	oldView := f.view
	copied := *f.view.State
	copied.Network = zone.CloneNetworkState(f.view.State.Network)
	f.view = corestate.View{Revision: oldView.Revision + 1, State: &copied}
	f.addGateway(t, "a-new.catofes.")
	after := planGateway(context.Background(), f.config, f.view, f.now, nil)
	if after.Selected == nil || after.Selected.Zone != "a-new.catofes." || len(after.Candidates) != 2 {
		t.Fatalf("new matching identity was not discovered from the next view: %+v", after)
	}
	if len(GatewayCandidates(f.config, oldView, f.now)) != 1 {
		t.Fatal("new view mutated the previous snapshot")
	}
	removed := zone.CloneNetworkState(f.view.State.Network)
	delete(removed.Zones, "a-new.catofes.")
	copied.Network = removed
	f.view.Revision++
	after = planGateway(context.Background(), f.config, f.view, f.now, nil)
	if after.Selected == nil || after.Selected.Zone != "node-a.catofes." || len(after.Candidates) != 1 {
		t.Fatal("removed matching identity remained eligible")
	}
	profile, _ := ipsec.ParseProfileRecord(copied.Network.Zones["node-a.catofes."].Records[ipsec.RecordKeyProfile])
	profile.Enabled = false
	f.put(t, "node-a.catofes.", ipsec.RecordKeyProfile, ipsec.RecordTypeProfile, profile)
	f.view.Revision++
	if current := revalidateActiveGateway(f.config, f.view, before, f.now); current.Selected != nil {
		t.Fatal("disabled matched identity remained eligible for the previous active plan")
	}
	if current := GatewayCandidates(f.config, f.view, f.now); len(current) != 1 || current[0].Rejected == "" {
		t.Fatal("disabled matching identity lost its rejection diagnosis")
	}
	// Same immutable revision, later time still rechecks signed TTLs.
	if current := GatewayCandidates(f.config, oldView, f.now.Add(2*time.Minute)); len(current) != 1 || current[0].Rejected == "" {
		t.Fatal("glob retained an expired contact without a revision change")
	}
}

func TestGatewayPatternsShareTheExistingDNSBudget(t *testing.T) {
	f := newGatewayPatternFixture(t)
	f.addGateway(t, "node-b.catofes.")
	for _, peer := range []zone.ZonePath{"node-a.catofes.", "node-b.catofes."} {
		f.put(t, peer, ipsec.RecordKeyAddresses, ipsec.RecordTypeAddresses, ipsec.AddressRecord{Version: 1, UpdatedAt: f.now.Unix(), Addresses: []ipsec.AddressAdvertisement{{ID: "dns", Source: ipsec.SourceManualDNS, Host: "gateway.example", Family: ipsec.FamilyIPv4, TTLSeconds: 60}}})
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	started := time.Now()
	plan := planGateway(ctx, f.config, f.view, f.now, blockingGatewayResolver{})
	if plan.Selected != nil || plan.Rejected == "" || len(plan.Candidates) != 2 || time.Since(started) > time.Second {
		t.Fatalf("expanded peers gained separate DNS budgets: %+v", plan)
	}
}
