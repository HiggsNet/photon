package photonwindows

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

func TestServiceDirectoryRevalidatesSignedFacts(t *testing.T) {
	for _, scenario := range []string{"active", "withdrawn", "bad-signature", "wrong-owner", "bad-json", "assignment-withdrawn", "assignment-signature", "authority-expired", "revoked", "wrong-root"} {
		t.Run(scenario, func(t *testing.T) {
			network, _, private := signedNetwork(t)
			root := private.Public().(ed25519.PublicKey)
			network.Zones[zone.RootZone].Authority = photoncrypto.ConfiguredRootAuthority(root)
			if err := photoncrypto.SignDelegation(network.Zones[zone.RootZone].Delegations["catofes."], zone.RootZone, private); err != nil {
				t.Fatal(err)
			}
			now := time.Now().Truncate(time.Second)
			owner := zone.ZonePath("node-a.catofes.")
			put := func(path zone.ZonePath, key, kind string, value any) *zone.Record {
				t.Helper()
				data, err := json.Marshal(value)
				if err != nil {
					t.Fatal(err)
				}
				record := &zone.Record{Zone: path, Key: key, Type: kind, Value: data, Timestamp: now.Unix(), Version: 1}
				if err := photoncrypto.SignRecord(record, private); err != nil {
					t.Fatal(err)
				}
				network.Zones[path].Records[key] = record
				return record
			}
			poolKey, _ := routing.NormalizeIPAMPoolKey("fd42::/16")
			put(zone.RootZone, poolKey, routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{Version: 1, Prefix: "fd42::/16", DelegatedTo: zone.RootZone, Active: true})
			assignmentKey, _ := routing.NormalizeIPAMAssignmentKey("fd42:1::/64")
			assignment := put(zone.RootZone, assignmentKey, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: "fd42:1::/64", AssignedTo: owner, Active: scenario != "assignment-withdrawn"})
			active := scenario != "withdrawn"
			service := put(owner, "services/socks5", photonservice.RecordTypeSOCKS5, photonservice.SOCKS5Record{Type: "socks5", Active: &active, Endpoints: []photonservice.SOCKS5Endpoint{{Region: "cn", Address: "fd42:1::20", Port: 1080}, {Region: "jp", Address: "fd42:1::21", Port: 2080}}})
			config := &Config{ManagedZone: owner, TrustedRootPublicKey: root}
			config.Wintun.AdapterName = "Photon Test"
			config.Overlay.SplitRoutes = []netip.Prefix{netip.MustParsePrefix("fd42::/16")}
			config.Gateway.BootstrapHints = []BootstrapHint{{Address: "192.0.2.5:33434"}, {Address: "[2001:db8::5]:33434"}, {Address: "bootstrap.example:33434"}}
			switch scenario {
			case "bad-signature":
				service.Signature[0] ^= 1
			case "assignment-signature":
				assignment.Signature[0] ^= 1
			case "bad-json":
				service.Value = []byte(`{"type":"socks5","endpoints":[]}`)
				_ = photoncrypto.SignRecord(service, private)
			case "wrong-owner":
				service.Zone = "other.catofes."
				_ = photoncrypto.SignRecord(service, private)
			case "authority-expired":
				network.Zones[owner].Authority.Keys[0].NotAfter = now.Add(-time.Second).Unix()
			case "revoked":
				revocation := &zone.DelegationRevocation{ChildZone: owner, ParentZone: owner.Parent(), RevokedAuthorityEpoch: 1, RevokedAt: now.Unix()}
				if err := photoncrypto.SignDelegationRevocation(revocation, owner.Parent(), private); err != nil {
					t.Fatal(err)
				}
				network.Zones[owner.Parent()].Revocations[owner] = revocation
			case "wrong-root":
				config.TrustedRootPublicKey = make(ed25519.PublicKey, ed25519.PublicKeySize)
			}
			view := corestate.View{Revision: 7, State: &corestate.VerifiedState{Network: network}}
			got, err := buildServiceDirectory(t.Context(), config, view, "instance-one", now)
			if scenario == "wrong-root" {
				if err == nil {
					t.Fatal("wrong trust root accepted")
				}
				return
			}
			if err != nil || len(got.Services) != 1 {
				t.Fatal(got, err)
			}
			if got.InstanceID != "instance-one" || got.Revision != 7 || !got.ValidUntil.Equal(now.Add(5*time.Second)) {
				t.Fatal("missing snapshot identity or bounded freshness", got)
			}
			if got.AdapterName != "Photon Test" || len(got.BypassPrefixes) != 3 {
				t.Fatal("missing adapter or exact bootstrap/split bypasses", got)
			}
			entry := got.Services[0]
			if scenario != "active" {
				if entry.Status == "active" || len(entry.Endpoints) != 0 {
					t.Fatal("unusable endpoint exposed", entry)
				}
				return
			}
			if entry.Status != "active" || len(entry.Endpoints) != 2 || entry.Endpoints[0].ID == entry.Endpoints[1].ID {
				t.Fatal("multi-endpoint service missing", entry)
			}
			ids := []string{entry.Endpoints[0].ID, entry.Endpoints[1].ID}
			changed := *service
			changed.Version++
			if err := photoncrypto.SignRecord(&changed, private); err != nil {
				t.Fatal(err)
			}
			network.Zones[owner].Records[changed.Key] = &changed
			again, err := buildServiceDirectory(t.Context(), config, view, "instance-two", now)
			if err != nil || again.Services[0].Endpoints[0].ID != ids[0] || again.Services[0].Endpoints[1].ID != ids[1] {
				t.Fatal("stable endpoint identity changed on refresh/restart", again, err)
			}
			network.Zones[owner].Authority.Keys[0].NotAfter = now.Add(time.Second).Unix()
			later, err := buildServiceDirectory(t.Context(), config, view, "instance-two", now.Add(2*time.Second))
			if err != nil || later.Services[0].Status == "active" || len(later.Services[0].Endpoints) != 0 {
				t.Fatal("expired authority retained at the same revision", later, err)
			}
		})
	}
}

func TestServiceDirectoryDaemonLifecycle(t *testing.T) {
	a, b := NewDaemon(nil, nil), NewDaemon(nil, nil)
	if a.instanceID == "" || a.instanceID == b.instanceID {
		t.Fatal("daemon instance IDs are not unique")
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := a.Services(ctx); err == nil {
		t.Fatal("query ignored cancellation")
	}
	close(a.done)
	if _, err := a.Services(t.Context()); err == nil {
		t.Fatal("stopped daemon returned a directory")
	}
}
