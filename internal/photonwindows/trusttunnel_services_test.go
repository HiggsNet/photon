package photonwindows

import (
	"crypto/ed25519"
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	crypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	service "github.com/HiggsNet/photon/pkg/service"
)

func TestTrustTunnelDirectoryRevalidatesPinsAndAuthorization(t *testing.T) {
	for _, protocol := range []string{"trusttunnel", "http"} {
		for _, scenario := range []string{"active", "withdrawn", "bad-signature", "invalid-pin", "assignment-withdrawn"} {
			t.Run(protocol+"/"+scenario, func(t *testing.T) {
				network, _, private := signedNetwork(t)
				root := private.Public().(ed25519.PublicKey)
				network.Zones[zone.RootZone].Authority = crypto.ConfiguredRootAuthority(root)
				if err := crypto.SignDelegation(network.Zones[zone.RootZone].Delegations["catofes."], zone.RootZone, private); err != nil {
					t.Fatal(err)
				}
				now := time.Now().Truncate(time.Second)
				owner := zone.ZonePath("node-a.catofes.")
				put := func(path zone.ZonePath, key, kind string, value any) *zone.Record {
					data, _ := json.Marshal(value)
					r := &zone.Record{Zone: path, Key: key, Type: kind, Value: data, Timestamp: now.Unix(), Version: 1}
					if err := crypto.SignRecord(r, private); err != nil {
						t.Fatal(err)
					}
					network.Zones[path].Records[key] = r
					return r
				}
				pool, _ := routing.NormalizeIPAMPoolKey("fd42::/16")
				put(zone.RootZone, pool, routing.RecordTypeIPAMPool, routing.IPAMPoolRecord{Version: 1, Prefix: "fd42::/16", DelegatedTo: zone.RootZone, Active: true})
				assignment, _ := routing.NormalizeIPAMAssignmentKey("fd42:1::/64")
				put(zone.RootZone, assignment, routing.RecordTypeIPAMAssignment, routing.IPAMAssignmentRecord{Version: 1, Prefix: "fd42:1::/64", AssignedTo: owner, Active: scenario != "assignment-withdrawn"})
				active := scenario != "withdrawn"
				pin := strings.Repeat("ab", 32)
				if scenario == "invalid-pin" {
					pin = ""
				}
				var r *zone.Record
				if protocol == "trusttunnel" {
					r = put(owner, "services/trusttunnel", service.RecordTypeTrustTunnel, service.TrustTunnelRecord{Type: service.TypeTrustTunnel, Endpoints: []service.SOCKS5Endpoint{{Region: "local", Address: "fd42:1::22", Port: 4433}}, ServerName: "trusttunnel.node-a.catofes", Fingerprint: pin, Active: &active})
				} else {
					port := uint16(3128)
					if scenario == "invalid-pin" {
						port = 0
					}
					r = put(owner, "services/http", service.RecordTypeHTTP, service.HTTPRecord{Type: service.TypeHTTP, Endpoints: []service.SOCKS5Endpoint{{Region: "local", Address: "fd42:1::21", Port: port}}, AuthRequired: true, Active: &active})
				}
				if scenario == "bad-signature" {
					r.Signature[0] ^= 1
				}
				config := &Config{ManagedZone: owner, TrustedRootPublicKey: root}
				config.Wintun.AdapterName = "Photon Test"
				config.Overlay.SplitRoutes = []netip.Prefix{netip.MustParsePrefix("fd42::/16")}
				view := corestate.View{Revision: 7, State: &corestate.VerifiedState{Network: network}}
				directory, err := buildServiceDirectory(t.Context(), config, view, "test", now)
				if err != nil || len(directory.Services) != 1 {
					t.Fatal(directory, err)
				}
				entry := directory.Services[0]
				if scenario != "active" {
					if entry.Status == "active" || len(entry.Endpoints) != 0 {
						t.Fatal("unusable endpoint exposed", entry)
					}
					return
				}
				if entry.Status != "active" || len(entry.Endpoints) != 1 || entry.Endpoints[0].Type != protocol {
					t.Fatal(entry)
				}
				if protocol == "http" && !entry.Endpoints[0].AuthRequired {
					t.Fatal("HTTP auth policy lost")
				}
				if protocol == "trusttunnel" && entry.Endpoints[0].Fingerprint != pin {
					t.Fatal("certificate pin lost")
				}
			})
		}
	}
}
