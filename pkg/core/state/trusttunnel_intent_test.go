package state

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	service "github.com/HiggsNet/photon/pkg/service"
)

func TestTrustTunnelIntentLifecycle(t *testing.T) {
	install, _ := identityInstallFixture(t)
	network := zone.CloneNetworkState(install.Network)
	addDomainRecord(t, network, zone.RootZone, routing.RecordTypeIPAMPool, routing.RecordKeyPrefixIPAMPools+"fd42::_16", routing.IPAMPoolRecord{Version: 1, Prefix: "fd42::/16", DelegatedTo: zone.RootZone, Active: true})
	addDomainRecord(t, network, zone.RootZone, routing.RecordTypeIPAMAssignment, routing.RecordKeyPrefixIPAMAssignments+"fd42:1::_64", routing.IPAMAssignmentRecord{Version: 1, Prefix: "fd42:1::/64", AssignedTo: install.ManagedZone, Active: true})
	store := NewStore(&VerifiedState{ManagedZone: install.ManagedZone, Network: network, IdentityPrivateKey: install.IdentityPrivateKey}, nil, nil)
	intent := PublishTrustTunnelIntent{Service: service.TrustTunnelRecord{Type: service.TypeTrustTunnel, Endpoints: []service.SOCKS5Endpoint{{Region: "local", Address: "fd42:1::22", Port: 4433}}, ServerName: "trusttunnel.node.catofes", Fingerprint: strings.Repeat("ab", 32)}}
	now := time.Unix(1000, 0)
	result, err := store.ApplyLocalIntent(context.Background(), intent, now)
	if err != nil {
		t.Fatal(err)
	}
	if result.Record.Type != service.RecordTypeTrustTunnel || result.Record.Key != "services/trusttunnel" {
		t.Fatal(result)
	}
	if _, err := store.ApplyLocalIntent(context.Background(), WithdrawTrustTunnelIntent{}, now); err != nil {
		t.Fatal(err)
	}
	r, err := service.ParseTrustTunnelRecord(store.ReadView().State.Network.Zones[install.ManagedZone].Records["services/trusttunnel"])
	if err != nil || r.IsActive() {
		t.Fatal(r, err)
	}
	before := store.ReadView().Revision
	intent.Service.Fingerprint = ""
	if _, err := store.ApplyLocalIntent(context.Background(), intent, now); err == nil || store.ReadView().Revision != before {
		t.Fatal("invalid pin committed", err)
	}
}
