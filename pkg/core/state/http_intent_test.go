package state

import (
	"context"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	service "github.com/HiggsNet/photon/pkg/service"
)

func TestHTTPIntentLifecycleAndAuthorization(t *testing.T) {
	install, _ := identityInstallFixture(t)
	network := zone.CloneNetworkState(install.Network)
	addDomainRecord(t, network, zone.RootZone, routing.RecordTypeIPAMPool, routing.RecordKeyPrefixIPAMPools+"fd42::_16", routing.IPAMPoolRecord{Version: 1, Prefix: "fd42::/16", DelegatedTo: zone.RootZone, Active: true})
	addDomainRecord(t, network, zone.RootZone, routing.RecordTypeIPAMAssignment, routing.RecordKeyPrefixIPAMAssignments+"fd42:1::_64", routing.IPAMAssignmentRecord{Version: 1, Prefix: "fd42:1::/64", AssignedTo: install.ManagedZone, Active: true})
	store := NewStore(&VerifiedState{ManagedZone: install.ManagedZone, Network: network, IdentityPrivateKey: install.IdentityPrivateKey}, nil, nil)
	intent := PublishHTTPIntent{Service: service.HTTPRecord{Type: service.TypeHTTP, Endpoints: []service.SOCKS5Endpoint{{Region: "local", Address: "fd42:1::21", Port: 3128}}, AuthRequired: true}}
	now := time.Unix(1000, 0)
	result, err := store.ApplyLocalIntent(context.Background(), intent, now)
	if err != nil || result.Record.Key != "services/http" || result.Record.Type != service.RecordTypeHTTP {
		t.Fatal(result, err)
	}
	if _, err := store.ApplyLocalIntent(context.Background(), WithdrawHTTPIntent{}, now); err != nil {
		t.Fatal(err)
	}
	parsed, err := service.ParseHTTPRecord(store.ReadView().State.Network.Zones[install.ManagedZone].Records["services/http"])
	if err != nil || parsed.IsActive() {
		t.Fatal(parsed, err)
	}
	before := store.ReadView().Revision
	if _, err := store.ApplyLocalIntent(context.Background(), WithdrawHTTPIntent{}, now); err != nil || store.ReadView().Revision != before {
		t.Fatal("withdrawal retry must be idempotent", err)
	}
	intent.Service.Endpoints[0].Address = "fd42:2::21"
	if _, err := store.ApplyLocalIntent(context.Background(), intent, now); err == nil || store.ReadView().Revision != before {
		t.Fatal("unauthorized HTTP endpoint committed")
	}
}
