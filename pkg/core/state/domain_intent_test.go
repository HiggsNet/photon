package state

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	photonservice "github.com/HiggsNet/photon/pkg/service"
)

func TestStoreGenericRecordRejectsTypedNamespaces(t *testing.T) {
	install, _ := identityInstallFixture(t)
	store := NewStore(&VerifiedState{
		ManagedZone: install.ManagedZone, Network: install.Network, IdentityPrivateKey: install.IdentityPrivateKey,
	}, nil, nil)
	cases := []PutRecordIntent{
		{Zone: install.ManagedZone, Key: "ipam/pools/10.0.0.0_8", Type: "application.test"},
		{Zone: install.ManagedZone, Key: "apps/test", Type: routing.RecordTypeRouteAnnouncement},
		{Zone: install.ManagedZone, Key: "services/socks5", Type: "application.test"},
		{Zone: install.ManagedZone, Key: "sync/endpoint/udp", Type: "application.test"},
		{Zone: install.ManagedZone, Key: "apps/test", Type: "ipsec.transport_key.v1"},
	}
	for _, intent := range cases {
		if _, err := store.ApplyLocalIntent(context.Background(), intent, time.Unix(1000, 0)); !errors.Is(err, ErrReservedRecordIntent) {
			t.Fatalf("ApplyLocalIntent(%q/%q) error = %v, want ErrReservedRecordIntent", intent.Key, intent.Type, err)
		}
	}
	if view := store.ReadView(); view.Revision != 0 {
		t.Fatalf("reserved intents advanced revision to %d", view.Revision)
	}
}

func TestStoreTypedIPAMRouteAndServiceLifecycle(t *testing.T) {
	now := time.Unix(1000, 0)
	install, _ := identityInstallFixture(t)
	network := zone.CloneNetworkState(install.Network)
	managed := install.ManagedZone
	managedAuthority := network.Zones[managed].Authority
	managedAuthority.Keys[0].Capabilities[0].Permissions = append(
		managedAuthority.Keys[0].Capabilities[0].Permissions,
		zone.PermAllocateIP,
	)
	addDomainRecord(t, network, zone.RootZone, routing.RecordTypeIPAMPool,
		routing.RecordKeyPrefixIPAMPools+"10.0.0.0_8",
		routing.IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/8", DelegatedTo: zone.RootZone, Active: true})
	addDomainRecord(t, network, zone.RootZone, routing.RecordTypeIPAMPool,
		routing.RecordKeyPrefixIPAMPools+"10.0.0.0_16",
		routing.IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "catofes.", Active: true})
	addDomainRecord(t, network, "catofes.", routing.RecordTypeIPAMPool,
		routing.RecordKeyPrefixIPAMPools+"10.0.0.0_16",
		routing.IPAMPoolRecord{Version: 1, Prefix: "10.0.0.0/16", DelegatedTo: "catofes.", Active: true})
	addDomainRecord(t, network, "catofes.", routing.RecordTypeIPAMPool,
		routing.RecordKeyPrefixIPAMPools+"10.0.1.0_24",
		routing.IPAMPoolRecord{Version: 1, Prefix: "10.0.1.0/24", DelegatedTo: managed, Active: true})
	addDomainRecord(t, network, managed, routing.RecordTypeIPAMPool,
		routing.RecordKeyPrefixIPAMPools+"10.0.1.0_24",
		routing.IPAMPoolRecord{Version: 1, Prefix: "10.0.1.0/24", DelegatedTo: managed, Active: true})

	store := NewStore(&VerifiedState{
		ManagedZone: managed, Network: network, IdentityPrivateKey: install.IdentityPrivateKey,
	}, nil, nil)
	apply := func(intent LocalIntent, wantRevision VerifiedRevision) *zone.Record {
		t.Helper()
		result, err := store.ApplyLocalIntent(context.Background(), intent, now)
		if err != nil {
			t.Fatalf("ApplyLocalIntent(%T): %v", intent, err)
		}
		if !result.Committed || result.Record == nil || result.Changes.VerifiedRevision != wantRevision {
			t.Fatalf("ApplyLocalIntent(%T) result = %+v, want revision %d", intent, result, wantRevision)
		}
		return result.Record
	}

	assignment := apply(PutIPAMAssignmentIntent{
		Zone: managed, Prefix: "10.0.1.9/24", AssignedTo: managed,
	}, 1)
	if assignment.Key != routing.RecordKeyPrefixIPAMAssignments+"10.0.1.0_24" || assignment.Type != routing.RecordTypeIPAMAssignment {
		t.Fatalf("assignment = %+v", assignment)
	}
	pool := apply(PutIPAMPoolIntent{Zone: managed, Prefix: "10.0.1.129/25", DelegatedTo: managed}, 2)
	apply(RevokeIPAMPoolIntent{Zone: managed, Prefix: "10.0.1.128/25"}, 3)
	apply(AnnounceRouteIntent{Zone: managed, Prefix: "10.0.1.9/24"}, 4)
	serviceRecord := apply(PublishSOCKS5Intent{Endpoints: []photonservice.SOCKS5Endpoint{
		{Region: "z", Address: "10.0.1.20", Port: 1080},
		{Region: "a", Address: "10.0.1.10", Port: 1080},
	}}, 5)
	parsedService, err := photonservice.ParseSOCKS5Record(serviceRecord)
	if err != nil {
		t.Fatalf("ParseSOCKS5Record: %v", err)
	}
	if got := parsedService.Endpoints[0].Region; got != "a" {
		t.Fatalf("canonical first service region = %q, want a", got)
	}
	apply(WithdrawRouteIntent{Zone: managed, Prefix: "10.0.1.0/24"}, 6)
	apply(WithdrawSOCKS5Intent{}, 7)
	apply(RevokeIPAMAssignmentIntent{Zone: managed, Prefix: "10.0.1.0/24"}, 8)

	view := store.ReadView()
	ann, err := routing.ParseRouteAnnouncementRecord(view.State.Network.Zones[managed].Records[routing.RecordKeyPrefixRoutes+"10.0.1.0_24"])
	if err != nil || ann.Active {
		t.Fatalf("withdrawn route = %+v/%v", ann, err)
	}
	assigned, err := routing.ParseIPAMAssignmentRecord(view.State.Network.Zones[managed].Records[assignment.Key])
	if err != nil || assigned.Active {
		t.Fatalf("revoked assignment = %+v/%v", assigned, err)
	}
	revokedPool, err := routing.ParseIPAMPoolRecord(view.State.Network.Zones[managed].Records[pool.Key])
	if err != nil || revokedPool.Active {
		t.Fatalf("revoked pool = %+v/%v", revokedPool, err)
	}
	service, err := photonservice.ParseSOCKS5Record(view.State.Network.Zones[managed].Records[serviceRecord.Key])
	if err != nil || service.IsActive() {
		t.Fatalf("withdrawn service = %+v/%v", service, err)
	}
}

func TestStoreTypedRouteRejectsMissingAssignmentWithoutCommit(t *testing.T) {
	install, _ := identityInstallFixture(t)
	store := NewStore(&VerifiedState{
		ManagedZone: install.ManagedZone, Network: install.Network, IdentityPrivateKey: install.IdentityPrivateKey,
	}, nil, nil)
	if _, err := store.ApplyLocalIntent(context.Background(), AnnounceRouteIntent{
		Zone: install.ManagedZone, Prefix: "192.0.2.0/24",
	}, time.Unix(1000, 0)); err == nil {
		t.Fatal("AnnounceRouteIntent accepted a prefix without an assignment")
	}
	view := store.ReadView()
	if view.Revision != 0 || view.State.Network.Zones[install.ManagedZone].Records[routing.RecordKeyPrefixRoutes+"192.0.2.0_24"] != nil {
		t.Fatalf("rejected route changed state: %+v", view)
	}
}

func TestStorePreviewLocalIntentUsesSameValidationWithoutPublishing(t *testing.T) {
	install, _ := identityInstallFixture(t)
	store := NewStore(&VerifiedState{
		ManagedZone: install.ManagedZone, Network: install.Network, IdentityPrivateKey: install.IdentityPrivateKey,
	}, nil, nil)
	preview, err := store.PreviewLocalIntent(PutRecordIntent{
		Zone: install.ManagedZone, Key: "apps/preview", Type: "application.test", Value: []byte("value"),
	}, time.Unix(1000, 0))
	if err != nil {
		t.Fatalf("PreviewLocalIntent: %v", err)
	}
	if preview.Committed || preview.Record == nil || preview.Record.Version != 1 || preview.Changes.VerifiedRevision != 0 ||
		!preview.Changes.NetworkChanged {
		t.Fatalf("preview = %+v", preview)
	}
	view := store.ReadView()
	if view.Revision != 0 || view.State.Network.Zones[install.ManagedZone].Records["apps/preview"] != nil {
		t.Fatalf("preview published state: %+v", view)
	}
	if _, err := store.PreviewLocalIntent(PutRecordIntent{
		Zone: install.ManagedZone, Key: "services/socks5", Type: "application.test",
	}, time.Unix(1000, 0)); !errors.Is(err, ErrReservedRecordIntent) {
		t.Fatalf("reserved preview error = %v, want ErrReservedRecordIntent", err)
	}
}

func addDomainRecord(t *testing.T, network *zone.NetworkState, path zone.ZonePath, recordType, key string, value any) {
	t.Helper()
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatalf("json.Marshal(%s): %v", key, err)
	}
	network.Zones[path].Records[key] = &zone.Record{Zone: path, Key: key, Type: recordType, Value: encoded}
}
