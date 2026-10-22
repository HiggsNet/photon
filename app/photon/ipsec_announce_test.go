package main

import (
	"errors"
	"net/netip"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestIPsecInterfacePublicationSignsChangesAndWithdrawals(t *testing.T) {
	verified, checkpoint, runtime, transportConfig := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	transportConfig.PeerID = string(verified.ManagedZone)
	now := time.Unix(5000, 0)
	config := defaultAppConfig()
	config.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	config.IPsec.AnnounceGossipEndpoints = false
	config.IPsec.AnnounceAddrs = []photonlinux.IPsecAnnounceAddress{{Address: "203.0.113.1", Priority: 100}}
	config.IPsec.AnnounceInterfaces = []photonlinux.IPsecAnnounceInterface{{Name: "eth0", Priority: 100}, {Name: "eth1", Priority: 100}}
	rt := &testApp{Config: testConfigWithStatePath(config, filepath.Join(t.TempDir(), "photon.db")), Clock: func() time.Time { return now }}
	service, _ := newPersistedIPsecPublishTestService(t, rt, verified, checkpoint, runtime, transportConfig)
	inventory := []photonlinux.IPsecInterface{
		{Name: "eth0", Up: true, Addresses: []photonlinux.IPsecInterfaceAddress{{Address: netip.MustParseAddr("192.0.2.1")}}},
		{Name: "eth1", Up: true, Addresses: []photonlinux.IPsecInterfaceAddress{{Address: netip.MustParseAddr("2001:db8::1")}}},
	}
	var readErr error
	service.ipsecInterfaceReader = func() ([]photonlinux.IPsecInterface, error) { return inventory, readErr }
	check := func(want ...string) uint64 {
		t.Helper()
		if _, err := service.publishLocalProtocols(); err != nil {
			t.Fatal(err)
		}
		view := service.State.Common.ReadView()
		signed := view.State.Network.Zones[view.State.ManagedZone].Records[ipsec.RecordKeyAddresses]
		record, err := ipsec.ParseAddressRecord(signed)
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		expected := map[string]bool{}
		for _, entry := range record.Addresses {
			got[entry.Address] = true
			if entry.Address == "203.0.113.1" && entry.Source != ipsec.SourceManualAddress {
				t.Fatal("manual source lost")
			}
		}
		for _, address := range want {
			expected[address] = true
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("addresses=%v want=%v", got, expected)
		}
		return signed.Version
	}
	version := check("203.0.113.1", "192.0.2.1", "2001:db8::1")
	now = now.Add(time.Minute)
	if unchanged := check("203.0.113.1", "192.0.2.1", "2001:db8::1"); unchanged != version {
		t.Fatal("unchanged addresses republished")
	}
	inventory[0].Addresses[0].Address = netip.MustParseAddr("192.0.2.2")
	if changed := check("203.0.113.1", "192.0.2.2", "2001:db8::1"); changed <= version {
		t.Fatal("address change not signed")
	}
	inventory[0].Up = false
	check("203.0.113.1", "2001:db8::1")
	readErr = errors.New("inventory unavailable")
	check("203.0.113.1")
	// A role change withdraws every inbound contact, while retaining both
	// underlay families in signed profile/overlay capability declarations.
	service.Config.IPsec.Role = ipsec.RoleOut
	service.ipsecInterfaceReader = func() ([]photonlinux.IPsecInterface, error) {
		t.Fatal("outbound node read interface addresses")
		return nil, nil
	}
	check()
	view := service.State.Common.ReadView()
	profile, err := ipsec.ParseProfileRecord(view.State.Network.Zones[view.State.ManagedZone].Records[ipsec.RecordKeyProfile])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(profile.AddressFamilies, []string{ipsec.FamilyIPv4, ipsec.FamilyIPv6}) {
		t.Fatal("empty outbound addresses lost dual stack", profile)
	}
	intent, err := ipsec.ParseOverlayIntentRecord(view.State.Network.Zones[view.State.ManagedZone].Records[ipsec.OverlayIntentRecordKey("main")])
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(intent.PathKeys, []string{"family:ipv4", "family:ipv6"}) {
		t.Fatal("outbound overlay lost dual stack", intent)
	}
}

func TestIPsecContactFailureDefersEndpointAcrossReconciles(t *testing.T) {
	now := time.Unix(5000, 0)
	d := &Daemon{Config: defaultAppConfig()}
	d.Config.IPsec.LinkGroups = []ipsec.LinkGroupSpec{{ID: "main", Reconcile: ipsec.ReconcilePolicy{IntervalSeconds: 60}}}
	point := ipsec.ContactPoint{AddressID: "manual", Source: ipsec.SourceManualAddress, Address: "192.0.2.1", Family: ipsec.FamilyIPv4, Priority: 300, IKEPort: 500, NATTPort: 4500, Generation: 1, Current: true}
	before := ipsec.LinkInstance{ID: "link", PeerZone: "peer.example.", SelectedContact: point, InitiatorRole: ipsec.InitiatorRolePrimary, ActualState: ipsec.LinkStateConnecting}
	after := before
	after.FailureCount = 1
	after.LastFailure = &ipsec.ContactAttemptError{Err: errors.New("waiting for established SA")}
	after.BackoffUntil = now.Add(time.Second).Unix()
	for _, kind := range []string{"local setup", "rotation"} {
		other := &Daemon{Config: d.Config}
		failure := after
		if kind == "local setup" {
			failure.LastFailure = errors.New("ensure interface: failed")
		} else {
			failure.StagedGeneration = 2
			failure.RotatePhase = ipsec.RotatePhaseTestingNew
		}
		other.observeIPsecContactOutcomes(map[string]ipsec.LinkInstance{"link": before}, map[string]ipsec.LinkInstance{"link": failure}, now)
		if got := other.buildIPsecContactPointQuality(nil, now); len(got) != 0 {
			t.Fatalf("%s failure penalized current endpoint: %+v", kind, got)
		}
	}
	d.observeIPsecContactOutcomes(map[string]ipsec.LinkInstance{"link": before}, map[string]ipsec.LinkInstance{"link": after}, now)
	quality := d.buildIPsecContactPointQuality(nil, now.Add(time.Minute))
	if !quality[zone.ZonePath("peer.example.")][point.Key()].BackoffUntil.After(now.Add(time.Minute)) {
		t.Fatal("contact backoff expired before reconcile", quality)
	}
	backup := point
	backup.AddressID = "interface"
	backup.Address = "192.0.2.2"
	backup.Source = ipsec.SourceDiscovery
	backup.Priority = 100
	selected := ipsec.SelectContactPointsWithOptions([]ipsec.ContactPoint{point, backup}, ipsec.PathModeFamilyRedundant, ipsec.AddressCandidateOptions{Now: now.Add(time.Minute), ContactQuality: quality["peer.example."]})
	if selected[0].Address != backup.Address {
		t.Fatal("IPsec failure did not trigger cross-source fallback", selected)
	}
	// Reobserving the same failure cannot extend hold-down forever.
	d.observeIPsecContactOutcomes(map[string]ipsec.LinkInstance{"link": after}, map[string]ipsec.LinkInstance{"link": after}, now.Add(time.Minute))
	if got := d.buildIPsecContactPointQuality(nil, now.Add(time.Minute)); got["peer.example."][point.Key()] != quality["peer.example."][point.Key()] {
		t.Fatal("same failure counted twice")
	}
	up := after
	up.ActualState = ipsec.LinkStateUp
	up.FailureCount = 0
	up.LastFailure = nil
	d.observeIPsecContactOutcomes(map[string]ipsec.LinkInstance{"link": after}, map[string]ipsec.LinkInstance{"link": up}, now.Add(2*time.Minute))
	if got := d.buildIPsecContactPointQuality(nil, now.Add(2*time.Minute)); !got["peer.example."][point.Key()].BackoffUntil.IsZero() {
		t.Fatal("established endpoint retained failure backoff")
	}
	if got := d.buildIPsecContactPointQuality(nil, now.Add(time.Hour)); len(got) != 0 {
		t.Fatal("old contact evidence not expired")
	}
	// A configured long reconcile interval must not expire endpoint evidence
	// before its still-active hold-down is consulted.
	d.Config.IPsec.LinkGroups[0].Reconcile.IntervalSeconds = 3600
	d.observeIPsecContactOutcomes(map[string]ipsec.LinkInstance{"link": before}, map[string]ipsec.LinkInstance{"link": after}, now)
	if got := d.buildIPsecContactPointQuality(nil, now.Add(time.Hour)); len(got) == 0 {
		t.Fatal("active hold-down expired before long reconcile")
	}
}
