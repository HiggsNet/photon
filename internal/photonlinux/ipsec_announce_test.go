package photonlinux

import (
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func TestIPsecAnnounceConfigMixedFormsAndFilters(t *testing.T) {
	config := DefaultIPsecConfig()
	err := applyIPsecYAML(`ipsec:
  announce_addrs:
    - 203.0.113.1
    - address: 203.0.113.2
      priority: 0
  announce_dns: [{host: vpn.example, priority: 300}, backup.example]
  announce_interfaces:
    - name: eth0
      ipv4: false
      include: ["2001:db8::/32"]
      exclude: ["2001:db8:1::/48"]
  announce_filter:
    exclude: ["fc00::/7"]
`, &config)
	if err != nil {
		t.Fatal(err)
	}
	if config.AnnounceAddrs[0].Priority != 100 || config.AnnounceAddrs[1].Priority != 0 || config.AnnounceDNS[0].Priority != 300 || config.AnnounceDNS[1].Priority != 100 || config.AnnounceInterfaces[0].Priority != 100 {
		t.Fatalf("priorities: %+v", config)
	}
	rule := config.AnnounceInterfaces[0]
	for address, want := range map[string]bool{"203.0.113.1": false, "2001:db8::1": true, "2001:db8:1::1": false, "2001:db9::1": false} {
		if got := rule.Allows(netip.MustParseAddr(address)); got != want {
			t.Fatalf("%s allowed=%v", address, got)
		}
	}
	for _, input := range []string{
		"announce_addrs: [{address: 203.0.113.1, prio: 300}]",
		"announce_dns: [{priority: 1}]",
		"announce_interfaces: [{name: eth0, ipv6: false, typo: true}]",
		"announce_interfaces: [{name: eth0}, {name: eth0}]",
		"announce_interfaces: [{name: eth0, exclude: [invalid]}]",
		"announce_interfaces: [{name: '../eth0'}]",
	} {
		c := DefaultIPsecConfig()
		if err := applyIPsecYAML("ipsec:\n  "+input+"\n", &c); err == nil {
			t.Fatalf("accepted %s", input)
		}
	}
}

func TestIPsecInterfaceSelectionFiltersAndIndependentWithdrawal(t *testing.T) {
	config := DefaultIPsecConfig()
	if err := applyIPsecYAML("ipsec:\n  announce_interfaces:\n    - name: eth0\n      ipv4: false\n      exclude: [\"fc00::/7\"]\n    - name: missing\n", &config); err != nil {
		t.Fatal(err)
	}
	inventory := []IPsecInterface{{Name: "eth0", Up: true, Addresses: []IPsecInterfaceAddress{
		{Address: netip.MustParseAddr("203.0.113.1")},
		{Address: netip.MustParseAddr("2001:db8::1")},
		{Address: netip.MustParseAddr("fd00::1")},
		{Address: netip.MustParseAddr("fe80::1")},
		{Address: netip.MustParseAddr("2001:db8::2"), Temporary: true},
		{Address: netip.MustParseAddr("2001:db8::3"), Tentative: true},
		{Address: netip.MustParseAddr("2001:db8::4"), Deprecated: true},
	}}}
	ads, err := SelectIPsecInterfaceAddresses(config.AnnounceInterfaces, inventory)
	if err == nil || !strings.Contains(err.Error(), "missing") {
		t.Fatalf("missing interface diagnostic: %v", err)
	}
	if len(ads) != 1 || ads[0].Address != "2001:db8::1" || ads[0].Priority != 100 || ads[0].Source != ipsec.SourceDiscovery {
		t.Fatalf("selected: %+v", ads)
	}
	inventory[0].Up = false
	ads, err = SelectIPsecInterfaceAddresses(config.AnnounceInterfaces, inventory)
	if err == nil || len(ads) != 0 {
		t.Fatalf("down interface retained: %v %v", ads, err)
	}
}

func TestIPsecAnnounceGlobalFilterAndGossipFallback(t *testing.T) {
	config := DefaultIPsecConfig()
	if err := applyIPsecYAML(`ipsec:
  announce_addrs: ["192.168.1.2"]
  announce_dns: [vpn.example]
  announce_interfaces: [{name: eth0}]
  announce_filter:
    ipv4: false
    exclude: ["fc00::/7"]
`, &config); err != nil {
		t.Fatal(err)
	}
	endpoints := &gossip.EndpointRecord{Endpoints: []gossip.EndpointEntry{
		{Address: "192.168.1.3", Source: "advertise", Priority: 99999},
		{Address: "fd00::1", Source: "interface", Scope: "global"},
		{Address: "2001:db8::1", Source: "advertise", Priority: 99999},
		{Address: "2001:db8::3", Source: "interface", Scope: "global"},
	}}
	ad := ipsec.AddressAdvertisement{ID: "interface-eth0", Source: ipsec.SourceDiscovery, Address: "2001:db8::2", Family: ipsec.FamilyIPv6, Priority: 100}
	record := BuildIPsecAddressRecord(config, []ipsec.AddressAdvertisement{ad}, nil, "203.0.113.9:33434", endpoints, time.Unix(5000, 0))
	if len(record.Addresses) != 4 {
		t.Fatalf("addresses: %+v", record)
	}
	for _, entry := range record.Addresses {
		if entry.Priority != 100 {
			t.Fatalf("default priority differs: %+v", entry)
		}
		if entry.Address == "2001:db8::1" && !entry.Fallback {
			t.Fatal("gossip advertise elevated to explicit")
		}
	}
	config.AnnounceAddrs = nil
	config.AnnounceDNS = nil
	config.AnnounceGossipEndpoints = false
	if got := BuildIPsecAddressRecord(config, nil, nil, "203.0.113.9:33434", nil, time.Time{}); len(got.Addresses) != 0 {
		t.Fatal("empty interface set borrowed listen host", got)
	}
	config.Role = ipsec.RoleOut
	config.AnnounceGossipEndpoints = true
	if got := BuildIPsecAddressRecord(config, []ipsec.AddressAdvertisement{ad}, nil, "203.0.113.9:33434", endpoints, time.Time{}); len(got.Addresses) != 0 {
		t.Fatal("outbound node announced inbound contacts", got)
	}
	if !reflect.DeepEqual(config.AnnounceDNSHosts(), []string(nil)) {
		t.Fatal("unexpected DNS hosts")
	}
}
