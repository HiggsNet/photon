//go:build linux

package photonopenwrt

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
)

const inventoryFixture = `{"interface":[
 {"interface":"wan6","up":true,"l3_device":"eth1","ipv6-address":[
  {"address":"2001:db8::2","mask":64,"preferred":300,"valid":600},
  {"address":"fd12::2","mask":64},
  {"address":"fe80::2","mask":64},
  {"address":"2001:db8::3","mask":64,"preferred":0},
  {"address":"2001:db8::4","mask":64,"valid":0},
  {"address":"2001:db8::5","mask":64,"temporary":true},
  {"address":"2001:db8::6","mask":64,"flags":["tentative"]}],
  "ipv6-prefix":[{"address":"2001:db8:100::","mask":56}],
  "ipv6-prefix-assignment":[{"address":"2001:db8:200::","mask":64,"local-address":{"address":"2001:db8:200::1","mask":64}},
   {"address":"2001:db8:300::","mask":64,"local-address":{}}]},
 {"interface":"wan","up":true,"l3_device":"pppoe-wan","ipv4-address":[
  {"address":"192.168.10.2","mask":24},{"address":"192.168.10.2","mask":24},
  {"address":"203.0.113.2","mask":24},{"address":"169.254.1.2","mask":16},
  {"address":"127.0.0.1","mask":8},{"address":"224.0.0.1","mask":4}]},
 {"interface":"backup","up":false}
]}`

func TestNetworkInventoryUsesFixedUBusAndLocalUnicastOnly(t *testing.T) {
	var called []string
	inventory, err := ReadNetworkInventory(context.Background(), func(_ context.Context, name string, args ...string) ([]byte, error) {
		called = append([]string{name}, args...)
		return []byte(inventoryFixture), nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(called, []string{"ubus", "call", "network.interface", "dump"}) {
		t.Fatalf("unexpected command %q", called)
	}
	if len(inventory) != 3 || inventory[0].Name != "backup" || inventory[1].Name != "wan" || inventory[2].Name != "wan6" {
		t.Fatalf("inventory = %+v", inventory)
	}
	if !reflect.DeepEqual(inventory[1].IPv4, []netip.Addr{netip.MustParseAddr("192.168.10.2"), netip.MustParseAddr("203.0.113.2")}) {
		t.Fatalf("IPv4 = %v", inventory[1].IPv4)
	}
	want := []netip.Addr{netip.MustParseAddr("2001:db8::2"), netip.MustParseAddr("2001:db8:200::1"), netip.MustParseAddr("fd12::2")}
	if !reflect.DeepEqual(inventory[2].IPv6, want) {
		t.Fatalf("IPv6 = %v, want %v", inventory[2].IPv6, want)
	}
	selected, err := ResolveWANNetworks(Config{WANNetworks: []string{"wan6", "wan"}, AnnounceIPsec: true}, inventory)
	if err != nil || len(selected) != 2 || selected[0].Name != "wan6" {
		t.Fatalf("selected = %v %v", selected, err)
	}
}

func TestNetworkInventoryFailuresNeverFallback(t *testing.T) {
	for _, input := range []string{`null`, `{}`, `{"interface":null}`, `{"interface":[{"interface":"wan"}]}`, `{"interface":[{"interface":"wan","up":true,"ipv4-address":[{"address":"::1","mask":32}]}]}`, `{"interface":[{"interface":"wan","up":true},{"interface":"wan","up":true}]}`} {
		if _, err := parseNetworkInventory([]byte(input)); err == nil {
			t.Fatalf("accepted malformed inventory %s", input)
		}
	}
	if _, err := ReadNetworkInventory(context.Background(), func(context.Context, string, ...string) ([]byte, error) { return nil, errors.New("ubus unavailable") }); err == nil || !strings.Contains(err.Error(), "ubus unavailable") {
		t.Fatal(err)
	}
	inventory, err := parseNetworkInventory([]byte(inventoryFixture))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"missing", "backup"} {
		if selected, err := ResolveWANNetworks(Config{WANNetworks: []string{name}, AutoFirewall: true}, inventory); err == nil || selected != nil {
			t.Fatalf("fallback for %s: %v %v", name, selected, err)
		}
	}
}
