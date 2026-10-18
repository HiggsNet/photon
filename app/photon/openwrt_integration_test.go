//go:build linux

package main

import (
	"context"
	"errors"
	"net"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonopenwrt"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
	"github.com/urfave/cli/v3"
)

type openWrtFirewallRecorder struct {
	desired photonopenwrt.FirewallDesired
	err     error
	cleaned bool
}

func (r *openWrtFirewallRecorder) Apply(_ context.Context, desired photonopenwrt.FirewallDesired) error {
	r.desired = desired
	return r.err
}
func (r *openWrtFirewallRecorder) Cleanup(context.Context) error { r.cleaned = true; return r.err }

func TestOpenWrtPublicationFollowsSelectedWANAndWithdraws(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	config.PeerID = string(verified.ManagedZone)
	now := time.Unix(5000, 0)
	local := defaultAppConfig()
	local.ListenAddr = "198.51.100.9:33434"
	local.AdvertiseAddrs = []string{"198.51.100.99:33434"}
	local.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	local.IPsec.AnnounceAddrs = []string{"203.0.113.10"}
	local.OpenWrt = &photonopenwrt.Config{WANNetworks: []string{"wan", "wan6"}, AnnounceIPsec: true, AutoFirewall: true}
	rt := &testApp{Config: testConfigWithStatePath(local, filepath.Join(t.TempDir(), "photon.db")), Clock: func() time.Time { return now }}
	service, _ := newPersistedIPsecPublishTestService(t, rt, verified, checkpoint, runtime, config)
	service.Config.ListenAddr = "[::]:33434"
	dump := `{"interface":[{"interface":"wan","up":true,"l3_device":"eth1","ipv4-address":[{"address":"192.0.2.10","mask":24}]},{"interface":"wan6","up":true,"l3_device":"pppoe-wan","ipv6-address":[{"address":"2001:db8::10","mask":64}]},{"interface":"lan","up":true,"l3_device":"br-lan","ipv4-address":[{"address":"192.168.1.1","mask":24}]}]}`
	var inventoryErr error
	service.openWrtRunner = func(ctx context.Context, name string, args ...string) ([]byte, error) {
		if name != "ubus" || !reflect.DeepEqual(args, []string{"call", "network.interface", "dump"}) {
			t.Fatalf("unexpected inventory command %s %v", name, args)
		}
		return []byte(dump), inventoryErr
	}
	backend := &openWrtFirewallRecorder{}
	service.openWrtFirewall = backend
	check := func(want ...string) {
		t.Helper()
		if _, err := service.publishLocalProtocols(); err != nil {
			t.Fatal(err)
		}
		view := service.State.Common.ReadView()
		addressRecord, err := ipsec.ParseAddressRecord(view.State.Network.Zones[view.State.ManagedZone].Records[ipsec.RecordKeyAddresses])
		if err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, address := range addressRecord.Addresses {
			got[address.Address] = true
			if address.Address != "203.0.113.10" && address.Source != ipsec.SourceDiscovery {
				t.Fatalf("WAN address is not discovery: %+v", address)
			}
			if address.Address == "203.0.113.10" && address.Source != ipsec.SourceManualAddress {
				t.Fatalf("manual address source changed: %+v", address)
			}
		}
		expected := map[string]bool{}
		for _, address := range want {
			expected[address] = true
		}
		if !reflect.DeepEqual(got, expected) {
			t.Fatalf("published %v, want %v", got, expected)
		}
		if err := service.reconcileOpenWrtFirewall(context.Background(), nil); err != nil {
			t.Fatal(err)
		}
		if backend.desired.GossipPort != 33434 || !reflect.DeepEqual(backend.desired.IKEPorts, []uint16{500}) || !reflect.DeepEqual(backend.desired.NATTPorts, []uint16{4500}) {
			t.Fatalf("ports must come from signed canonical record: %+v", backend.desired)
		}
	}
	check("192.0.2.10", "2001:db8::10", "203.0.113.10")
	if !reflect.DeepEqual(backend.desired.Devices, []string{"eth1", "pppoe-wan"}) {
		t.Fatal(backend.desired.Devices)
	}
	// One WAN going down cannot withdraw the other WAN. Replacement IPs are
	// signed through the same persisted publisher, with no stale fallback.
	dump = `{"interface":[{"interface":"wan","up":true,"l3_device":"eth2","ipv4-address":[{"address":"192.0.2.20","mask":24}]},{"interface":"wan6","up":false}]}`
	now = now.Add(time.Minute)
	check("192.0.2.20", "203.0.113.10")
	if !reflect.DeepEqual(backend.desired.Devices, []string{"eth2"}) {
		t.Fatal(backend.desired.Devices)
	}
	dump = `{"interface":[{"interface":"wan","up":false},{"interface":"wan6","up":false}]}`
	check("203.0.113.10")
	if len(backend.desired.Devices) != 0 {
		t.Fatal("all-down left ingress open", backend.desired)
	}
	// Observation failure deliberately withdraws automatic addresses while
	// preserving explicit operator intent and exposing a diagnostic.
	inventoryErr = errors.New("netifd unavailable")
	check("203.0.113.10")
	if !strings.Contains(service.openWrtObservation.read().LastError, "netifd unavailable") {
		t.Fatal(service.openWrtObservation.read())
	}
	service.Config.IPsec.AnnounceAddrs = nil
	check()
	groups := service.Config.IPsec.LinkGroups
	service.Config.IPsec.LinkGroups = nil
	if err := service.reconcileOpenWrtFirewall(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(backend.desired.IKEPorts) != 0 || len(backend.desired.NATTPorts) != 0 {
		t.Fatal("disabled IPsec retained ingress from old signed records", backend.desired)
	}
	service.Config.IPsec.LinkGroups = groups
	service.Config.IPsec.PortMode = ipsec.PortModeRange
	if err := service.reconcileOpenWrtFirewall(context.Background(), errors.New("DNAT failed")); err == nil {
		t.Fatal("range DNAT failure was hidden")
	}
	if len(backend.desired.IKEPorts) != 0 || len(backend.desired.NATTPorts) != 0 || service.openWrtObservation.read().FirewallApplied {
		t.Fatal("range ports opened despite failed redirect", backend.desired)
	}
	service.cleanupOpenWrtOnStop()
	if !backend.cleaned {
		t.Fatal("shutdown did not clean owned ingress")
	}
}

func TestOpenWrtCLIRequiresRunningSingleWriter(t *testing.T) {
	socket := filepath.Join(t.TempDir(), "photon.sock")
	t.Setenv("PHOTON_CONTROL_SOCKET", socket)
	// Refresh cannot fall back to an offline DB writer or create missing state.
	refresh := cmdOpenWrtRefresh()
	if err := refresh.Action(context.Background(), &cli.Command{}); err == nil {
		t.Fatal("offline refresh succeeded")
	}
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	cleanup := cmdOpenWrtCleanup()
	if err := cleanup.Action(context.Background(), &cli.Command{}); err == nil || !strings.Contains(err.Error(), "still running") {
		t.Fatalf("cleanup accepted active owner: %v", err)
	}
}

func TestOpenWrtDisabledReconcileWithdrawsPreviousOwnedRules(t *testing.T) {
	backend := &openWrtFirewallRecorder{}
	service := &Daemon{Config: defaultAppConfig(), openWrtFirewall: backend}
	if err := service.reconcileOpenWrtFirewall(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if !backend.cleaned {
		t.Fatal("disabled integration left previous owner's rules")
	}
	backend.cleaned = false
	service.openWrtFirewall = backend
	service.Config.OpenWrt = &photonopenwrt.Config{WANNetworks: []string{"wan"}, AnnounceIPsec: true}
	if err := service.reconcileOpenWrtFirewall(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if !backend.cleaned {
		t.Fatal("announce-only integration left previous firewall rules")
	}
}

func TestOpenWrtEmptyWANAddressSetIsVisible(t *testing.T) {
	config := defaultAppConfig()
	config.OpenWrt = &photonopenwrt.Config{WANNetworks: []string{"wan"}, AnnounceIPsec: true}
	service := &Daemon{Config: config, openWrtRunner: func(context.Context, string, ...string) ([]byte, error) {
		return []byte(`{"interface":[{"interface":"wan","up":true,"l3_device":"eth1"}]}`), nil
	}}
	service.refreshOpenWrtNetworks(context.Background())
	if !strings.Contains(service.openWrtObservation.read().LastError, "no eligible unicast") {
		t.Fatal(service.openWrtObservation.read())
	}
}

func TestOpenWrtFirewallTracksCanonicalPortRotationGrace(t *testing.T) {
	verified, checkpoint, runtime, config := buildTestDaemonOwners(t)
	verified.ManagedZone = "node-b.catofes."
	config.PeerID = string(verified.ManagedZone)
	now := time.Unix(5000, 0)
	local := defaultAppConfig()
	local.IPsec.LinkGroups = []ipsec.LinkGroupSpec{testIPsecLinkGroup()}
	local.IPsec.PortMode = ipsec.PortModeRange
	local.IPsec.PortRange = ipsec.PortRange{From: 30000, To: 30099}
	local.IPsec.PortRotateInterval = time.Hour
	local.IPsec.PortPreviousGrace = 10 * time.Minute
	local.OpenWrt = &photonopenwrt.Config{WANNetworks: []string{"wan"}, AutoFirewall: true}
	rt := &testApp{Config: testConfigWithStatePath(local, filepath.Join(t.TempDir(), "photon.db")), Clock: func() time.Time { return now }}
	service, _ := newPersistedIPsecPublishTestService(t, rt, verified, checkpoint, runtime, config)
	service.Config.ListenAddr = "[::]:33434"
	service.openWrtRunner = func(context.Context, string, ...string) ([]byte, error) {
		return []byte(`{"interface":[{"interface":"wan","up":true,"l3_device":"eth1"}]}`), nil
	}
	backend := &openWrtFirewallRecorder{}
	service.openWrtFirewall = backend
	if _, err := service.publishLocalProtocols(); err != nil {
		t.Fatal(err)
	}
	if err := service.reconcileOpenWrtFirewall(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	first := backend.desired
	now = now.Add(time.Hour + time.Second)
	if _, err := service.publishLocalProtocols(); err != nil {
		t.Fatal(err)
	}
	if err := service.reconcileOpenWrtFirewall(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(backend.desired.IKEPorts) != 2 || backend.desired.IKEPorts[1] != first.IKEPorts[0] || len(backend.desired.NATTPorts) != 2 || backend.desired.NATTPorts[1] != first.NATTPorts[0] {
		t.Fatalf("signed grace not retained: first=%+v next=%+v", first, backend.desired)
	}
	now = now.Add(11 * time.Minute)
	if err := service.reconcileOpenWrtFirewall(context.Background(), nil); err != nil {
		t.Fatal(err)
	}
	if len(backend.desired.IKEPorts) != 1 || len(backend.desired.NATTPorts) != 1 {
		t.Fatalf("expired grace still open: %+v", backend.desired)
	}
}

func TestOpenWrtRangeRequiresExistingHostRedirectOwner(t *testing.T) {
	for _, test := range []struct {
		name, extra string
		valid       bool
	}{
		{"missing", "", false},
		{"host", "firewall:\n  instances:\n    - id: host\n      host: true\n      backend: nft\n", true},
		{"disabled redirect", "firewall:\n  instances:\n    - id: host\n      host: true\n      redirect_grace:\n        enabled: false\n", false},
		{"disabled host", "firewall:\n  instances:\n    - id: host\n      host: true\n      enabled: false\n", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			input := "openwrt:\n  wan_networks: [wan]\n  auto_firewall: true\nipsec:\n  port_mode: range\n  port_range: {from: 40000, to: 41000}\n" + test.extra
			err := parseConfigYAML(input, defaultAppConfig())
			if (err == nil) != test.valid {
				t.Fatalf("valid=%v err=%v", test.valid, err)
			}
		})
	}
}
