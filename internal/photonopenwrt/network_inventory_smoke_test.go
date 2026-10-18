//go:build linux

package photonopenwrt

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"
)

// This verifies the real netifd input contract only. It does not publish signed
// Photon state or invoke the host netifd/hotplug service.
func TestOpenWrtNetifdIsolatedInventory(t *testing.T) {
	if os.Getenv("PHOTON_OPENWRT_NETIFD_SMOKE") != "1" {
		t.Skip("set PHOTON_OPENWRT_NETIFD_SMOKE=1 for isolated real netifd inventory")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if os.Getenv("PHOTON_NETIFD_SMOKE_CHILD") != "1" {
		for _, command := range []string{"unshare", "mount", "ip", "ubus", "ubusd", "netifd"} {
			if _, err := exec.LookPath(command); err != nil {
				t.Fatal(err)
			}
		}
		cmd := exec.CommandContext(ctx, "unshare", "-m", "--propagation", "private", "-n", "-p", "--fork", "--kill-child=SIGKILL", "--mount-proc", os.Args[0], "-test.run=^TestOpenWrtNetifdIsolatedInventory$", "-test.v")
		cmd.Env = append(os.Environ(), "PHOTON_NETIFD_SMOKE_CHILD=1", "PHOTON_FW4_HOST_NET="+fw4Namespace(t, "net"), "PHOTON_FW4_HOST_MNT="+fw4Namespace(t, "mnt"), "PHOTON_NETIFD_HOST_PID="+fw4Namespace(t, "pid"), "PHOTON_FW4_FIXTURE="+t.TempDir())
		output, err := cmd.CombinedOutput()
		t.Logf("isolated netifd:\n%s", output)
		if err != nil {
			t.Fatalf("isolated netifd: %v", err)
		}
		return
	}
	for kind, parent := range map[string]string{"net": os.Getenv("PHOTON_FW4_HOST_NET"), "mnt": os.Getenv("PHOTON_FW4_HOST_MNT"), "pid": os.Getenv("PHOTON_NETIFD_HOST_PID")} {
		if parent == "" || parent == fw4Namespace(t, kind) {
			t.Fatalf("refusing netifd without private %s namespace", kind)
		}
	}
	if os.Getpid() != 1 {
		t.Fatal("fixture must own its private PID namespace")
	}
	fw4PrivateFiles(t, ctx)
	for _, dir := range []string{"/var/run/ubus", "/tmp/empty-netifd-addons"} {
		if err := os.MkdirAll(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	fw4Write(t, "/tmp/netifd-hotplug", `#!/bin/sh
printf '%s:%s\n' "$ACTION" "$INTERFACE" >> /tmp/netifd-hotplug-events
`)
	if err := os.Chmod("/tmp/netifd-hotplug", 0700); err != nil {
		t.Fatal(err)
	}
	for _, dev := range []string{"phnet0", "phnet1", "phnet2", "phnetlan"} {
		fw4Command(t, ctx, "ip", "link", "add", dev, "type", "veth", "peer", "name", dev+"p")
		fw4Command(t, ctx, "ip", "link", "set", dev+"p", "up")
	}
	writeConfig := func(device, address4, address6 string) {
		fw4Write(t, "/etc/config/network", fmt.Sprintf(`config interface 'wan'
	option device '%s'
	option proto 'static'
	option ipaddr '%s'
	option netmask '255.255.255.0'
	list ip6addr '%s/64'
config interface 'wan6'
	option device 'phnet1'
	option proto 'static'
	option ipaddr '203.0.113.1'
	option netmask '255.255.255.0'
	list ip6addr '2001:db8:2::1/64'
config interface 'lan'
	option device 'phnetlan'
	option proto 'static'
	option ipaddr '198.51.100.1'
	option netmask '255.255.255.0'
	list ip6addr '2001:db8:3::1/64'
`, device, address4, address6))
	}
	writeConfig("phnet0", "192.0.2.1", "2001:db8:1::1")
	start := func(name string, args ...string) {
		log, err := os.OpenFile("/tmp/"+name+".log", os.O_CREATE|os.O_WRONLY, 0600)
		if err != nil {
			t.Fatal(err)
		}
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Stdout, cmd.Stderr = log, log
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = cmd.Process.Kill(); _ = cmd.Wait(); _ = log.Close() })
	}
	start("ubusd", "-s", "/var/run/ubus/ubus.sock")
	fw4Await(t, 5*time.Second, func() bool { _, err := os.Stat("/var/run/ubus/ubus.sock"); return err == nil })
	// Built-in static protocol only; do not load firmware protocol addons or
	// invoke any of the installed hotplug hooks that may control real hardware.
	start("netifd", "-s", "/var/run/ubus/ubus.sock", "-c", "/etc/config", "-p", "/tmp/empty-netifd-addons", "-h", "/tmp/netifd-hotplug", "-r", "/tmp/netifd-resolv.conf", "-S")
	t.Cleanup(func() {
		data, _ := os.ReadFile("/tmp/netifd.log")
		t.Logf("private netifd log:\n%s", data)
		data, _ = os.ReadFile("/tmp/netifd-hotplug-events")
		t.Logf("private hotplug event recorder:\n%s", data)
	})
	var inventory []NetworkInterface
	awaitNetwork := func(name, device string, up bool, addresses ...string) {
		t.Helper()
		fw4Await(t, 8*time.Second, func() bool {
			var err error
			inventory, err = ReadNetworkInventory(ctx, nil)
			if err != nil {
				return false
			}
			for _, network := range inventory {
				if network.Name != name {
					continue
				}
				if network.Up != up {
					return false
				}
				if !up {
					return true
				}
				if network.L3Device != device {
					return false
				}
				got := append(slices.Clone(network.IPv4), network.IPv6...)
				want := make([]netip.Addr, len(addresses))
				for i, address := range addresses {
					want[i] = netip.MustParseAddr(address)
				}
				slices.SortFunc(got, func(a, b netip.Addr) int { return a.Compare(b) })
				slices.SortFunc(want, func(a, b netip.Addr) int { return a.Compare(b) })
				return slices.Equal(got, want)
			}
			return false
		})
	}
	config := Config{WANNetworks: []string{"wan", "wan6"}, AnnounceIPsec: true}
	awaitNetwork("wan", "phnet0", true, "192.0.2.1", "2001:db8:1::1")
	awaitNetwork("wan6", "phnet1", true, "203.0.113.1", "2001:db8:2::1")
	selected, err := ResolveWANNetworks(config, inventory)
	if err != nil || len(selected) != 2 || selected[0].Name != "wan" || selected[1].Name != "wan6" {
		t.Fatalf("selected wrong logical networks: %+v %v", selected, err)
	}
	t.Log("real netifd static dual-stack WANs resolved through logical names/l3_device; unrelated LAN excluded")
	writeConfig("phnet0", "192.0.2.9", "2001:db8:1::9")
	fw4Command(t, ctx, "ubus", "call", "network", "reload", "{}")
	awaitNetwork("wan", "phnet0", true, "192.0.2.9", "2001:db8:1::9")
	writeConfig("phnet2", "192.0.2.19", "2001:db8:1::19")
	fw4Command(t, ctx, "ubus", "call", "network", "reload", "{}")
	awaitNetwork("wan", "phnet2", true, "192.0.2.19", "2001:db8:1::19")
	t.Log("real UCI/netifd reload replaced both address families and moved unchanged logical WAN to a new L3 device")
	fw4Command(t, ctx, "ubus", "call", "network.interface.wan6", "down", "{}")
	awaitNetwork("wan6", "", false)
	if selected, err := ResolveWANNetworks(config, inventory); err == nil || len(selected) != 0 {
		t.Fatalf("down selected network silently fell back: %+v %v", selected, err)
	}
	one := config
	one.WANNetworks = []string{"wan"}
	if selected, err := ResolveWANNetworks(one, inventory); err != nil || len(selected) != 1 || selected[0].L3Device != "phnet2" {
		t.Fatalf("healthy WAN was lost: %+v %v", selected, err)
	}
	fw4Command(t, ctx, "ubus", "call", "network.interface.wan", "down", "{}")
	awaitNetwork("wan", "", false)
	if selected, err := ResolveWANNetworks(config, inventory); err == nil || len(selected) != 0 {
		t.Fatalf("all-down selected LAN/another device: %+v %v", selected, err)
	}
	fw4Command(t, ctx, "ubus", "call", "network.interface.wan6", "up", "{}")
	awaitNetwork("wan6", "phnet1", true, "203.0.113.1", "2001:db8:2::1")
	one.WANNetworks = []string{"wan6"}
	if selected, err := ResolveWANNetworks(one, inventory); err != nil || len(selected) != 1 {
		t.Fatalf("WAN recovery not observed: %+v %v", selected, err)
	}
	events, _ := os.ReadFile("/tmp/netifd-hotplug-events")
	if !strings.Contains(string(events), "ifup:wan") || !strings.Contains(string(events), "ifdown:wan") {
		t.Fatalf("expected actual netifd lifecycle events: %s", events)
	}
	t.Log("partial-down keeps the independently selected healthy WAN; all-down fails closed; explicit up restores WAN6")
}
