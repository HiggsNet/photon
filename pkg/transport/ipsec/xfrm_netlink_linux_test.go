package ipsec

import (
	"context"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

func TestXFRMNetlinkMatchesIP(t *testing.T) {
	if os.Getenv("PHOTON_IPSEC_XFRM_SMOKE") != "1" {
		t.Skip("set PHOTON_IPSEC_XFRM_SMOKE=1 to exercise real XFRM links")
	}
	ctx := t.Context()
	ns := "photon-xfrm-netlink-" + filepath.Base(filepath.Dir(t.TempDir()))
	named := NetNSSpec{Kind: NetNSName, Name: ns}
	host := NetNSSpec{Kind: NetNSHost}
	const iface = "phxnl0"

	runIP(t, ctx, "netns", "add", ns)
	t.Cleanup(func() { _, _ = execCommand(context.Background(), "ip", "netns", "delete", ns) })
	runIP(t, ctx, "link", "add", iface, "type", "xfrm", "if_id", "424242")
	t.Cleanup(func() { _, _ = execCommand(context.Background(), "ip", "link", "delete", iface) })
	runIP(t, ctx, "link", "set", iface, "netns", ns)
	runIP(t, ctx, "-n", ns, "link", "set", iface, "addrgenmode", "none")
	runIP(t, ctx, "-n", ns, "link", "set", iface, "multicast", "on", "up")
	runIP(t, ctx, "-n", ns, "addr", "add", "fd00:4242::1/64", "dev", iface)
	runIP(t, ctx, "-n", ns, "addr", "add", "192.0.2.1", "peer", "192.0.2.2/32", "dev", iface)

	driver := NewSystemXFRMDriver(named)
	want, err := driver.inspectLinksViaIP(ctx, named)
	if err != nil {
		t.Fatal(err)
	}
	got, err := driver.inspectNetlink(ctx, named)
	if err != nil {
		t.Fatal(err)
	}
	link := func(links []observedInterface) observedInterface {
		t.Helper()
		for _, link := range links {
			if link.state.InterfaceName == iface {
				return link
			}
		}
		t.Fatalf("%s missing from %+v", iface, links)
		return observedInterface{}
	}
	if got, want := link(got), link(want); !reflect.DeepEqual(got.state, want.state) ||
		!got.xfrm || got.state.XFRMIfID != 424242 || !got.state.IPv6AddrGenDisabled ||
		!got.state.InterfaceUp || !got.state.Multicast || len(got.state.Addresses) != 2 {
		t.Fatalf("netlink = %+v, ip = %+v", got, want)
	}

	// An inventory-only batch needs no ip subprocess. Include the host
	// namespace to verify isolation.
	var commands []string
	driver.Command = func(_ context.Context, command string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(args, " "))
		return execCommand(ctx, command, args...)
	}
	_, inventory, err := driver.InspectLinks(ctx, nil, []NetNSSpec{host, named})
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 0 ||
		!reflect.DeepEqual(linkInventory(inventory, iface), []XFRMLinkState{link(want).state}) {
		t.Fatalf("commands = %v, inventory = %+v", commands, inventory)
	}

	// Existing namespaces can be repaired end to end without invoking ip.
	driver.Command = func(_ context.Context, command string, args ...string) ([]byte, error) {
		commands = append(commands, strings.Join(args, " "))
		return nil, fmt.Errorf("unexpected fallback to %s %v", command, args)
	}
	spec := TransportLinkSpec{
		InterfaceName: "phxnl1", XFRMIfID: 424243, NetNS: ns,
		LocalTunnelAddr: netip.MustParseAddr("fd00:4242::2"),
	}
	if err := driver.EnsureInterface(ctx, spec); err != nil {
		t.Fatal(err)
	}
	if err := driver.AssignAddress(ctx, spec, "fd00:4242::3/64"); err != nil {
		t.Fatal(err)
	}
	if err := driver.AssignAddress(ctx, spec, "fd00:4242::2/64"); err != nil {
		t.Fatal(err)
	}
	states, _, err := driver.InspectLinks(ctx, []TransportLinkSpec{spec}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(states) != 1 || !states[0].InterfaceForwarding || !states[0].NamespaceForwarding ||
		!reflect.DeepEqual(states[0].Addresses, []netip.Prefix{netip.MustParsePrefix("fd00:4242::2/64")}) {
		t.Fatalf("unexpected state %+v", states)
	}
	if err := driver.DeleteInterface(ctx, spec.InterfaceName); err != nil {
		t.Fatal(err)
	}
	if driver.linkExists(ctx, named, spec.InterfaceName) || len(commands) != 0 {
		t.Fatalf("delete failed or used fallback: commands=%v", commands)
	}
}

func linkInventory(inventory []XFRMLinkState, iface string) []XFRMLinkState {
	var matches []XFRMLinkState
	for _, link := range inventory {
		if link.InterfaceName == iface {
			matches = append(matches, link)
		}
	}
	return matches
}

func TestXFRMNetlinkWriteFallbackBeforeSendOnly(t *testing.T) {
	for _, attempted := range []bool{false, true} {
		t.Run(fmt.Sprintf("sent=%t", attempted), func(t *testing.T) {
			var calls int
			driver := SystemXFRMDriver{
				mutateNetlink: func(context.Context, NetNSSpec, string, xfrmMutation) (bool, error) {
					return attempted, fmt.Errorf("netlink failed")
				},
				Command: func(context.Context, string, ...string) ([]byte, error) {
					calls++
					return nil, nil
				},
			}
			err := driver.setLinkUp(t.Context(), NetNSSpec{Kind: NetNSHost}, "phxnl0")
			if attempted {
				if err == nil || calls != 0 {
					t.Fatalf("err=%v fallback calls=%d after send", err, calls)
				}
			} else if err != nil || calls != 1 {
				t.Fatalf("err=%v fallback calls=%d before send", err, calls)
			}
		})
	}
}
