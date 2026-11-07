package photonwindows

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestWindowsOutboundExclusionDistinguishesMihomoFromOtherWintun(t *testing.T) {
	var row windows.MibIfRow2
	row.Type, row.MediaType = 53, 19 // Wintun
	name, _ := windows.UTF16FromString("custom adapter name")
	copy(row.Alias[:], name)
	for _, tc := range []struct {
		description string
		excluded    bool
	}{
		{"Meta Tunnel", true},
		{"Meta Tunnel #2", true},
		{"WireGuard Tunnel", false},
	} {
		clear(row.Description[:])
		description, _ := windows.UTF16FromString(tc.description)
		copy(row.Description[:], description)
		ownedAdapterGUIDs.RLock()
		got := excludedOutboundAdapter(row)
		ownedAdapterGUIDs.RUnlock()
		if got != tc.excluded {
			t.Errorf("%s: excluded=%t, want %t", tc.description, got, tc.excluded)
		}
	}
}

func TestWindowsOuterRouteSnapshotExcludesOwnedTunEvenWithMoreSpecificRoute(t *testing.T) {
	if os.Getenv("PHOTON_IPHELPER_SMOKE") != "1" {
		t.Skip("requires elevated isolated Windows VM")
	}
	ctx := context.Background()
	target := netip.MustParseAddr("198.18.254.25")
	before, err := outboundRouteSnapshot([]netip.Addr{target}, netip.Addr{})
	if err != nil {
		t.Fatal(err)
	}
	interfaces, err := outboundInterfaces()
	if err != nil {
		t.Fatal(err)
	}
	if bestOutboundRoute(target, netip.Addr{}, interfaces).index == 0 {
		t.Skip("test requires an eligible IPv4 underlay route")
	}
	device, err := openWintun(ctx, fmt.Sprintf("PhotonRouteProbe-%d", os.Getpid()), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(device.Close)
	driver, err := newIPHelperDriver(device, []netip.Prefix{netip.MustParsePrefix("198.18.254.0/24"), netip.MustParsePrefix("198.19.254.0/24")})
	if err != nil {
		t.Fatal(err)
	}
	want := ipHelperIntent{Addresses: []netip.Prefix{netip.MustParsePrefix("198.19.254.1/32")}, Routes: []netip.Prefix{netip.MustParsePrefix("198.19.254.0/24")}, MTU: 1400, Metric: 50}
	defer driver.Reconcile(ctx, ipHelperIntent{MTU: 1400, Metric: 50})
	if _, err := driver.Reconcile(ctx, want); err != nil {
		t.Fatal(err)
	}
	// Wait out DAD/adapter initialization before checking the unrelated path.
	time.Sleep(200 * time.Millisecond)
	unrelated, err := outboundRouteSnapshot([]netip.Addr{target}, netip.Addr{})
	if err != nil || !maps.Equal(unrelated, before) {
		t.Fatal("unrelated virtual adapter altered outer path", err)
	}
	want.Routes = append(want.Routes, netip.MustParsePrefix("198.18.254.0/24"))
	if _, err := driver.Reconcile(ctx, want); err != nil {
		t.Fatal(err)
	}
	destination := ipHelperSockaddr(target)
	var globalRoute windows.MibIpForwardRow2
	var source windows.RawSockaddrInet
	deadline := time.Now().Add(6 * time.Second)
	for {
		result, _, _ := getBestRoute2.Call(0, 0, 0, uintptr(unsafe.Pointer(&destination)), 0,
			uintptr(unsafe.Pointer(&globalRoute)), uintptr(unsafe.Pointer(&source)))
		if result == 0 && globalRoute.InterfaceLuid == device.luid {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("test route did not capture the Windows global lookup: status %d, interface %d", result, globalRoute.InterfaceLuid)
		}
		time.Sleep(50 * time.Millisecond)
	}
	changed, err := outboundRouteSnapshot([]netip.Addr{target}, netip.Addr{})
	if err != nil || !maps.Equal(before, changed) {
		t.Fatal("owned TUN captured the filtered route", err)
	}
	if _, err := driver.Reconcile(ctx, ipHelperIntent{MTU: 1400, Metric: 50}); err != nil {
		t.Fatal(err)
	}
	restored, err := outboundRouteSnapshot([]netip.Addr{target}, netip.Addr{})
	if err != nil || !maps.Equal(restored, before) {
		t.Fatal("outer route did not restore", err)
	}
}
