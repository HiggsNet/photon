package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func TestIPHelperSockaddrABI(t *testing.T) {
	if unsafe.Sizeof(ipHelperInterfaceRow{}) != 168 || unsafe.Offsetof(ipHelperInterfaceRow{}.TransmitOffload) != 164 ||
		unsafe.Offsetof(ipHelperInterfaceRow{}.DisableDefaultRoutes) != 166 || unsafe.Offsetof(ipHelperInterfaceTable{}.Table) != 8 {
		t.Fatal("unexpected Windows SDK IP interface row layout")
	}
	if unsafe.Sizeof(windows.MibUnicastIpAddressRow{}) != 80 || unsafe.Offsetof(windows.MibUnicastIpAddressRow{}.InterfaceLuid) != 32 ||
		unsafe.Offsetof(windows.MibUnicastIpAddressRow{}.OnLinkPrefixLength) != 60 || unsafe.Sizeof(windows.MibIpForwardRow2{}) != 104 {
		t.Fatal("unexpected Windows SDK address/route row layout")
	}
	for _, text := range []string{"198.18.254.1", "fd00:7068:ffff::1", "0.0.0.0", "::"} {
		addr := netip.MustParseAddr(text)
		raw := ipHelperSockaddr(addr)
		if got := ipHelperAddr(&raw); got != addr {
			t.Fatalf("sockaddr roundtrip: %s != %s", got, addr)
		}
	}
}

func ipHelperTestIntent() ipHelperIntent {
	return ipHelperIntent{
		Addresses: []netip.Prefix{netip.MustParsePrefix("198.18.254.1/32"), netip.MustParsePrefix("fd00:7068:ffff::1/128")},
		Routes:    []netip.Prefix{netip.MustParsePrefix("198.18.254.0/24"), netip.MustParsePrefix("fd00:7068:ffff::/64")},
		MTU:       1400, Metric: 50,
	}
}

func ipHelperTestObservation() ipHelperObservation {
	return ipHelperObservation{luid: 123, interfaces: [2]ipHelperInterfaceRow{
		{Family: windows.AF_INET, InterfaceLuid: 123, NlMtu: 1400, Metric: 50},
		{Family: windows.AF_INET6, InterfaceLuid: 123, NlMtu: 1400, Metric: 50},
	}}
}

func TestIPHelperPlanBoundaries(t *testing.T) {
	want := ipHelperTestIntent()
	for _, prefix := range []string{"0.0.0.0/0", "::/0", "::ffff:198.18.0.0/112", "127.0.0.0/8", "fe80::/64", "224.0.0.0/4", "198.18.254.1/24"} {
		t.Run(prefix, func(t *testing.T) {
			bad := want
			bad.Routes = []netip.Prefix{netip.MustParsePrefix(prefix)}
			if _, err := planIPHelper(bad, ipHelperTestObservation()); err == nil {
				t.Fatal("accepted unsafe route")
			}
		})
	}
	for _, mutate := range []func(*ipHelperIntent){
		func(w *ipHelperIntent) { w.Addresses = []netip.Prefix{netip.MustParsePrefix("198.18.254.1/24")} },
		func(w *ipHelperIntent) { w.Routes = append(w.Routes, w.Routes[0]) },
		func(w *ipHelperIntent) { w.MTU = 1279 },
		func(w *ipHelperIntent) { w.Metric = 0 },
	} {
		bad := ipHelperTestIntent()
		mutate(&bad)
		if _, err := planIPHelper(bad, ipHelperTestObservation()); err == nil {
			t.Fatal("accepted invalid intent")
		}
	}
	for _, mutate := range []func(*ipHelperObservation){
		func(o *ipHelperObservation) { o.interfaces[1].InterfaceLuid++ },
		func(o *ipHelperObservation) { o.addresses = []windows.MibUnicastIpAddressRow{{InterfaceLuid: 999}} },
		func(o *ipHelperObservation) { o.routes = []windows.MibIpForwardRow2{{InterfaceLuid: 999}} },
	} {
		have := ipHelperTestObservation()
		mutate(&have)
		if _, err := planIPHelper(want, have); err == nil {
			t.Fatal("accepted foreign OS resource")
		}
	}
	driver, err := newIPHelperDriver(&wintunDevice{}, want.Routes)
	if err != nil {
		t.Fatal(err)
	}
	want.Routes[0] = netip.MustParsePrefix("198.19.0.0/24")
	if _, err = driver.Reconcile(context.Background(), want); err == nil || errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("out-of-scope intent reached device: %v", err)
	}
}

func TestIPHelperPlanDriftAndWithdrawal(t *testing.T) {
	want, have := ipHelperTestIntent(), ipHelperTestObservation()
	p, err := planIPHelper(want, have)
	if err != nil || len(p.addAddr) != 2 || len(p.addRoute) != 2 || len(p.interfaces) != 0 {
		t.Fatalf("initial plan: %+v, %v", p, err)
	}
	for _, prefix := range want.Addresses {
		raw := ipHelperSockaddr(prefix.Addr())
		have.addresses = append(have.addresses, windows.MibUnicastIpAddressRow{
			InterfaceLuid: have.luid, Address: *(*windows.RawSockaddrInet6)(unsafe.Pointer(&raw)), OnLinkPrefixLength: uint8(prefix.Bits()),
		})
	}
	for _, prefix := range want.Routes {
		next := netip.IPv6Unspecified()
		if prefix.Addr().Is4() {
			next = netip.IPv4Unspecified()
		}
		have.routes = append(have.routes, windows.MibIpForwardRow2{
			InterfaceLuid: have.luid, DestinationPrefix: windows.IpAddressPrefix{Prefix: ipHelperSockaddr(prefix.Addr()), PrefixLength: uint8(prefix.Bits())}, NextHop: ipHelperSockaddr(next),
		})
	}
	p, err = planIPHelper(want, have)
	if err != nil || !p.empty() {
		t.Fatalf("stable plan: %+v, %v", p, err)
	}
	have.routes[0].Metric = 9
	have.addresses[1].SkipAsSource = 1
	have.interfaces[0].UseAutomaticMetric = 1
	p, err = planIPHelper(want, have)
	if err != nil || len(p.removeRoute) != 1 || len(p.addRoute) != 1 || len(p.removeAddr) != 1 || len(p.addAddr) != 1 || len(p.interfaces) != 1 {
		t.Fatalf("drift plan: %+v, %v", p, err)
	}
	want.Addresses, want.Routes = nil, nil
	p, err = planIPHelper(want, have)
	if err != nil || len(p.removeRoute) != 2 || len(p.removeAddr) != 2 || len(p.addRoute)+len(p.addAddr) != 0 {
		t.Fatalf("withdrawal plan: %+v, %v", p, err)
	}
}

// This opt-in test changes only its freshly created, uniquely named Wintun
// adapter. It installs isolated benchmark/ULA ranges, never a default route.
func TestIPHelperNativeLifecycle(t *testing.T) {
	if os.Getenv("PHOTON_IPHELPER_SMOKE") != "1" {
		t.Skip("requires elevated Windows VM and pinned adjacent wintun.dll")
	}
	ctx := context.Background()
	device, err := openWintun(ctx, fmt.Sprintf("PhotonIPTest-%d", os.Getpid()), nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(device.Close)
	want := ipHelperTestIntent()
	driver, err := newIPHelperDriver(device, want.Routes)
	if err != nil {
		t.Fatal(err)
	}
	// Record Windows-managed link-local entries outside the reconciler's manual
	// address scope. They must survive both configuration and withdrawal.
	var initial *windows.MibUnicastIpAddressTable
	if err := windows.GetUnicastIpAddressTable(windows.AF_UNSPEC, &initial); err != nil {
		t.Fatal(err)
	}
	var generated []windows.MibUnicastIpAddressRow
	for _, row := range unsafe.Slice(&initial.Table[0], initial.NumEntries) {
		if row.InterfaceLuid == device.luid && ipHelperAddressPrefix(row).Addr().IsLinkLocalUnicast() {
			generated = append(generated, row)
		}
	}
	windows.FreeMibTable(unsafe.Pointer(initial))
	for n := 0; n < 2; n++ {
		after, err := driver.Reconcile(ctx, want)
		if err != nil {
			t.Fatalf("reconcile %d: %v", n, err)
		}
		if len(after.addresses) != 2 || len(after.routes) != 2 {
			t.Fatalf("observation: %+v", after)
		}
	}
	// CreateUnicastIpAddressEntry can return while duplicate-address detection
	// is still tentative. Configuration convergence alone is not tunnel readiness.
	deadline := time.Now().Add(8 * time.Second)
	for {
		o, err := driver.Observe(ctx)
		if err != nil {
			t.Fatal(err)
		}
		ready := len(o.addresses) == 2
		for _, row := range o.addresses {
			ready = ready && row.DadState == 4 /* IpDadStatePreferred */
		}
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("addresses did not become DAD preferred: %+v", o.addresses)
		}
		time.Sleep(50 * time.Millisecond)
	}
	// Delete one owned route behind the reconciler, then verify fresh observation
	// recreates it. This must not depend on a remembered successful apply.
	after, err := driver.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if err := ipHelperCall("DeleteIpForwardEntry2", unsafe.Pointer(&after.routes[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := driver.Reconcile(ctx, want); err != nil {
		t.Fatalf("repair: %v", err)
	}
	bad := want
	bad.Routes = []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")}
	if _, err := driver.Reconcile(ctx, bad); err == nil {
		t.Fatal("default route accepted")
	}
	after, err = driver.Observe(ctx)
	if err != nil {
		t.Fatal(err)
	}
	p, err := planIPHelper(want, after)
	if err != nil || !p.empty() {
		t.Fatalf("invalid intent mutated OS: %+v %v", p, err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := driver.Reconcile(cancelled, want); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancel: %v", err)
	}
	want.Addresses, want.Routes = nil, nil
	after, err = driver.Reconcile(ctx, want)
	if err != nil || len(after.addresses)+len(after.routes) != 0 {
		t.Fatalf("withdraw: %+v %v", after, err)
	}
	for _, row := range generated {
		if err := windows.GetUnicastIpAddressEntry(&row); err != nil {
			t.Fatalf("OS-managed link-local removed: %v", err)
		}
	}
	t.Logf("preserved %d Windows-managed link-local addresses", len(generated))
	// Close while configured proves the adapter owner also cleans up on teardown.
	if _, err := driver.Reconcile(ctx, ipHelperTestIntent()); err != nil {
		t.Fatal(err)
	}
	device.Close()
	if _, err := driver.Observe(ctx); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("observe after close: %v", err)
	}
	row := ipHelperInterfaceRow{Family: windows.AF_INET, InterfaceLuid: device.luid}
	if err := getIPHelperInterface(&row); err == nil {
		t.Fatal("adapter interface survived Close")
	}
	t.Log("native dual-stack add, idempotence, drift repair, invalid-scope rejection, withdrawal and configured adapter teardown passed")
}
