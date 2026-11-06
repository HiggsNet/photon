package photonwindows

import (
	"context"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"testing"
	"time"
)

func TestWindowsOuterRouteSnapshotIgnoresUnrelatedTunAndDetectsActualPath(t *testing.T) {
	if os.Getenv("PHOTON_IPHELPER_SMOKE") != "1" {
		t.Skip("requires elevated isolated Windows VM")
	}
	ctx := context.Background()
	target := netip.MustParseAddr("198.18.254.25")
	before, err := outboundRouteSnapshot([]netip.Addr{target})
	if err != nil {
		t.Fatal(err)
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
	unrelated, err := outboundRouteSnapshot([]netip.Addr{target})
	if err != nil || !maps.Equal(unrelated, before) {
		t.Fatal("unrelated virtual adapter altered outer path", err)
	}
	want.Routes = append(want.Routes, netip.MustParsePrefix("198.18.254.0/24"))
	if _, err := driver.Reconcile(ctx, want); err != nil {
		t.Fatal(err)
	}
	changed, err := outboundRouteSnapshot([]netip.Addr{target})
	if err != nil || !outboundPathsChanged(before, changed) {
		t.Fatal("real path change was ignored", err)
	}
	if _, err := driver.Reconcile(ctx, ipHelperIntent{MTU: 1400, Metric: 50}); err != nil {
		t.Fatal(err)
	}
	restored, err := outboundRouteSnapshot([]netip.Addr{target})
	if err != nil || !maps.Equal(restored, before) {
		t.Fatal("outer route did not restore", err)
	}
}
