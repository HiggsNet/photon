package sadr

import (
	"net/netip"
	"testing"
	"time"
)

func TestHasRouteAgreesWithSelection(t *testing.T) {
	now := time.Unix(100, 0)
	base := route("2001:db8::/32", "", "fe80::a", 200, now)
	specific := route("2001:db8:1::/64", "2001:db8:2::/64", "fe80::b", 10, now)
	specific.RouterID = [8]byte{2}
	source, destination := netip.MustParseAddr("2001:db8:2::1"), netip.MustParseAddr("2001:db8:1::1")
	for _, routes := range [][]Route{nil, {base}, {specific, base}, make([]Route, MaxRoutes+1)} {
		for _, gate := range []func(Route) bool{nil, allow, func(r Route) bool { return r.RouterID == base.RouterID }} {
			for _, at := range []time.Time{now, specific.ExpiresAt} {
				for _, address := range []netip.Addr{source, {}, netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("2001:db8:2::1%eth0")} {
					if got, want := HasRoute(routes, address, destination, at, gate), len(Lookup(routes, address, destination, at, gate)) != 0; got != want {
						t.Fatalf("route verdict %v differs from selection %v", got, want)
					}
				}
			}
		}
	}
}
