package sadr

import (
	"net/netip"
	"slices"
	"testing"
	"time"
)

func route(dst, src, hop string, metric uint16, now time.Time) Route {
	r := Route{Destination: netip.MustParsePrefix(dst), NextHop: netip.MustParseAddr(hop), RouterID: [8]byte{1}, Metric: metric, ExpiresAt: now.Add(time.Minute)}
	if src != "" {
		r.Source = netip.MustParsePrefix(src)
	}
	return r
}
func allow(Route) bool { return true }

func TestDestinationFirstThenSourceThenMetric(t *testing.T) {
	now := time.Unix(100, 0)
	src, dst := netip.MustParseAddr("2001:db8:2::1"), netip.MustParseAddr("2001:db8:1::1")
	a := route("2001:db8:1::/64", "", "fe80::a", 100, now)
	b := route("::/0", "2001:db8:2::/64", "fe80::b", 1, now)
	routes := []Route{b, a}
	got := Lookup(routes, src, dst, now, allow)
	if len(got) != 1 || got[0].NextHop != a.NextHop {
		t.Fatal("source-first ambiguity chose wrong gateway", got)
	}
	c := route("2001:db8:1::/64", "2001:db8:2::/64", "fe80::c", 500, now)
	routes = append(routes, c)
	got = Lookup(routes, src, dst, now, allow)
	if len(got) != 1 || got[0].NextHop != c.NextHop {
		t.Fatal("source specificity lost to metric", got)
	}
	d := c
	d.NextHop = netip.MustParseAddr("fe80::d")
	d.Metric = 10
	routes = append(routes, d)
	got = Lookup(routes, src, dst, now, allow)
	if len(got) != 1 || got[0].NextHop != d.NextHop {
		t.Fatal("lowest metric not chosen", got)
	}
	got = Lookup(routes, netip.MustParseAddr("2001:db8:3::1"), dst, now, allow)
	if len(got) != 1 || got[0].NextHop != a.NextHop {
		t.Fatal("source constraint silently dropped", got)
	}
}

func TestECMPIsStableAndDeduplicated(t *testing.T) {
	now := time.Unix(100, 0)
	src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.1.0.1")
	a := route("10.1.0.0/16", "", "fe80::a", 10, now)
	b := a
	b.NextHop = netip.MustParseAddr("fe80::b")
	routes := []Route{b, a, b}
	got := Lookup(routes, src, dst, now, allow)
	if len(got) != 2 || got[0] != a || got[1] != b {
		t.Fatal("unstable ECMP", got)
	}
	slices.Reverse(routes)
	other := Lookup(routes, src, dst, now, allow)
	if !slices.Equal(got, other) {
		t.Fatal("input ordering changed ECMP")
	}
	got[0].Metric = 1
	if routes[0].Metric != 10 {
		t.Fatal("result aliases candidate storage")
	}
}

func TestCurrentAuthorizationExpiryAndFailClosed(t *testing.T) {
	now := time.Unix(100, 0)
	src, dst := netip.MustParseAddr("10.0.0.1"), netip.MustParseAddr("10.1.0.1")
	r := route("10.1.0.0/16", "", "fe80::a", 10, now)
	routes := []Route{r}
	authorized := true
	gate := func(Route) bool { return authorized }
	if len(Lookup(routes, src, dst, now, gate)) != 1 {
		t.Fatal("authorized candidate rejected")
	}
	authorized = false
	if len(Lookup(routes, src, dst, now, gate)) != 0 {
		t.Fatal("withdrawn candidate retained")
	}
	if len(Lookup(routes, src, dst, now, nil)) != 0 {
		t.Fatal("missing gate granted permission")
	}
	if len(Lookup(routes, src, dst, r.ExpiresAt, allow)) != 0 {
		t.Fatal("expired route retained")
	}
	if len(Lookup(make([]Route, MaxRoutes+1), src, dst, now, allow)) != 0 {
		t.Fatal("unbounded candidate table")
	}
	for _, mutate := range []func(*Route){
		func(r *Route) { r.Source = netip.MustParsePrefix("2001:db8::/32") },
		func(r *Route) { r.Destination = netip.MustParsePrefix("10.1.0.1/16") },
		func(r *Route) { r.Source = netip.MustParsePrefix("10.0.0.1/8") },
		func(r *Route) { r.NextHop = netip.MustParseAddr("ff02::1") },
		func(r *Route) { r.RouterID = [8]byte{} },
		func(r *Route) { r.Metric = 65535 },
		func(r *Route) { r.ExpiresAt = time.Time{} },
	} {
		invalid := r
		mutate(&invalid)
		if len(Lookup([]Route{invalid}, src, dst, now, allow)) != 0 {
			t.Fatal("invalid candidate accepted", invalid)
		}
	}
}
