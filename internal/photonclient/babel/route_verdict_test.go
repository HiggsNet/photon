package babel

import (
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
)

func TestLeafForwardingTracksCurrentRoutesAndPolicy(t *testing.T) {
	l, now := leafForTest(t)
	specific := remoteUpdate()
	fallback := specific
	fallback.Prefix = netip.MustParsePrefix("2001:db8::/48")
	fallback.SourcePrefix = netip.Prefix{}
	fallback.Interval = 200
	receiveLeaf(t, l, now, specific, fallback)
	source, destination := netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8::1")
	check := func(at time.Time, authorize func(sadr.Route) bool, want Message) {
		t.Helper()
		got, ok := l.LookupRoute(source, destination, at, authorize)
		if !ok || got.Destination != want.Prefix || got.Source != want.SourcePrefix {
			t.Fatalf("lookup at %v: got %+v, want %v from %v", at, got, want.Prefix, want.SourcePrefix)
		}
	}
	check(now, allowCandidate, specific)
	check(now, func(route sadr.Route) bool { return route.Destination != specific.Prefix }, fallback)
	check(now.Add(3500*time.Millisecond), allowCandidate, fallback)
	receiveLeaf(t, l, now, Message{Type: TLVIHU, Address: neighborLocal, Metric: 200, Interval: 400})
	if got, _ := l.LookupRoute(source, destination, now, allowCandidate); got.Metric != 250 {
		t.Fatalf("lookup kept the old link cost: %+v", got)
	}
	l.RevalidateRoutes(now, func(route sadr.Route) bool { return route.Destination != specific.Prefix })
	check(now, allowCandidate, fallback)
	receiveLeaf(t, l, now, specific)
	check(now, allowCandidate, specific)
	specific.Metric = MetricInfinity
	receiveLeaf(t, l, now, specific)
	check(now, allowCandidate, fallback)
	if l.HasRoute(source, destination, now.Add(14*time.Second), allowCandidate) || l.HasRoute(source, destination, now, nil) {
		t.Fatal("lookup bypassed live neighbor or authorization gate")
	}
	l.Tick(now.Add(7 * time.Second))
	if l.HasRoute(source, destination, now.Add(7*time.Second), allowCandidate) || len(l.routes) != 0 {
		t.Fatal("control tick retained an expired route")
	}
}

func BenchmarkLeafRouteVerdict(b *testing.B) {
	for _, fast := range []bool{false, true} {
		name := "CandidatesLookup"
		if fast {
			name = "HasRoute"
		}
		b.Run(name, func(b *testing.B) {
			l, now := leafForTest(b)
			receiveLeaf(b, l, now, remoteUpdate())
			source, destination := netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8::1")
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				matched := false
				if fast {
					matched = l.HasRoute(source, destination, now, allowCandidate)
				} else {
					matched = len(sadr.Lookup(l.Candidates(now, allowCandidate), source, destination, now, allowCandidate)) != 0
				}
				if !matched {
					b.Fatal("valid route was rejected")
				}
			}
		})
	}
}
