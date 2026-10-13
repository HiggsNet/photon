package babel

import (
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
)

func TestLeafHasRouteKeepsCurrentGatesAndPruning(t *testing.T) {
	l, now := leafForTest(t)
	message := remoteUpdate()
	receiveLeaf(t, l, now, message)
	source, destination := netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8::1")
	if !l.HasRoute(source, destination, now, allowCandidate) || l.HasRoute(netip.MustParseAddr("2001:db8:2::1"), destination, now, allowCandidate) {
		t.Fatal("source-specific verdict differs from the learned route")
	}
	// A match must not skip cleanup of another expired candidate.
	expired := message
	expired.Prefix = netip.MustParsePrefix("2001:db8:3::/64")
	l.routes[Origin{Prefix: expired.Prefix, SourcePrefix: expired.SourcePrefix}] = learnedRoute{message: expired, expires: now}
	if !l.HasRoute(source, destination, now, allowCandidate) || len(l.routes) != 1 {
		t.Fatal("existence lookup skipped expired candidate pruning")
	}
	if l.HasRoute(source, destination, now.Add(14*time.Second), allowCandidate) {
		t.Fatal("dead neighbor still authorized delivery")
	}
	if l.HasRoute(source, destination, now, nil) || len(l.routes) != 0 {
		t.Fatal("missing authorization retained a learned candidate")
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
