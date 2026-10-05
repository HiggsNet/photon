// Package sadr selects authorized source-specific routes. The Babel neighbor
// owner supplies feasible candidates; this package neither originates routes
// nor substitutes route selection for current identity/prefix authorization.
package sadr

import (
	"bytes"
	"net/netip"
	"slices"
	"time"
)

const MaxRoutes = 4096

// Route is a feasible Babel candidate. An invalid Source denotes the
// non-source-specific route. RouterID is the complete on-wire origin ID; a
// next-hop or a partial ID is not an identity binding. ExpiresAt is mandatory.
type Route struct {
	Destination, Source netip.Prefix
	RouterID            [8]byte
	NextHop             netip.Addr
	Metric              uint16
	ExpiresAt           time.Time
}

// Lookup returns all equal-cost choices at the most-specific authorized prefix
// pair (RFC 9079 section 4: destination first, source second). authorize must
// revalidate the active gateway, full origin binding and prefix permissions at
// the caller's current verified revision and time; nil denies every route.
// Inputs and returned values contain no borrowed mutable storage. The caller
// retains the candidate table and owns its revision/neighbor lifecycle.
func Lookup(routes []Route, source, destination netip.Addr, now time.Time, authorize func(Route) bool) []Route {
	if authorize == nil || len(routes) > MaxRoutes || !source.IsValid() || !destination.IsValid() || source.Is4In6() || destination.Is4In6() || source.BitLen() != destination.BitLen() || source.Zone() != "" || destination.Zone() != "" {
		return nil
	}
	bestDestination, bestSource, bestMetric := -1, -1, uint16(65535)
	var selected []Route
	for _, r := range routes {
		if !validRoute(r, source, destination, now) {
			continue
		}
		dstBits, srcBits := r.Destination.Bits(), 0
		if r.Source.IsValid() {
			srcBits = r.Source.Bits()
		}
		if dstBits < bestDestination || dstBits == bestDestination && srcBits < bestSource || dstBits == bestDestination && srcBits == bestSource && r.Metric > bestMetric {
			continue
		}
		if !authorize(r) {
			continue
		}
		if dstBits > bestDestination || srcBits > bestSource || r.Metric < bestMetric {
			selected = selected[:0]
			bestDestination, bestSource, bestMetric = dstBits, srcBits, r.Metric
		}
		selected = append(selected, r)
	}
	// Stable ordering is independent of packet arrival and map iteration order,
	// so a caller can use a stable flow hash without needless path changes.
	slices.SortFunc(selected, func(a, b Route) int {
		if c := a.NextHop.Compare(b.NextHop); c != 0 {
			return c
		}
		return bytes.Compare(a.RouterID[:], b.RouterID[:])
	})
	return slices.CompactFunc(selected, func(a, b Route) bool { return a.NextHop == b.NextHop && a.RouterID == b.RouterID })
}

func validRoute(r Route, source, destination netip.Addr, now time.Time) bool {
	if !r.Destination.IsValid() || r.Destination != r.Destination.Masked() || r.Destination.Addr().Is4In6() || !r.Destination.Contains(destination) || !r.NextHop.IsValid() || r.NextHop.IsUnspecified() || r.NextHop.IsMulticast() || r.NextHop.Is4In6() || r.NextHop.Zone() != "" || r.RouterID == [8]byte{} || r.Metric == 65535 || r.ExpiresAt.IsZero() || !now.Before(r.ExpiresAt) {
		return false
	}
	if r.Source.IsValid() && (r.Source != r.Source.Masked() || r.Source.Addr().Is4In6() || r.Source.Addr().BitLen() != r.Destination.Addr().BitLen() || !r.Source.Contains(source)) {
		return false
	}
	return true
}
