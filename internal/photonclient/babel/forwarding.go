package babel

import (
	"bytes"
	"cmp"
	"net/netip"
	"slices"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/sadr"
)

// The leaf owns the table and invalidates it when learned routes change.
// Metrics in the table exclude the common cost of this adjacency.
type forwardingTable struct {
	byDestination map[netip.Prefix][]sadr.Route
	lengths       [2][]int
}

func (l *Leaf) removeRoute(origin Origin) {
	if _, ok := l.routes[origin]; ok {
		delete(l.routes, origin)
		l.forwarding = nil
	}
}

func (l *Leaf) refreshForwarding() {
	if l.forwarding != nil || len(l.routes) == 0 {
		return
	}
	table := &forwardingTable{byDestination: make(map[netip.Prefix][]sadr.Route)}
	var lengths [2][129]bool
	for _, learned := range l.routes {
		m := learned.message
		r := sadr.Route{Destination: m.Prefix, Source: m.SourcePrefix, RouterID: m.RouterID, NextHop: m.NextHop, Metric: m.Metric, ExpiresAt: learned.expires}
		table.byDestination[r.Destination] = append(table.byDestination[r.Destination], r)
		lengths[addressFamily(r.Destination.Addr())][r.Destination.Bits()] = true
	}
	for family, set := range lengths {
		for bits := len(set) - 1; bits >= 0; bits-- {
			if set[bits] {
				table.lengths[family] = append(table.lengths[family], bits)
			}
		}
	}
	for _, routes := range table.byDestination {
		slices.SortFunc(routes, func(a, b sadr.Route) int {
			if c := cmp.Compare(b.Source.Bits(), a.Source.Bits()); c != 0 {
				return c
			}
			if c := cmp.Compare(a.Metric, b.Metric); c != 0 {
				return c
			}
			if c := a.NextHop.Compare(b.NextHop); c != 0 {
				return c
			}
			return bytes.Compare(a.RouterID[:], b.RouterID[:])
		})
	}
	l.forwarding = table
}

func addressFamily(addr netip.Addr) int {
	if addr.Is4() {
		return 0
	}
	return 1
}

// LookupRoute finds the first authorized path in destination, source, metric
// order. Live link cost, lease expiry and authorization are checked on use.
func (l *Leaf) LookupRoute(source, destination netip.Addr, now time.Time, authorize func(sadr.Route) bool) (sadr.Route, bool) {
	if authorize == nil {
		return sadr.Route{}, false
	}
	return l.lookupRoute(source, destination, now, authorize)
}

// LookupInstalledRoute uses the policy already applied by Receive and
// RevalidateRoutes. The serial owner must revalidate before publishing any new
// policy. Neighbor reachability and route lifetime are checked on every lookup.
func (l *Leaf) LookupInstalledRoute(source, destination netip.Addr, now time.Time) (sadr.Route, bool) {
	return l.lookupRoute(source, destination, now, nil)
}

func (l *Leaf) lookupRoute(source, destination netip.Addr, now time.Time, authorize func(sadr.Route) bool) (sadr.Route, bool) {
	if !source.IsValid() || !destination.IsValid() ||
		source.Is4In6() || destination.Is4In6() || source.BitLen() != destination.BitLen() || source.Zone() != "" || destination.Zone() != "" {
		return sadr.Route{}, false
	}
	cost := l.neighbor.Cost(now)
	if cost == MetricInfinity {
		return sadr.Route{}, false
	}
	if l.forwarding == nil {
		return sadr.Route{}, false
	}
	table := l.forwarding
	for _, bits := range table.lengths[addressFamily(destination)] {
		prefix := netip.PrefixFrom(destination, bits).Masked()
		for _, route := range table.byDestination[prefix] {
			metric := uint32(route.Metric) + uint32(cost)
			if metric >= uint32(MetricInfinity) || !now.Before(route.ExpiresAt) ||
				route.Source.IsValid() && !route.Source.Contains(source) {
				continue
			}
			route.Metric = uint16(metric)
			if authorize == nil || authorize(route) {
				return route, true
			}
		}
	}
	return sadr.Route{}, false
}

func (l *Leaf) HasRoute(source, destination netip.Addr, now time.Time, authorize func(sadr.Route) bool) bool {
	_, ok := l.LookupRoute(source, destination, now, authorize)
	return ok
}
