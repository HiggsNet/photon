package photonlinux

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
)

// Reserved by Photon on an upstream interface it manages. Both route and
// address ownership live in the kernel, surviving a daemon restart.
const upstreamProtocol = 242

type upstreamRoute struct {
	Prefix   netip.Prefix
	Gateway  netip.Addr
	Source   netip.Addr
	Metric   uint32
	Protocol uint8
}

type upstreamAddress struct {
	Prefix   netip.Prefix
	Protocol uint8
}

type upstreamSnapshot struct {
	Routes           []upstreamRoute
	Addresses        []upstreamAddress
	UnreadyAddresses map[netip.Addr]uint32
}

type upstreamOperation struct {
	Delete  bool
	Route   *upstreamRoute
	Address *upstreamAddress
}

type upstreamRouteIO interface {
	Read(context.Context) (upstreamSnapshot, error)
	Apply(context.Context, upstreamOperation) error
}

type kernelUpstreamRouteManager struct{}

func newUpstreamRouteManager() *kernelUpstreamRouteManager { return &kernelUpstreamRouteManager{} }

func (*kernelUpstreamRouteManager) EnsureRoutes(ctx context.Context, spec UpstreamRouteSpec) error {
	if spec.Interface == "" {
		return fmt.Errorf("upstream route interface is required")
	}
	// Validate the complete desired input before opening or changing the kernel.
	desired, err := desiredUpstreamState(spec)
	if err != nil {
		return err
	}
	return withUpstreamRouteIO(ctx, spec, func(io upstreamRouteIO) error {
		return reconcileUpstreamRoutes(ctx, io, desired)
	})
}

func desiredUpstreamState(spec UpstreamRouteSpec) (upstreamSnapshot, error) {
	var desired upstreamSnapshot
	for _, prefix := range spec.SourcePrefixes {
		if !prefix.IsValid() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return desired, fmt.Errorf("invalid upstream source prefix %s", prefix)
		}
		desired.Addresses = append(desired.Addresses, upstreamAddress{Prefix: prefix, Protocol: upstreamProtocol})
	}
	slices.SortFunc(desired.Addresses, func(a, b upstreamAddress) int { return compareUpstreamPrefix(a.Prefix, b.Prefix) })
	desired.Addresses = slices.Compact(desired.Addresses)
	sources := make([]netip.Prefix, 0, len(desired.Addresses))
	for _, address := range desired.Addresses {
		sources = append(sources, address.Prefix)
	}
	nextHops, err := upstreamNextHopByFamily(spec.MeshIPv4LL, spec.MeshIPv6LL)
	if err != nil {
		return desired, err
	}
	sourceByFamily := upstreamSourceByFamily(sources)
	for _, prefix := range spec.Prefixes {
		if !prefix.IsValid() || prefix != prefix.Masked() || prefix.Addr().Is4In6() || prefix.Addr().Zone() != "" {
			return desired, fmt.Errorf("invalid upstream route prefix %s", prefix)
		}
		metric := uint32(0)
		if prefix.Addr().Is6() {
			metric = 1024 // Linux normalizes an omitted IPv6 route metric to 1024.
		}
		desired.Routes = append(desired.Routes, upstreamRoute{Prefix: prefix, Gateway: nextHops[prefix.Addr().Is4()], Source: sourceByFamily[prefix.Addr().Is4()], Metric: metric, Protocol: upstreamProtocol})
	}
	slices.SortFunc(desired.Routes, func(a, b upstreamRoute) int { return compareUpstreamPrefix(a.Prefix, b.Prefix) })
	desired.Routes = slices.Compact(desired.Routes)
	return desired, nil
}

func compareUpstreamPrefix(a, b netip.Prefix) int {
	if prefixLess(a, b) {
		return -1
	}
	if prefixLess(b, a) {
		return 1
	}
	return 0
}

func planUpstreamRoutes(current, desired upstreamSnapshot) ([]upstreamOperation, error) {
	var withdraw, addAddresses, addRoutes, removeAddresses []upstreamOperation
	for _, route := range current.Routes {
		if route.Protocol == upstreamProtocol && !slices.Contains(desired.Routes, route) {
			withdraw = append(withdraw, upstreamOperation{Delete: true, Route: &route})
		}
	}
	for _, address := range desired.Addresses {
		// An existing unmarked address is usable but remains administrator-owned.
		if !slices.ContainsFunc(current.Addresses, func(a upstreamAddress) bool { return a.Prefix == address.Prefix }) {
			addAddresses = append(addAddresses, upstreamOperation{Address: &address})
		}
	}
	for _, route := range desired.Routes {
		found := false
		for _, existing := range current.Routes {
			if existing.Prefix != route.Prefix {
				continue
			}
			if existing.Protocol == upstreamProtocol {
				found = found || existing == route
				continue
			}
			borrowed := existing
			borrowed.Protocol = upstreamProtocol
			if borrowed != route {
				return nil, fmt.Errorf("upstream route %s conflicts with an unmanaged route", route.Prefix)
			}
			found = true
		}
		if !found {
			addRoutes = append(addRoutes, upstreamOperation{Route: &route})
		}
	}
	for _, address := range current.Addresses {
		if address.Protocol == upstreamProtocol && !slices.Contains(desired.Addresses, address) {
			removeAddresses = append(removeAddresses, upstreamOperation{Delete: true, Address: &address})
		}
	}
	// Withdraw stale forwarding first. Install new sources before the routes
	// that select them; retire old sources only after the route changes succeed.
	return slices.Concat(withdraw, addAddresses, addRoutes, removeAddresses), nil
}

func reconcileUpstreamRoutes(ctx context.Context, io upstreamRouteIO, desired upstreamSnapshot) error {
	current, err := io.Read(ctx)
	if err != nil {
		return err
	}
	operations, err := planUpstreamRoutes(current, desired)
	if err != nil {
		return err
	}
	for _, operation := range operations {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := io.Apply(ctx, operation); err != nil {
			return err
		}
	}
	return nil
}
