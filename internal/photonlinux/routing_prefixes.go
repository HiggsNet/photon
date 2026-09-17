package photonlinux

import (
	"net/netip"
	"sort"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing"
)

// BuildRoutingExportSet computes the BIRD export set using the forwarding policy
// shared with the firewall planner (Phase 6.3.4). An absent or non-transit
// namespace policy exports only locally announced authorized prefixes; transit=true exports
// authorized prefixes filtered by the shared allow/deny lists.
func BuildRoutingExportSet(ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath, policy firewall.ForwardingPolicy) []netip.Prefix {
	localExport := routing.AuthorizedPrefixes(ars, []zone.ZonePath{managedZone})
	if !policy.Transit {
		// Non-transit or no policy: only export locally announced authorized prefixes.
		return localExport
	}
	// Transit: export all authorized prefixes filtered by the policy.
	allAuthorized := routing.AuthorizedPrefixes(ars, nil)
	if len(policy.AllowPrefixes) == 0 && len(policy.DenyPrefixes) == 0 {
		return allAuthorized
	}
	return firewall.FilterAuthorizedByPolicy(allAuthorized, policy)
}

func ExternalUpstreamRoutePrefixes(ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath) []netip.Prefix {
	authorized := routing.AuthorizedPrefixes(ars, nil)
	localAssigned := routing.LocalAssignedPrefixes(ars, managedZone, true)
	if len(authorized) == 0 {
		return nil
	}
	out := make([]netip.Prefix, 0, len(authorized))
	seen := make(map[netip.Prefix]struct{}, len(authorized))
prefixes:
	for _, prefix := range authorized {
		for _, assigned := range localAssigned {
			if prefix.Addr().Is4() == assigned.Addr().Is4() && prefix.Bits() >= assigned.Bits() && assigned.Contains(prefix.Addr()) {
				continue prefixes
			}
		}
		if _, ok := seen[prefix]; ok {
			continue
		}
		seen[prefix] = struct{}{}
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool { return prefixLess(out[i], out[j]) })
	return out
}

func ExternalUpstreamSourcePrefixes(ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath) []netip.Prefix {
	// Source identities belong to the node itself. Shared/anycast prefixes are
	// served behind the upstream veth and must remain routes, not addresses on
	// the veth endpoint itself.
	localAssigned := routing.LocalAssignedPrefixes(ars, managedZone, false)
	out := make([]netip.Prefix, 0, len(localAssigned))
	seen := make(map[netip.Prefix]struct{}, len(localAssigned))
	for _, prefix := range localAssigned {
		addr := prefix.Addr()
		if prefix.Bits() < addr.BitLen() {
			if next := addr.Next(); next.IsValid() && prefix.Contains(next) {
				addr = next
			}
		}
		source := netip.PrefixFrom(addr, prefix.Bits())
		if _, ok := seen[source]; ok {
			continue
		}
		seen[source] = struct{}{}
		out = append(out, source)
	}
	sort.Slice(out, func(i, j int) bool { return prefixLess(out[i], out[j]) })
	return out
}
