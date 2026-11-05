package photonwindows

import (
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
)

// A detached observation input, not a transport/authorization owner. The OS
// observer reads this off the packet loop and never opens the state database.
type networkRouteTargets struct {
	addresses   atomic.Pointer[[]netip.Addr]
	splitRoutes []netip.Prefix
}

func (t *networkRouteTargets) load() []netip.Addr {
	if addresses := t.addresses.Load(); addresses != nil {
		return *addresses
	}
	return nil
}

func (t *networkRouteTargets) update(plan GatewayPlan, bootstrap map[string]*net.UDPAddr, additional ...netip.Addr) {
	addresses := slices.Clone(additional)
	for _, endpoint := range bootstrap {
		if endpoint != nil {
			if address, ok := netip.AddrFromSlice(endpoint.IP); ok {
				addresses = append(addresses, address.Unmap())
			}
		}
	}
	for _, candidate := range plan.Candidates {
		for _, contact := range candidate.Contacts {
			if address, err := netip.ParseAddr(contact.Address); err == nil {
				addresses = append(addresses, address.Unmap())
			}
		}
	}
	addresses = slices.DeleteFunc(addresses, func(address netip.Addr) bool {
		for _, prefix := range t.splitRoutes {
			if prefix.Contains(address) {
				return true
			}
		}
		return !address.IsGlobalUnicast()
	})
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	addresses = slices.Compact(addresses)
	t.addresses.Store(&addresses)
}
