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
	changed     chan struct{}
}

type outboundRoute struct {
	source     netip.Addr
	nextHop    netip.Addr
	index      uint32
	luid       uint64
	mtu        uint32
	prefixBits int
	metric     uint64
}

func (p outboundRoute) precedes(other outboundRoute) bool {
	if other.index == 0 {
		return true
	}
	if p.prefixBits != other.prefixBits {
		return p.prefixBits > other.prefixBits
	}
	if p.metric != other.metric {
		return p.metric < other.metric
	}
	return p.luid < other.luid
}

func (t *networkRouteTargets) load() []netip.Addr {
	if addresses := t.addresses.Load(); addresses != nil {
		return *addresses
	}
	return nil
}

func (t *networkRouteTargets) publish(addresses []netip.Addr) {
	if slices.Equal(t.load(), addresses) {
		return
	}
	t.addresses.Store(&addresses)
	select {
	case t.changed <- struct{}{}:
	default:
	}
}

// A plan refresh can change the monitored peers without changing any path.
// New targets get a baseline; only paths observed in both samples can change.
func outboundPathsChanged(previous, current map[netip.Addr]string) bool {
	for target, path := range current {
		if old, ok := previous[target]; ok && old != path {
			return true
		}
	}
	return false
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
	addresses = slices.DeleteFunc(addresses, func(address netip.Addr) bool {
		for _, prefix := range t.splitRoutes {
			if prefix.Contains(address) {
				return true
			}
		}
		return !address.IsGlobalUnicast()
	})
	// IKE/ESP contacts are outer targets even when their address overlaps a
	// configured overlay prefix. Only Gossip uses the split-route exception.
	for _, candidate := range plan.Candidates {
		for _, contact := range candidate.Contacts {
			if address, err := netip.ParseAddr(contact.Address); err == nil && address.Unmap().IsGlobalUnicast() {
				addresses = append(addresses, address.Unmap())
			}
		}
	}
	slices.SortFunc(addresses, func(a, b netip.Addr) int { return a.Compare(b) })
	addresses = slices.Compact(addresses)
	t.publish(addresses)
}
