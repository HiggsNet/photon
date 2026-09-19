package ipsec

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"
)

// LocalAnnounceDNSForceUpdates detects the asymmetric case where this node is
// the initiator and its own advertised DNS address moved while StrongSwan still
// reports the old SA as established. It uses the live SA endpoint and traffic
// counters instead of persisting a second DNS snapshot.
func LocalAnnounceDNSForceUpdates(ctx context.Context, hosts []string, reconnectAfter time.Duration, desired []TransportLinkSpec, instances map[string]LinkInstance, sas []SAState, resolver DNSResolver) (map[string]string, error) {
	if len(hosts) == 0 || reconnectAfter <= 0 || resolver == nil {
		return nil, nil
	}
	resolved := make(map[netip.Addr]struct{})
	for _, host := range hosts {
		addresses, err := resolver.LookupIPAddr(ctx, host)
		if err != nil {
			// A partial answer set is unsafe: the current SA may correspond to
			// the name that failed, so force no reconnect this round.
			return nil, fmt.Errorf("resolve local announce DNS %q: %w", host, err)
		}
		for _, address := range addresses {
			if address.IP == nil {
				continue
			}
			if addr, ok := netip.AddrFromSlice(address.IP); ok {
				resolved[addr.Unmap()] = struct{}{}
			}
		}
	}
	if len(resolved) == 0 {
		return nil, nil
	}

	threshold := uint64(reconnectAfter / time.Second)
	updates := make(map[string]string)
	for _, spec := range desired {
		if !IsActiveInitiatorRole(spec.InitiatorRole) {
			continue
		}
		id := LinkInstanceID(spec)
		instance, ok := instances[id]
		if !ok {
			continue
		}
		var sa SAState
		for _, candidate := range sas {
			if candidate.Name == instance.IKEName || candidate.ChildSA == instance.ChildSAName || (instance.XFRMIfID != 0 && candidate.XFRMIfID == instance.XFRMIfID) {
				sa = candidate
				break
			}
		}
		idle := sa.InboundIdleSecs
		if sa.InboundPackets == 0 {
			idle = max(sa.ChildAgeSeconds, sa.IKEAgeSeconds)
		}
		if !sa.Established || !sa.InitiatorKnown || !sa.Initiator || !sa.InboundKnown || (threshold == 0 || idle < threshold) {
			continue
		}
		localAddr, ok := endpointAddr(sa.LocalEndpoint)
		if !ok {
			continue
		}
		if _, present := resolved[localAddr]; present {
			continue
		}
		compatible := false
		for address := range resolved {
			if address.Is4() == localAddr.Is4() && addressScope(address) == addressScope(localAddr) {
				compatible = true
				break
			}
		}
		if compatible {
			updates[id] = "local announce DNS changed after inbound idle"
		}
	}
	if len(updates) == 0 {
		return nil, nil
	}
	return updates, nil
}

func endpointAddr(endpoint string) (netip.Addr, bool) {
	host, _, err := net.SplitHostPort(endpoint)
	if err != nil {
		host = strings.Trim(endpoint, "[]")
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.IsUnspecified() || addr.IsLoopback() || addr.IsLinkLocalUnicast() {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func addressScope(addr netip.Addr) string {
	if addr.IsPrivate() || netip.MustParsePrefix("100.64.0.0/10").Contains(addr) {
		return "private"
	}
	return "public"
}
