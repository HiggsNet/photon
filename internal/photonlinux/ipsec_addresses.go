package photonlinux

import (
	"fmt"
	"net"
	"net/netip"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// BuildIPsecAddressRecord combines local declarations and optional gossip endpoints.
// A nil endpoints argument disables gossip inheritance. Inputs are never mutated.
func BuildIPsecAddressRecord(announce, advertise, dns []string, listen string, endpoints *gossip.EndpointRecord, now time.Time) ipsec.AddressRecord {
	record := ipsec.AddressRecord{Version: 1}
	seen := map[string]bool{}
	priority := 100
	nextID := 1

	addAddress := func(ad ipsec.AddressAdvertisement) {
		if ad.ID == "" {
			ad.ID = fmt.Sprintf("addr-%d", nextID)
			nextID++
		}
		record.Addresses = append(record.Addresses, ad)
		priority--
	}

	// 1. IPsec-specific manual addresses (highest priority).
	for _, candidate := range announce {
		parsed, err := netip.ParseAddr(strings.TrimSpace(candidate))
		if err != nil {
			continue
		}
		addr := parsed.String()
		if seen[addr] {
			continue
		}
		family := ipsecFamily(addr)
		if family == "" {
			continue
		}
		seen[addr] = true
		addAddress(ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("announce-%d", nextID),
			Source:       ipsec.SourceManualAddress,
			Address:      addr,
			Family:       family,
			Priority:     priority,
			Reachability: ipsecReachability(addr),
		})
	}

	// 2. Top-level advertise addresses (backward compatibility).
	for _, candidate := range advertise {
		addr := advertiseHost(candidate)
		if addr == "" || seen[addr] {
			continue
		}
		family := ipsecFamily(addr)
		if family == "" {
			continue
		}
		seen[addr] = true
		addAddress(ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("advertise-%d", nextID),
			Source:       ipsec.SourceManualAddress,
			Address:      addr,
			Family:       family,
			Priority:     priority,
			Reachability: ipsecReachability(addr),
		})
	}

	// 3. Manual DNS names.
	for _, host := range dns {
		host = strings.TrimSpace(host)
		if host == "" || seen[host] {
			continue
		}
		seen[host] = true
		addAddress(ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("dns-%d", nextID),
			Source:       ipsec.SourceManualDNS,
			Host:         host,
			Families:     []string{ipsec.FamilyIPv4, ipsec.FamilyIPv6},
			Priority:     priority,
			Reachability: ipsec.ReachabilityPublic,
		})
	}

	// 4. Follow gossip endpoints (reflector / interface discovery).
	if endpoints != nil {
		for _, ad := range ipsecAddressesFromGossipEndpoints(endpoints, seen, now) {
			addAddress(ad)
		}
	}

	// 5. Fallback to listen_addr host.
	if len(record.Addresses) == 0 {
		host := advertiseHost(listen)
		if host != "" && host != "0.0.0.0" && host != "::" {
			if family := ipsecFamily(host); family != "" {
				addAddress(ipsec.AddressAdvertisement{
					ID:           "listen",
					Source:       ipsec.SourceLocal,
					Address:      host,
					Family:       family,
					Priority:     priority,
					Reachability: ipsecReachability(host),
				})
			}
		}
	}
	return record
}

// ipsecAddressesFromGossipEndpoints updates seen for each accepted address.
func ipsecAddressesFromGossipEndpoints(er *gossip.EndpointRecord, seen map[string]bool, now time.Time) []ipsec.AddressAdvertisement {
	var out []ipsec.AddressAdvertisement
	nextID := 1
	for _, ep := range er.Endpoints {
		addr := ep.Address
		if addr == "" || seen[addr] {
			continue
		}
		family := ipsecFamily(addr)
		if family == "" {
			continue
		}
		// Skip expired grace entries; the endpoint record itself already
		// applies TTL/grace, but re-check here to avoid publishing stale
		// addresses if the record was read before LocalEndpointsToRecord
		// filtered it.
		if ep.LastObserved != 0 {
			ttl := time.Duration(er.TTL) * time.Second
			if ttl <= 0 {
				ttl = gossip.DefaultEndpointTTL
			}
			grace := time.Duration(er.GraceSeconds) * time.Second
			expiresAt := time.Unix(ep.LastObserved, 0).Add(ttl + grace)
			if now.After(expiresAt) {
				continue
			}
		}
		seen[addr] = true
		source, reachability := mapGossipEndpointSourceToIPsec(ep)
		out = append(out, ipsec.AddressAdvertisement{
			ID:           fmt.Sprintf("endpoint-%d", nextID),
			Source:       source,
			Address:      addr,
			Family:       family,
			Priority:     ep.Priority,
			Reachability: reachability,
			// Do not copy LastObserved from gossip endpoints. The IPsec record
			// has declaration semantics; copying endpoint timestamps would make
			// the record change every gossip lease renewal even when the set of
			// addresses is unchanged.
		})
		nextID++
	}
	return out
}

// mapGossipEndpointSourceToIPsec maps a gossip EndpointEntry to an IPsec
// address source and reachability classification.
func mapGossipEndpointSourceToIPsec(ep gossip.EndpointEntry) (source, reachability string) {
	switch strings.Split(ep.Source, "+")[0] {
	case "advertise":
		source = ipsec.SourceManualAddress
	case "reflector":
		source = ipsec.SourceReflector
	case "interface":
		if ep.Scope == "global" {
			source = ipsec.SourceDiscovery
		} else {
			source = ipsec.SourceLocal
		}
	default:
		source = ipsec.SourceDiscovery
	}
	ip := net.ParseIP(ep.Address)
	if ip == nil {
		reachability = ipsec.ReachabilityUnknown
		return
	}
	if ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast() {
		reachability = ipsec.ReachabilityPrivate
	} else {
		reachability = ipsec.ReachabilityPublic
	}
	return
}

func advertiseHost(value string) string {
	value = strings.TrimSpace(value)
	host, _, err := net.SplitHostPort(value)
	if err == nil {
		return strings.Trim(host, "[]")
	}
	if strings.Count(value, ":") > 1 {
		if addr, err := netip.ParseAddr(strings.Trim(value, "[]")); err == nil {
			return addr.String()
		}
	}
	if host, _, ok := strings.Cut(value, ":"); ok {
		return host
	}
	return strings.Trim(value, "[]")
}

func ipsecFamily(addr string) string {
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return ""
	}
	if parsed.Is4() {
		return ipsec.FamilyIPv4
	}
	if parsed.Is6() {
		return ipsec.FamilyIPv6
	}
	return ""
}

func ipsecReachability(addr string) string {
	parsed, err := netip.ParseAddr(addr)
	if err != nil {
		return ipsec.ReachabilityUnknown
	}
	if parsed.IsLoopback() || parsed.IsPrivate() || parsed.IsLinkLocalUnicast() {
		return ipsec.ReachabilityPrivate
	}
	return ipsec.ReachabilityPublic
}

// BuildIPsecContactQuality maps gossip dial outcomes only to matching IPsec port generations.
func BuildIPsecContactQuality(states map[string]gossip.AddrQuality, addresses *ipsec.AddressRecord, ports []ipsec.PortAdvertisement) map[string]ipsec.ContactPointQuality {
	if addresses == nil {
		return nil
	}
	out := make(map[string]ipsec.ContactPointQuality)
	for addrStr, st := range states {
		udpAddr, err := net.ResolveUDPAddr("udp", addrStr)
		if err != nil {
			continue
		}
		ip := udpAddr.IP.String()
		for _, ad := range addresses.Addresses {
			if ad.Address != ip {
				continue
			}
			for _, port := range ports {
				if udpAddr.Port <= 0 || (udpAddr.Port != int(port.IKE.DialPort()) && udpAddr.Port != int(port.NATT.DialPort())) {
					continue
				}
				key := ipsec.ContactPoint{
					AddressID:  ad.ID,
					Address:    ad.Address,
					Generation: port.Generation,
					IKEPort:    port.IKE.DialPort(),
					NATTPort:   port.NATT.DialPort(),
				}.Key()
				out[key] = ipsec.ContactPointQuality{
					Successes:    st.SuccessCount,
					Failures:     st.FailureCount,
					BackoffUntil: st.BackoffUntil,
				}
			}
		}
	}
	return out
}
