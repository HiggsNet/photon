package photonlinux

import (
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// BuildIPsecAddressRecord merges explicit declarations before automatic fallbacks.
// Interface and global filters never alter Gossip's own endpoint discovery.
func BuildIPsecAddressRecord(config IPsecConfig, interfaces []ipsec.AddressAdvertisement, advertise []string, listen string, endpoints *gossip.EndpointRecord, now time.Time) ipsec.AddressRecord {
	record := ipsec.AddressRecord{Version: 1}
	if config.Role == ipsec.RoleOut {
		return record
	}
	seen := map[string]bool{}
	add := func(ad ipsec.AddressAdvertisement) {
		key := ad.Address
		if key == "" {
			key = ad.Host
		}
		if key == "" || seen[key] {
			return
		}
		seen[key] = true
		record.Addresses = append(record.Addresses, ad)
	}
	// Priority is shared across all explicit kinds. Stable IDs do not depend on
	// another entry appearing/disappearing, or on a lease renewal timestamp.
	var explicit []ipsec.AddressAdvertisement
	for _, entry := range config.AnnounceAddrs {
		addr, err := netip.ParseAddr(strings.TrimSpace(entry.Address))
		if err != nil {
			continue
		}
		explicit = append(explicit, ipsec.AddressAdvertisement{ID: "announce-" + addr.String(), Source: ipsec.SourceManualAddress, Address: addr.String(), Family: ipsecFamily(addr.String()), Priority: entry.Priority, Reachability: ipsecReachability(addr.String())})
	}
	for _, entry := range config.AnnounceDNS {
		host := strings.TrimSpace(entry.Host)
		if host == "" {
			continue
		}
		explicit = append(explicit, ipsec.AddressAdvertisement{ID: "dns-" + host, Source: ipsec.SourceManualDNS, Host: host, Families: []string{ipsec.FamilyIPv4, ipsec.FamilyIPv6}, Priority: entry.Priority, Reachability: ipsec.ReachabilityPublic})
	}
	explicit = append(explicit, interfaces...)
	sort.SliceStable(explicit, func(i, j int) bool {
		if explicit[i].Priority != explicit[j].Priority {
			return explicit[i].Priority > explicit[j].Priority
		}
		return false
	})
	for _, ad := range explicit {
		if ad.Source == ipsec.SourceDiscovery {
			addr, err := netip.ParseAddr(ad.Address)
			if err != nil || !config.AnnounceFilter.Allows(addr) {
				continue
			}
		}
		add(ad)
	}
	// Preserve the legacy top-level declaration independently of whether Gossip
	// endpoint inheritance is enabled, but keep it below explicit IPsec entries.
	for _, entry := range advertise {
		addr := advertiseHost(entry)
		if ipsecFamily(addr) == "" {
			continue
		}
		addAutomaticIPsecAddress(&record, seen, config, ipsec.AddressAdvertisement{ID: "advertise-" + addr, Source: ipsec.SourceManualAddress, Address: addr, Family: ipsecFamily(addr), Priority: DefaultIPsecAnnouncePriority, Reachability: ipsecReachability(addr), Fallback: true})
	}
	if config.AnnounceGossipEndpoints {
		if endpoints != nil {
			eligible := *endpoints
			if len(config.AnnounceInterfaces) > 0 {
				// Explicit interface selection replaces the broad interface scan for
				// IPsec. Otherwise an excluded or withdrawn address returns via Gossip.
				eligible.Endpoints = nil
				for _, entry := range endpoints.Endpoints {
					if strings.Split(entry.Source, "+")[0] != "interface" {
						eligible.Endpoints = append(eligible.Endpoints, entry)
					}
				}
			}
			// The helper maintains its own seen set; global filtering must not mark a
			// rejected address as published.
			for _, ad := range ipsecAddressesFromGossipEndpoints(&eligible, map[string]bool{}, now) {
				addAutomaticIPsecAddress(&record, seen, config, ad)
			}
		}
	}
	// Preserve legacy listen-host fallback only when no interface selector is
	// configured. An empty selected-interface set must not borrow another NIC.
	if len(record.Addresses) == 0 && len(config.AnnounceInterfaces) == 0 {
		addr := advertiseHost(listen)
		if addr != "0.0.0.0" && addr != "::" && ipsecFamily(addr) != "" {
			addAutomaticIPsecAddress(&record, seen, config, ipsec.AddressAdvertisement{ID: "listen", Source: ipsec.SourceLocal, Address: addr, Family: ipsecFamily(addr), Priority: DefaultIPsecAnnouncePriority, Reachability: ipsecReachability(addr), Fallback: true})
		}
	}
	return record
}

func addAutomaticIPsecAddress(record *ipsec.AddressRecord, seen map[string]bool, config IPsecConfig, ad ipsec.AddressAdvertisement) {
	addr, err := netip.ParseAddr(ad.Address)
	if err != nil || seen[ad.Address] || !config.AnnounceFilter.Allows(addr) {
		return
	}
	ad.Fallback = true
	// Gossip-specific weights do not compete with explicit IPsec priorities.
	ad.Priority = DefaultIPsecAnnouncePriority
	seen[ad.Address] = true
	record.Addresses = append(record.Addresses, ad)
}

// ipsecAddressesFromGossipEndpoints updates seen for each accepted address.
func ipsecAddressesFromGossipEndpoints(er *gossip.EndpointRecord, seen map[string]bool, now time.Time) []ipsec.AddressAdvertisement {
	var out []ipsec.AddressAdvertisement
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
			ID:           "endpoint-" + addr,
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
