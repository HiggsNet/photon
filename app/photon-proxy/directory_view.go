package main

import (
	"encoding/json"
	"math"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/service"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// Policy can change as time crosses these boundaries without a store commit.
func nextDirectoryBoundary(network *zone.NetworkState, now time.Time) time.Time {
	var next time.Time
	add := func(at time.Time) {
		if at.After(now) && (next.IsZero() || at.Before(next)) {
			next = at
		}
	}
	addUnix := func(at int64) {
		if at > 0 {
			add(time.Unix(at, 0))
		}
	}
	for _, state := range network.Zones {
		if state == nil {
			continue
		}
		if state.Authority != nil {
			for _, key := range state.Authority.Keys {
				addUnix(key.NotBefore)
				if key.NotAfter > 0 && key.NotAfter < math.MaxInt64 {
					addUnix(key.NotAfter + 1)
				}
			}
		}
		for _, delegation := range state.Delegations {
			if delegation != nil && delegation.ExpiresAt != nil {
				add(*delegation.ExpiresAt)
			}
		}
		for _, delegation := range state.ParentProof {
			if delegation != nil && delegation.ExpiresAt != nil {
				add(*delegation.ExpiresAt)
			}
		}
		for _, revocation := range state.Revocations {
			if revocation != nil {
				addUnix(revocation.RevokedAt)
			}
		}
		for key, record := range state.Records {
			if record == nil {
				continue
			}
			switch {
			case key == service.RecordKeyProxy:
				if capability, err := service.ParseProxyCapability(record); err == nil {
					add(capability.ExpiresAt)
				}
			case strings.HasPrefix(key, service.ProxyV2Prefix):
				var lease service.ProxyV2Lease
				if json.Unmarshal(record.Value, &lease) == nil {
					addUnix(lease.ExpiresAt)
				}
			case key == ipsec.RecordKeyAddresses:
				if addresses, err := ipsec.ParseAddressRecord(record); err == nil {
					for _, address := range addresses.Addresses {
						base := address.LastObserved
						if base == 0 {
							base = addresses.UpdatedAt
						}
						if base > 0 && address.TTLSeconds > 0 && base <= math.MaxInt64-address.TTLSeconds {
							add(time.Unix(base+address.TTLSeconds, 1))
						}
					}
				}
			}
		}
	}
	return next
}

func buildProxyV2Directory(network *zone.NetworkState, local zone.ZonePath, now time.Time, verifier *photoncrypto.Verifier) (map[zone.ZonePath]service.ProxyV2Peer, []string) {
	peers := make(map[zone.ZonePath]service.ProxyV2Peer)
	authorized, _ := routing.BuildAuthorizedRouteSet(network, now)
	var mesh []string
	if authorized != nil {
		for prefix := range authorized.Assignments {
			mesh = append(mesh, prefix.String())
		}
		slices.Sort(mesh)
	}
	for owner, zs := range network.Zones {
		if zs == nil || owner.IsRoot() {
			continue
		}
		peer := service.ProxyV2Peer{
			TLS: make(map[string]service.ProxyV2TLS), Endpoints: make(map[string]service.ProxyV2Endpoint),
		}
		var checkedChain, validChain bool
		for key, record := range zs.Records {
			if !strings.HasPrefix(key, service.ProxyV2Prefix) || record == nil || record.Zone != owner {
				continue
			}
			if !checkedChain {
				validChain = verifier.VerifyChain(network, owner, now) == nil
				checkedChain = true
			}
			if !validChain || verifier.VerifyRecord(record, zs.Authority, now) != nil {
				continue
			}
			body, lease, err := service.ParseProxyV2Record(service.ProxyV2Record{Key: key, Type: record.Type, Value: record.Value})
			if err != nil || !lease.ValidAt(now) {
				continue
			}
			switch value := body.(type) {
			case *service.ProxyV2Identity:
				peer.Identity = value
			case *service.ProxyV2TLS:
				peer.TLS[strings.TrimPrefix(key, service.ProxyV2TLSPrefix)] = *value
			case *service.ProxyV2Endpoint:
				peer.Endpoints[strings.TrimPrefix(key, service.ProxyV2EndpointPrefix)] = *value
			}
		}
		if owner != local && peer.Identity == nil && len(peer.Endpoints) == 0 && len(peer.TLS) == 0 {
			continue
		}
		if authorized != nil {
			for _, local := range routing.ExternalUpstreamSourcePrefixes(authorized, owner) {
				for _, ann := range authorized.Announced[owner] {
					if !ann.SharedAssignment && ann.Prefix.Contains(local.Addr()) {
						peer.Mesh = append(peer.Mesh, local.Addr().String())
						break
					}
				}
			}
			for prefix, ann := range authorized.Announced[owner] {
				ip := prefix.Addr()
				if !ann.SharedAssignment && prefix.Bits() == ip.BitLen() && ip.IsGlobalUnicast() {
					peer.Mesh = append(peer.Mesh, ip.String())
				}
			}
		}
		record := zs.Records[ipsec.RecordKeyAddresses]
		if record != nil && record.Zone == owner && verifier.VerifyRecord(record, zs.Authority, now) == nil {
			if addresses, err := ipsec.ParseAddressRecord(record); err == nil {
				candidates, _ := ipsec.ResolveAddressCandidates(nil, addresses, now, ipsec.AddressCandidateOptions{})
				for _, candidate := range candidates {
					if host := candidate.Host; host != "" {
						peer.IPsec = append(peer.IPsec, host)
					} else if ip, err := netip.ParseAddr(candidate.Address); err == nil && service.ProxyV2PublicAddress(ip) {
						peer.IPsec = append(peer.IPsec, ip.String())
					}
				}
			}
		}
		slices.Sort(peer.Mesh)
		slices.Sort(peer.IPsec)
		peer.Mesh = slices.Compact(peer.Mesh)
		peer.IPsec = slices.Compact(peer.IPsec)
		peers[owner] = peer
	}
	return peers, mesh
}

func buildProxyDirectory(network *zone.NetworkState, now time.Time, verifier *photoncrypto.Verifier) service.ProxyDirectory {
	view := service.ProxyDirectory{Peers: make(map[zone.ZonePath]service.ProxyCapability)}
	seen := make(map[string]zone.ZonePath)
	for owner, zs := range network.Zones {
		if zs == nil {
			continue
		}
		raw := zs.Records[service.RecordKeyProxy]
		if raw == nil || raw.Zone != owner {
			continue
		}
		record, err := service.ParseProxyCapability(raw)
		if err != nil || !record.Active || !record.ExpiresAt.After(now) ||
			verifier.VerifyChain(network, owner, now) != nil || verifier.VerifyRecord(raw, zs.Authority, now) != nil {
			continue
		}
		if record.SPKI != "" {
			if previous, ok := seen[record.SPKI]; ok {
				delete(view.Peers, previous)
				continue
			}
			seen[record.SPKI] = owner
		}
		view.Peers[owner] = record
	}
	return view
}
