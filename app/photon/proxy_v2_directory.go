package main

import (
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/photonlinux"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/service"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func buildProxyV2Directory(network *zone.NetworkState, local zone.ZonePath, now time.Time) (map[zone.ZonePath]service.ProxyV2Peer, []string) {
	peers := make(map[zone.ZonePath]service.ProxyV2Peer)
	authorized, _ := routing.BuildAuthorizedRouteSet(network, now)
	var mesh []string
	if authorized != nil {
		for prefix := range authorized.Assignments {
			mesh = append(mesh, prefix.String())
		}
		slices.Sort(mesh)
	}
	verifier := new(photoncrypto.Verifier)
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
			for _, local := range photonlinux.ExternalUpstreamSourcePrefixes(authorized, owner) {
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
