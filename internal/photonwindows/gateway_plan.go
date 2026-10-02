package photonwindows

import (
	"context"
	"crypto/ed25519"
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// GatewaySelection is a target for a future authenticated IKE connection, not
// an established SA. The allowlist order selects one gateway deterministically.
type GatewaySelection struct {
	Zone        zone.ZonePath      `json:"zone"`
	Identity    string             `json:"identity"`
	PublicKey   ed25519.PublicKey  `json:"public_key"`
	Fingerprint string             `json:"fingerprint"`
	Contact     ipsec.ContactPoint `json:"contact"`
}

// AuthorizedGatewayRoute records only the signed origin/prefix authorization.
// It cannot authorize installation: B3/B4 must additionally authenticate the SA
// and bind the received Router ID to this exact origin (including collisions).
type AuthorizedGatewayRoute struct {
	Origin zone.ZonePath `json:"origin"`
	Prefix netip.Prefix  `json:"prefix"`
}

type GatewayPlan struct {
	Revision    corestate.VerifiedRevision `json:"revision"`
	EvaluatedAt time.Time                  `json:"evaluated_at"`
	Candidates  []GatewayCandidate         `json:"candidates"`
	Selected    *GatewaySelection          `json:"selected,omitempty"`
	Routes      []AuthorizedGatewayRoute   `json:"route_authorizations,omitempty"`
	Rejected    string                     `json:"rejected,omitempty"`
}

func planGateway(ctx context.Context, config *Config, view corestate.View, now time.Time, resolver ipsec.DNSResolver) GatewayPlan {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	plan := GatewayPlan{Revision: view.Revision, EvaluatedAt: now}
	plan.Candidates = gatewayCandidates(ctx, config, view, now, resolver)
	if err := ctx.Err(); err != nil {
		plan.Rejected = err.Error()
		return plan
	}
	for _, candidate := range plan.Candidates {
		if candidate.Rejected != "" || len(candidate.Contacts) == 0 {
			continue
		}
		plan.Selected = &GatewaySelection{Zone: candidate.Zone, Identity: candidate.Identity, PublicKey: candidate.PublicKey, Fingerprint: candidate.Fingerprint, Contact: candidate.Contacts[0]}
		break
	}
	if plan.Selected == nil {
		plan.Rejected = "no authorized gateway contact"
		return plan
	}
	plan.Routes = authorizedGatewayRoutes(config, view, now)
	return plan
}

// RevalidateGatewayPlan checks an asynchronous DNS result at consumption time.
// It performs no network I/O: only IPs resolved from signed advertisements in
// the same revision are reused. Time-dependent grants are evaluated again.
func RevalidateGatewayPlan(config *Config, view corestate.View, plan GatewayPlan, now time.Time) GatewayPlan {
	if view.Revision != plan.Revision || plan.Rejected != "" {
		return GatewayPlan{Revision: view.Revision, EvaluatedAt: now, Rejected: "gateway plan is stale or rejected"}
	}
	resolved := gatewayResolvedHosts{}
	seen := make(map[string]map[netip.Addr]bool)
	for _, candidate := range plan.Candidates {
		for _, contact := range candidate.Contacts {
			address, err := netip.ParseAddr(contact.Address)
			if contact.Host == "" || err != nil {
				continue
			}
			address = address.Unmap()
			if seen[contact.Host] == nil {
				seen[contact.Host] = make(map[netip.Addr]bool)
			}
			if seen[contact.Host][address] {
				continue
			}
			seen[contact.Host][address] = true
			resolved[contact.Host] = append(resolved[contact.Host], net.IPAddr{IP: net.IP(address.AsSlice())})
		}
	}
	return planGateway(context.Background(), config, view, now, resolved)
}

type gatewayResolvedHosts map[string][]net.IPAddr

func (hosts gatewayResolvedHosts) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if addresses := hosts[host]; len(addresses) > 0 {
		return addresses, nil
	}
	return nil, fmt.Errorf("no current DNS result for %q", host)
}

func authorizedGatewayRoutes(config *Config, view corestate.View, now time.Time) []AuthorizedGatewayRoute {
	if view.State == nil || view.State.Network == nil || photoncrypto.VerifyPinnedRoot(view.State.Network, config.TrustedRootPublicKey) != nil {
		return nil
	}
	// BuildAuthorizedRouteSet expects verified active input. A previous verified
	// revision can outlive an authority/delegation: recheck every relevant record
	// and chain against now before invoking the common IPAM authorization logic.
	active := zone.NewNetworkState()
	for path, zs := range view.State.Network.Zones {
		if zs == nil || photoncrypto.VerifyChain(view.State.Network, path, now) != nil {
			continue
		}
		copy := *zs
		copy.Records = make(map[string]*zone.Record)
		for key, record := range zs.Records {
			if !strings.HasPrefix(key, routing.RecordKeyPrefixIPAMPools) && !strings.HasPrefix(key, routing.RecordKeyPrefixIPAMAssignments) && !strings.HasPrefix(key, routing.RecordKeyPrefixRoutes) {
				continue
			}
			if record != nil && record.Zone == path && record.Key == key && photoncrypto.VerifyRecord(record, zs.Authority, now) == nil {
				copy.Records[key] = record
			}
		}
		active.Zones[path] = &copy
	}
	set, err := routing.BuildAuthorizedRouteSet(active, now)
	if err != nil {
		return nil
	}
	var routes []AuthorizedGatewayRoute
	for origin, announced := range set.Announced {
		for prefix := range announced {
			for _, aggregate := range config.Overlay.SplitRoutes {
				if aggregate.Addr().BitLen() == prefix.Addr().BitLen() && aggregate.Bits() <= prefix.Bits() && aggregate.Contains(prefix.Addr()) {
					routes = append(routes, AuthorizedGatewayRoute{Origin: origin, Prefix: prefix})
					break
				}
			}
		}
	}
	slices.SortFunc(routes, func(a, b AuthorizedGatewayRoute) int {
		if a.Origin != b.Origin {
			return strings.Compare(string(a.Origin), string(b.Origin))
		}
		return strings.Compare(a.Prefix.String(), b.Prefix.String())
	})
	return routes
}
