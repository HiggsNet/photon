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
// an established SA. Every eligible peer gets a connection; order only stabilizes diagnostics.
type GatewaySelection struct {
	Zone        zone.ZonePath      `json:"zone"`
	Identity    string             `json:"identity"`
	PublicKey   ed25519.PublicKey  `json:"public_key"`
	Fingerprint string             `json:"fingerprint"`
	Contact     ipsec.ContactPoint `json:"contact"`
}

// AuthorizedGatewayRoute records only the signed origin/prefix authorization.
// It cannot authorize installation: B3/B4 must additionally authenticate the SA
// and match the destination against these signed prefix permissions.
type AuthorizedGatewayRoute struct {
	Origin zone.ZonePath `json:"origin"`
	Prefix netip.Prefix  `json:"prefix"`
}

type GatewayPlan struct {
	Revision    corestate.VerifiedRevision `json:"revision"`
	EvaluatedAt time.Time                  `json:"evaluated_at"`
	Candidates  []GatewayCandidate         `json:"candidates"`
	Targets     []GatewaySelection         `json:"targets,omitempty"`
	Selected    *GatewaySelection          `json:"selected,omitempty"`
	Routes      []AuthorizedGatewayRoute   `json:"route_authorizations,omitempty"`
	Rejected    string                     `json:"rejected,omitempty"`
	outerFamily string
}

func planGateway(ctx context.Context, config *Config, view corestate.View, now time.Time, resolver ipsec.DNSResolver) GatewayPlan {
	plan := planGatewaySelection(ctx, config, view, now, resolver, nil)
	if plan.Selected != nil {
		plan.Routes = authorizedGatewayRoutes(config, view, now)
	}
	return plan
}

func planGatewaySelection(ctx context.Context, config *Config, view corestate.View, now time.Time, resolver ipsec.DNSResolver, verifier *photoncrypto.Verifier) GatewayPlan {
	return planGatewayForFamily(ctx, config, view, now, resolver, verifier, "")
}

func planGatewayForFamily(ctx context.Context, config *Config, view corestate.View, now time.Time, resolver ipsec.DNSResolver, verifier *photoncrypto.Verifier, family string) GatewayPlan {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	plan := GatewayPlan{Revision: view.Revision, EvaluatedAt: now, outerFamily: family}
	plan.Candidates = gatewayCandidates(ctx, config, view, now, resolver, verifier)
	for i := range plan.Candidates {
		candidate := &plan.Candidates[i]
		if family != "" {
			candidate.Contacts = contactsForFamily(candidate.Contacts, family)
		}
		if candidate.Rejected != "" || len(candidate.Contacts) == 0 {
			continue
		}
		selection := GatewaySelection{Zone: candidate.Zone, Identity: candidate.Identity, PublicKey: candidate.PublicKey, Fingerprint: candidate.Fingerprint, Contact: candidate.Contacts[0]}
		plan.Targets = append(plan.Targets, selection)
		if plan.Selected == nil {
			plan.Selected = &selection
		}
	}
	if plan.Selected == nil {
		plan.Rejected = "no authorized gateway contact"
		if err := ctx.Err(); err != nil {
			plan.Rejected = err.Error()
		}
		return plan
	}
	return plan
}

// RevalidateGatewayPlan checks an asynchronous DNS result at consumption time.
// It performs no network I/O: only IPs resolved from signed advertisements in
// the same revision are reused. Time-dependent grants are evaluated again.
func RevalidateGatewayPlan(config *Config, view corestate.View, plan GatewayPlan, now time.Time) GatewayPlan {
	if view.Revision != plan.Revision || plan.Rejected != "" {
		return GatewayPlan{Revision: view.Revision, EvaluatedAt: now, Rejected: "gateway plan is stale or rejected"}
	}
	return revalidateResolvedGateway(config, view, plan, now)
}

// Established SAs can survive unrelated verified revisions. Cached DNS is only
// a short-lived reachability hint: all signed records, chains and route facts
// are reconstructed from the current view, then the caller compares the result
// with the authenticated SA's pinned identity and endpoint. Packet processing
// must never replace the original planner timestamp with this result's time.
func revalidateActiveGateway(config *Config, view corestate.View, plan GatewayPlan, now time.Time) GatewayPlan {
	current := revalidateActiveGatewaySelection(config, view, plan, now, nil)
	if current.Selected != nil {
		current.Routes = authorizedGatewayRoutes(config, view, now)
	}
	return current
}

func revalidateActiveGatewaySelection(config *Config, view corestate.View, plan GatewayPlan, now time.Time, verifier *photoncrypto.Verifier) GatewayPlan {
	if plan.Selected == nil || plan.Rejected != "" || now.Before(plan.EvaluatedAt) || now.Sub(plan.EvaluatedAt) > 10*time.Second {
		return GatewayPlan{Rejected: "active gateway DNS hint expired"}
	}
	return revalidateResolvedGatewaySelection(config, view, plan, now, verifier)
}

func revalidateResolvedGateway(config *Config, view corestate.View, plan GatewayPlan, now time.Time) GatewayPlan {
	current := revalidateResolvedGatewaySelection(config, view, plan, now, nil)
	if current.Selected != nil {
		current.Routes = authorizedGatewayRoutes(config, view, now)
	}
	return current
}

func revalidateResolvedGatewaySelection(config *Config, view corestate.View, plan GatewayPlan, now time.Time, verifier *photoncrypto.Verifier) GatewayPlan {
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
	current := planGatewayForFamily(context.Background(), config, view, now, resolved, verifier, plan.outerFamily)
	// A healthy connection keeps its authenticated contact while other peers or
	// address preference change. A removed contact still forces replacement.
	if plan.Selected != nil && current.Selected != nil && plan.Selected.Zone == current.Selected.Zone {
		for _, candidate := range current.Candidates {
			if candidate.Zone != plan.Selected.Zone {
				continue
			}
			for _, contact := range candidate.Contacts {
				if contact == plan.Selected.Contact {
					current.Selected.Contact = contact
				}
			}
		}
	}
	return current
}

func contactsForFamily(contacts []ipsec.ContactPoint, family string) []ipsec.ContactPoint {
	var selected []ipsec.ContactPoint
	for _, contact := range contacts {
		addr, err := netip.ParseAddr(contact.Address)
		if err == nil && outerFamily(addr) == family {
			selected = append(selected, contact)
		}
	}
	return selected
}

func outerFamily(address netip.Addr) string {
	if address.Unmap().Is4() {
		return ipsec.FamilyIPv4
	}
	return ipsec.FamilyIPv6
}

type gatewayResolvedHosts map[string][]net.IPAddr

func (hosts gatewayResolvedHosts) LookupIPAddr(_ context.Context, host string) ([]net.IPAddr, error) {
	if addresses := hosts[host]; len(addresses) > 0 {
		return addresses, nil
	}
	return nil, fmt.Errorf("no current DNS result for %q", host)
}

func authorizedGatewayRoutes(config *Config, view corestate.View, now time.Time) []AuthorizedGatewayRoute {
	return authorizedGatewayRoutesFromSet(config, currentAuthorizedRouteSet(config, view, now))
}

func authorizedGatewayRoutesFromSet(config *Config, set *routing.AuthorizedRouteSet) []AuthorizedGatewayRoute {
	if set == nil {
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

func currentAuthorizedRouteSet(config *Config, view corestate.View, now time.Time) *routing.AuthorizedRouteSet {
	return currentAuthorizedRouteSetWithVerifier(config, view, now, nil)
}

func currentAuthorizedRouteSetWithVerifier(config *Config, view corestate.View, now time.Time, verifier *photoncrypto.Verifier) *routing.AuthorizedRouteSet {
	if config == nil || view.State == nil || view.State.Network == nil || photoncrypto.VerifyPinnedRoot(view.State.Network, config.TrustedRootPublicKey) != nil {
		return nil
	}
	// BuildAuthorizedRouteSet expects verified active input. A previous verified
	// revision can outlive an authority/delegation: recheck every relevant record
	// and chain against now before invoking the common IPAM authorization logic.
	active := zone.NewNetworkState()
	for path, zs := range view.State.Network.Zones {
		if zs == nil || verifier.VerifyChain(view.State.Network, path, now) != nil {
			continue
		}
		copy := *zs
		copy.Records = make(map[string]*zone.Record)
		for key, record := range zs.Records {
			if !strings.HasPrefix(key, routing.RecordKeyPrefixIPAMPools) && !strings.HasPrefix(key, routing.RecordKeyPrefixIPAMAssignments) && !strings.HasPrefix(key, routing.RecordKeyPrefixRoutes) {
				continue
			}
			if record != nil && record.Zone == path && record.Key == key && verifier.VerifyRecord(record, zs.Authority, now) == nil {
				copy.Records[key] = record
			}
		}
		active.Zones[path] = &copy
	}
	set, err := routing.BuildAuthorizedRouteSet(active, now)
	if err != nil {
		return nil
	}
	return set
}
