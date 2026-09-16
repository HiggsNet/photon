package photonlinux

import (
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/firewall"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// BuildFirewallPolicyInput assembles the verified derived state for the planner.
func BuildFirewallPolicyInput(spec firewall.FirewallInstanceSpec, ars *routing.AuthorizedRouteSet, verified *corestate.VerifiedState, links []photonstate.LinkOutput, namespaces NetNSConfig, instances []RoutingInstance, now time.Time) firewall.FirewallPolicyInput {
	input := firewall.FirewallPolicyInput{}
	if ars == nil || verified == nil {
		return input
	}
	runtimeNetNS := namespaces.runtimeTarget(spec.NetNS)

	// Local assigned prefixes (AssignedTo == managed zone).
	managedZone := verified.ManagedZone
	// Use AllAssignments through the shared helper: Assignments keeps only one
	// representative per prefix, so it can hide this zone's membership in a
	// shared/anycast assignment when another zone is the representative.
	input.LocalAssigned = routing.LocalAssignedPrefixes(ars, managedZone, true)

	// All authorized mesh prefixes.
	for _, prefixes := range ars.Announced {
		for prefix := range prefixes {
			input.MeshAuthorized = append(input.MeshAuthorized, prefix)
		}
	}

	// Assignment prefixes (import whitelist).
	for prefix := range ars.Assignments {
		input.AssignmentPrefixes = append(input.AssignmentPrefixes, prefix)
	}

	// Provider-neutral live Babel-facing interfaces.
	for _, link := range links {
		if link.InterfaceName != "" &&
			link.Readiness.Interface == "ready" &&
			(link.Provider == "" || link.Provider == ipsec.ProviderStrongSwan) &&
			(link.NetNS == "" || link.NetNS == runtimeNetNS) {
			input.LiveInterfaces = append(input.LiveInterfaces, link.InterfaceName)
		}
	}

	// Upstream interfaces come only from routing instances in this firewall's
	// namespace. This keeps routing as the sole authority for veth names.
	for _, inst := range instances {
		if inst.Enabled &&
			namespaces.runtimeTarget(inst.NetNS) == runtimeNetNS &&
			inst.Upstream != nil &&
			inst.Upstream.Enabled &&
			inst.Upstream.MeshInterface != "" {
			input.UpstreamInterfaces = append(input.UpstreamInterfaces, inst.Upstream.MeshInterface)
		}
	}

	// Forwarding policy is owned by the network namespace and shared with BIRD.
	if !spec.IsHost {
		input.Forwarding = namespaces.ForwardingPolicy(spec.NetNS)
	}

	// Phase 6.3.7: derive revoked prefixes from the route authorization errors.
	// Any prefix in a revoked zone is excluded from allow sets (deny-first).
	for _, e := range ars.Errors {
		if e.Code == "route_zone_revoked" {
			input.Revoked = append(input.Revoked, e.Prefix)
		}
	}

	// Advertised current/previous ports for host redirect. Current advertised
	// ports keep ipsec.port_mode=range usable while charon listens on stable
	// 500/4500; previous ports keep rotate grace alive during the configured
	// window.
	if spec.IsHost && verified.Network != nil && verified.ManagedZone.Valid() {
		input.AdvertisedCurrentIKEPorts, input.AdvertisedCurrentNATTPorts, input.AdvertisedPreviousIKEPorts, input.AdvertisedPreviousNATTPorts = extractIPsecRedirectPortsFromNetwork(verified.Network, verified.ManagedZone, now)
	}

	return input
}

// extractIPsecRedirectPortsFromNetwork reads the signed ipsec/ports record from
// the managed zone's active state and returns current advertised ports plus
// previous-generation ports still within the grace window. These ports are used
// by the host firewall planner to generate DNAT/redirect rules.
func extractIPsecRedirectPortsFromNetwork(network *zone.NetworkState, managedZone zone.ZonePath, now time.Time) (currentIKE []uint16, currentNATT []uint16, previousIKE []uint16, previousNATT []uint16) {
	if network == nil || !managedZone.Valid() {
		return nil, nil, nil, nil
	}
	zs, ok := network.Zones[managedZone]
	if !ok || zs == nil {
		return nil, nil, nil, nil
	}
	record := zs.Records[ipsec.RecordKeyPorts]
	if record == nil {
		return nil, nil, nil, nil
	}
	pr, err := ipsec.ParsePortRecord(record)
	if err != nil || pr == nil {
		return nil, nil, nil, nil
	}
	if pr.Current != nil {
		if pr.Current.IKE.Advertised > 0 {
			currentIKE = append(currentIKE, pr.Current.IKE.Advertised)
		}
		if pr.Current.NATT.Advertised > 0 {
			currentNATT = append(currentNATT, pr.Current.NATT.Advertised)
		}
	}
	for _, sel := range pr.Previous {
		// Check if still within grace window.
		if sel.ValidUntil > 0 && now.Unix() > sel.ValidUntil {
			continue
		}
		if sel.IKE.Advertised > 0 {
			previousIKE = append(previousIKE, sel.IKE.Advertised)
		}
		if sel.NATT.Advertised > 0 {
			previousNATT = append(previousNATT, sel.NATT.Advertised)
		}
	}
	return currentIKE, currentNATT, previousIKE, previousNATT
}
