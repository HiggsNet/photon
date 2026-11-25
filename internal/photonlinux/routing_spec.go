package photonlinux

import (
	"cmp"
	"net/netip"
	"slices"
	"strings"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// BuildBirdInstanceSpec combines parsed configuration with current overlay and route inputs.
func BuildBirdInstanceSpec(inst RoutingInstance, routerID uint32, groups []ipsec.LinkGroupSpec, ars *routing.AuthorizedRouteSet, managedZone zone.ZonePath) bird.BirdInstanceSpec {
	spec := inst.Bird
	spec.RouterID = routerID
	var overlays []string
	for _, group := range groups {
		if NetNSTarget(group.NetNS) != spec.NetNSName {
			continue
		}
		if len(overlays) == 0 {
			ns := group.NetNS.Normalized()
			spec.NetNS = bird.NetNSSpec{Kind: ns.Kind, Name: ns.Name, Path: ns.Path, Create: ns.Create}
		}
		overlays = append(overlays, group.ID)
	}
	if len(overlays) > 0 {
		spec.Overlays = overlays
	}
	if spec.Mode == "" {
		spec.Mode = bird.BirdModeManaged
	}

	// Wire upstream config into BIRD spec.
	if inst.Upstream != nil && inst.Upstream.Enabled {
		spec.Upstream = &bird.UpstreamSpec{
			Interface: inst.Upstream.Veth.MeshInterface,
		}
	}

	// Build static routes for local assigned prefixes.
	if ars != nil && managedZone.Valid() && (inst.Upstream == nil || !inst.Upstream.Enabled || inst.Upstream.Mode == UpstreamModeStatic) {
		for _, prefix := range routing.LocalAssignedPrefixes(ars, managedZone, true) {
			via := ""
			var nextHop netip.Addr
			if inst.Upstream != nil && inst.Upstream.Enabled && inst.Upstream.Mode == UpstreamModeStatic {
				via = inst.Upstream.Veth.MeshInterface
				value := inst.Upstream.Veth.PeerIPv6LL
				if prefix.Addr().Is4() {
					value = inst.Upstream.Veth.PeerIPv4LL
				}
				if parsed, err := netip.ParsePrefix(value); err == nil {
					nextHop = parsed.Addr()
				}
			}
			spec.StaticRoutes = append(spec.StaticRoutes, bird.StaticRouteSpec{
				Prefix:  prefix,
				Via:     via,
				NextHop: nextHop,
			})
		}
	}

	return spec
}

// BirdInterfacePolicies applies configured link costs and rotation costs to current interfaces.
func (inst RoutingInstance) BirdInterfacePolicies(instances map[string]ipsec.LinkInstance, outputs []photonstate.LinkOutput, spec bird.BirdInstanceSpec) []bird.BabelInterfacePolicy {
	byInterface := make(map[string]bird.BabelInterfacePolicy)
	for _, link := range outputs {
		if link.InterfaceName == "" || !LinkOutputBelongsToBirdInstance(link, spec.NetNSName, spec.Overlays) {
			continue
		}
		instanceID := strings.TrimSuffix(link.ID, "#"+photonstate.LinkRuntimeStaged)
		instance, ok := instances[instanceID]
		if !ok {
			for _, candidate := range instances {
				id := candidate.LinkID
				if id == "" {
					id = candidate.ID
				}
				if id == instanceID {
					instance, ok = candidate, true
					break
				}
			}
		}
		rotating := ok && instance.StagedInterfaceName != ""
		cost := effectiveBabelLinkCost(inst.babelLinkCosts, babelLinkCostKey{
			overlay: link.GroupID, peer: link.PeerZone, family: photonstate.LinkPathFamily(link.PathKey),
		})
		if !rotating && cost == (babelLinkCost{}) {
			continue
		}
		metric := spec.MetricBase
		if cost.rxCost != nil {
			metric = *cost.rxCost
		}
		if rotating {
			deprioritized := metric
			if metric < bird.BabelInfinity {
				deprioritized = min(2*metric, bird.BabelInfinity-1)
			}
			staged := link.RuntimeRole == photonstate.LinkRuntimeStaged
			if instance.RotatePhase == ipsec.RotatePhaseDraining {
				if !staged {
					metric = cmp.Or(spec.MetricDraining, deprioritized)
				}
			} else if staged {
				metric = cmp.Or(spec.MetricStaged, deprioritized)
			}
		}
		previous := byInterface[link.InterfaceName]
		rtt := previous.RTT
		if rtt == nil && (cost.rttCost != nil || cost.rttMin != 0 || cost.rttMax != 0) {
			rtt = &bird.BabelRTTPolicy{
				Cost: spec.BabelRTTCost,
				Min:  cmp.Or(cost.rttMin, spec.BabelRTTMin),
				Max:  cmp.Or(cost.rttMax, spec.BabelRTTMax),
			}
			if cost.rttCost != nil {
				rtt.Cost = *cost.rttCost
			}
		}
		byInterface[link.InterfaceName] = bird.BabelInterfacePolicy{
			InterfaceName: link.InterfaceName,
			Metric:        max(metric, previous.Metric),
			RTT:           rtt,
		}
	}
	policies := make([]bird.BabelInterfacePolicy, 0, len(byInterface))
	for _, policy := range byInterface {
		policies = append(policies, policy)
	}
	slices.SortFunc(policies, func(a, b bird.BabelInterfacePolicy) int {
		return strings.Compare(a.InterfaceName, b.InterfaceName)
	})
	return policies
}

// LinkOutputBelongsToBirdInstance matches the namespace and overlay filters used by BIRD.
func LinkOutputBelongsToBirdInstance(link photonstate.LinkOutput, netnsName string, overlays []string) bool {
	if link.NetNS != "" && link.NetNS != netnsName {
		return false
	}
	if len(overlays) == 0 {
		return true
	}
	return slices.Contains(overlays, link.GroupID)
}

// BirdOwner identifies the resources managed by Photon for this routing instance.
func (inst RoutingInstance) BirdOwner() bird.BirdResourceOwner {
	owner := bird.BirdResourceOwner{
		Manager:    "photon",
		InstanceID: inst.ID,
		NetNSName:  inst.Bird.NetNSName,
	}
	owner.Token = bird.OwnerToken(owner.InstanceID, owner.NetNSName)
	owner.ControlSocketToken = bird.ResourceToken(owner, "control_socket")
	owner.PIDFileToken = bird.ResourceToken(owner, "pid_file")
	owner.ConfigFileToken = bird.ResourceToken(owner, "config_file")
	owner.RouteTableToken = bird.ResourceToken(owner, "route_table")
	owner.RuleToken = bird.ResourceToken(owner, "rule")
	return owner
}
