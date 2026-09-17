package photonlinux

import (
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

// BirdRotateInterfacePolicies selects interface costs while old and staged links coexist.
func BirdRotateInterfacePolicies(instances map[string]ipsec.LinkInstance, outputs []photonstate.LinkOutput, spec bird.BirdInstanceSpec) []bird.BabelInterfacePolicy {
	metrics := make(map[string]uint)
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
		if !ok || instance.StagedInterfaceName == "" {
			continue
		}
		metric := spec.MetricBase
		if link.RuntimeRole == photonstate.LinkRuntimeStaged {
			metric = spec.MetricStaged
		}
		if instance.RotatePhase == ipsec.RotatePhaseDraining {
			if link.RuntimeRole == photonstate.LinkRuntimeStaged {
				metric = spec.MetricBase
			} else {
				metric = spec.MetricDraining
			}
		}
		if previous := metrics[link.InterfaceName]; metric > previous {
			metrics[link.InterfaceName] = metric
		}
	}
	policies := make([]bird.BabelInterfacePolicy, 0, len(metrics))
	for iface, metric := range metrics {
		policies = append(policies, bird.BabelInterfacePolicy{InterfaceName: iface, Metric: metric})
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
