package photonlinux

import (
	"strings"

	"github.com/HiggsNet/photon/pkg/health"
	"github.com/HiggsNet/photon/pkg/routing/bird"
)

// BirdObservationForInterface converts BIRD routes and neighbors into a health observation.
func BirdObservationForInterface(instanceID, probeID, iface string, observed *bird.BirdObservation) health.BabelObservation {
	obs := health.BabelObservation{InstanceID: instanceID, ProbeID: probeID}
	if iface == "" || observed == nil {
		return obs
	}
	for _, n := range observed.Neighbors {
		if n.Interface != iface {
			continue
		}
		obs.Neighbor = true
		if n.Routes > 0 {
			obs.Route = true
		}
		if n.Metric > 0 && (obs.Metric == 0 || int(n.Metric) < obs.Metric) {
			obs.Metric = int(n.Metric)
		}
	}
	for _, r := range observed.Routes {
		if r.Iface == iface && (strings.Contains(strings.ToLower(r.Protocol), "babel") || strings.Contains(strings.ToLower(r.Source), "babel")) {
			obs.Route = true
			if r.Metric > 0 && (obs.Metric == 0 || int(r.Metric) < obs.Metric) {
				obs.Metric = int(r.Metric)
			}
		}
	}
	return obs
}
