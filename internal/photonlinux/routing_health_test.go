package photonlinux

import (
	"testing"

	"github.com/HiggsNet/photon/pkg/routing/bird"
)

func TestBirdObservationAcceptsUnselectedBabelRouteOnStagedInterface(t *testing.T) {
	observed := &bird.BirdObservation{
		Neighbors: []bird.BirdNeighbor{{Interface: "phx-new", Metric: 128}},
		Routes: []bird.BirdRoute{{
			Iface:    "phx-new",
			Protocol: "babel1",
			Selected: false,
			Metric:   96,
		}},
	}
	obs := BirdObservationForInterface("link-1", "link-1#staged", "phx-new", observed)
	if !obs.Neighbor || !obs.Route || obs.Metric != 96 {
		t.Fatalf("observation = %+v, want neighbor and unselected staged route", obs)
	}
}
