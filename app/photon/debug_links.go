package main

import (
	"fmt"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/routing/bird"
)

func debugLinks(filter string) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.LinksDebugView](rt, controlRequest{Method: "links_view"}); err != nil {
		return err
	} else if ok {
		fmt.Printf("daemon: online link_instances=%d desired_links=%d last_link_error=%s\n",
			view.Inspection.Summary.LinkInstances,
			view.Inspection.Summary.DesiredLinks,
			dash(view.Inspection.Summary.LastError),
		)
		view.Filter = filter
		return inspecttext.WriteLinksDebug(os.Stdout, view)
	}
	return fmt.Errorf("daemon control socket unavailable; link runtime state requires a running daemon")
}

func showLinks(filter string, verbose bool) error {
	rt, err := NewAppContext()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.LinksDebugView](rt, controlRequest{Method: "links_view"}); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteLinks(os.Stdout, view.Inspection, filter, verbose)
	}
	return fmt.Errorf("daemon control socket unavailable; link runtime state requires a running daemon")
}

func debugLinkRoutingState(rt *AppContext, birdInstances map[string]*bird.InstanceObservation, groupID string) (state, neighborCount, bestRouteCount string) {
	state = "-"
	neighborCount = "-"
	bestRouteCount = "-"
	if rt == nil || rt.Config == nil || groupID == "" {
		return
	}
	// In the per-netns model, routing is configured at the netns level.
	// Map the overlay groupID to netns name and look up the BIRD instance by netns.
	netnsName := routingNetnsForOverlay(rt, groupID)
	if netnsName == "" {
		return
	}
	hasRoutingInstance := false
	for _, inst := range rt.Config.Routing.Instances {
		if inst.NetNS == netnsName && inst.Enabled {
			hasRoutingInstance = true
			break
		}
	}
	if !hasRoutingInstance {
		return
	}
	state = "pending"
	if birdInstances != nil {
		if inst := birdInstances[netnsName]; inst != nil {
			state = inst.State
			if state == "" {
				state = "pending"
			}
		}
	}
	return
}

func desiredByInstanceID(items []desiredLinkState) map[string]desiredLinkState {
	out := map[string]desiredLinkState{}
	for _, item := range items {
		if item.InstanceID != "" {
			out[item.InstanceID] = item
		}
	}
	return out
}
