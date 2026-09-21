package main

import (
	"fmt"
	"os"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	"github.com/HiggsNet/photon/pkg/routing/bird"
)

func debugLinks(filter string) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.LinksDebugView](config, controlRequest{Method: "links_view"}, false); err != nil {
		return err
	} else if ok {
		lastFailure := "-"
		if failure := view.Inspection.LastFailure; failure != nil {
			lastFailure = fmt.Sprintf("code=%s message=%s", failure.Code, failure.Message)
		}
		fmt.Printf("daemon: online link_instances=%d desired_links=%d last_link_failure=%s\n",
			view.Inspection.LinkInstances,
			view.Inspection.DesiredLinks,
			lastFailure,
		)
		view.Filter = filter
		return inspecttext.WriteLinksDebug(os.Stdout, view)
	}
	return fmt.Errorf("daemon control socket unavailable; link runtime state requires a running daemon")
}

func showLinks(filter string, verbose bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	if view, ok, err := readCanonicalViewViaControl[inspect.LinksDebugView](config, controlRequest{Method: "links_view"}, false); err != nil {
		return err
	} else if ok {
		return inspecttext.WriteLinks(os.Stdout, view.Inspection, filter, verbose)
	}
	return fmt.Errorf("daemon control socket unavailable; link runtime state requires a running daemon")
}

func debugLinkRoutingState(config *appConfig, birdInstances map[string]*bird.InstanceObservation, groupID string) (state, neighborCount, bestRouteCount string) {
	state = "-"
	neighborCount = "-"
	bestRouteCount = "-"
	if config == nil || groupID == "" {
		return
	}
	// In the per-netns model, routing is configured at the netns level.
	// Map the overlay groupID to netns name and look up the BIRD instance by netns.
	netnsName := routingNetnsForOverlay(config, groupID)
	if netnsName == "" {
		return
	}
	hasRoutingInstance := false
	for _, inst := range config.Routing.Instances {
		if inst.Bird.NetNSName == netnsName && inst.Enabled {
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
