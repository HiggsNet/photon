package main

import (
	"sort"

	photonstate "github.com/HiggsNet/photon/internal/state"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/routing/bird"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

// buildStoredLinkInspection projects the daemon-owned Linux runtime result.
// Read paths do not run the IPsec planner or platform drivers again.
func buildStoredLinkInspection(rt *AppContext, instances map[string]ipsec.LinkInstance, reconcile *ipsecObservationSummary, birdInstances map[string]*bird.InstanceObservation, health []inspect.HealthSample) inspect.LinksDebugView {
	input := inspect.LinkInput{Health: append([]inspect.HealthSample(nil), health...)}
	if reconcile != nil {
		input.LastRunUnix = reconcile.LastRunUnix
		input.DesiredLinks = reconcile.DesiredLinks
		input.LastFailure = reconcile.LastFailure
		input.LastDesired = inspectDesiredLinks(reconcile.Desired)
		input.ActualSAs = inspectLinkSAs(reconcile.ActualSAs)
		input.Actions = inspectLinkActions(reconcile.Actions)
		input.Skipped = inspectLinkSkips(reconcile.Skipped)
	}
	ids := sortedLinkInstanceIDs(instances)
	input.Instances = make([]inspect.LinkInstance, 0, len(ids))
	for _, id := range ids {
		inst := instances[id]
		birdState, birdNeighbors, birdBestRoutes := debugLinkRoutingState(rt, birdInstances, inst.GroupID)
		input.Instances = append(input.Instances, inspect.BuildLinkInstanceFromRuntime(inst, inspect.LinkRouting{
			BirdState: birdState, BirdNeighbors: birdNeighbors, BirdBestRoutes: birdBestRoutes,
		}))
	}
	lastDesired := lastReconcileDesiredLinks(reconcile)
	view := inspect.LinksDebugView{
		Inspection: inspect.BuildLinks(input), ReplannedDesired: lastDesired,
		LastDesiredLinks: lastDesired, DesiredPlanSource: "last_reconcile",
	}
	if reconcile != nil {
		view.StoredSAs = inspectLinkSAs(reconcile.ActualSAs)
	}
	return view
}

func lastReconcileDesiredLinks(reconcile *ipsecObservationSummary) int {
	if reconcile == nil {
		return 0
	}
	if len(reconcile.Desired) > 0 {
		return len(reconcile.Desired)
	}
	return reconcile.DesiredLinks
}

func sortedLinkInstanceIDs(instances map[string]ipsec.LinkInstance) []string {
	ids := make([]string, 0, len(instances))
	for id := range instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func inspectDesiredLinks(items []photonstate.DesiredLinkState) []inspect.DesiredLink {
	out := make([]inspect.DesiredLink, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.BuildDesiredLinkFromRuntime(item))
	}
	return out
}

func inspectLinkSAs(items []photonstate.LinkSAState) []inspect.LinkSA {
	out := make([]inspect.LinkSA, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.LinkSA(item))
	}
	return out
}

func inspectLinkActions(items []photonstate.LinkActionState) []inspect.LinkAction {
	out := make([]inspect.LinkAction, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.BuildLinkActionFromRuntime(item))
	}
	return out
}

func inspectLinkSkips(items []photonstate.LinkSkipState) []inspect.LinkSkip {
	out := make([]inspect.LinkSkip, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.BuildLinkSkipFromRuntime(item))
	}
	return out
}
