package main

import (
	"sort"

	"github.com/HiggsNet/photon/internal/inspect"
)

// buildStoredLinkInspection projects the daemon-owned Linux runtime result.
// Read paths do not run the IPsec planner or platform drivers again.
func buildStoredLinkInspection(rt *AppContext, instances map[string]linkInstanceState, reconcile *ipsecObservationSummary, bird map[string]*BirdInstanceState, health []healthLinkJSON) inspect.LinksDebugView {
	input := inspect.LinkInput{Health: inspectLinkHealth(health)}
	if reconcile != nil {
		input.LastRunUnix = reconcile.LastRunUnix
		input.DesiredLinks = reconcile.DesiredLinks
		input.LastError = reconcile.LastError
		input.LastDesired = inspectDesiredLinks(reconcile.Desired)
		input.ActualSAs = inspectLinkSAs(reconcile.ActualSAs)
		input.Actions = inspectLinkActions(reconcile.Actions)
		input.Skipped = inspectLinkSkips(reconcile.Skipped)
	}
	ids := sortedLinkInstanceIDs(instances)
	input.Instances = make([]inspect.LinkInstance, 0, len(ids))
	for _, id := range ids {
		inst := instances[id]
		birdState, birdNeighbors, birdBestRoutes := debugLinkRoutingState(rt, bird, inst.GroupID)
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

func sortedLinkInstanceIDs(instances map[string]linkInstanceState) []string {
	ids := make([]string, 0, len(instances))
	for id := range instances {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func inspectDesiredLinks(items []desiredLinkState) []inspect.DesiredLink {
	out := make([]inspect.DesiredLink, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.BuildDesiredLinkFromRuntime(item))
	}
	return out
}

func inspectLinkSAs(items []linkSAState) []inspect.LinkSA {
	out := make([]inspect.LinkSA, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.LinkSA(item))
	}
	return out
}

func inspectLinkHealth(items []healthLinkJSON) []inspect.LinkHealth {
	out := make([]inspect.LinkHealth, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.LinkHealth{
			ProbeID:         item.ProbeID,
			InstanceID:      item.InstanceID,
			ProbeRole:       item.ProbeRole,
			InterfaceName:   item.InterfaceName,
			State:           item.State,
			ProbeType:       item.ProbeType,
			Sent:            item.Sent,
			Received:        item.Received,
			Lost:            item.Lost,
			LossRatio:       item.LossRatio,
			LastRTTMs:       item.LastRTTMs,
			EWMARTTMs:       item.EWMARTTMs,
			P50RTTMs:        item.P50RTTMs,
			P95RTTMs:        item.P95RTTMs,
			P99RTTMs:        item.P99RTTMs,
			JitterMs:        item.JitterMs,
			ConsecutiveFail: item.ConsecutiveFail,
			LastError:       item.LastError,
			NextProbeUnix:   item.NextProbeUnix,
			CutoverBlocking: item.CutoverBlocking,
		})
	}
	return out
}

func inspectLinkActions(items []linkActionState) []inspect.LinkAction {
	out := make([]inspect.LinkAction, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.BuildLinkActionFromRuntime(item))
	}
	return out
}

func inspectLinkSkips(items []linkSkipState) []inspect.LinkSkip {
	out := make([]inspect.LinkSkip, 0, len(items))
	for _, item := range items {
		out = append(out, inspect.BuildLinkSkipFromRuntime(item))
	}
	return out
}
