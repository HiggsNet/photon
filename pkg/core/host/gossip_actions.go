package host

import "github.com/HiggsNet/photon/pkg/core/gossip"

// GossipActionPlan classifies one ordered FSM action list into the execution
// phases shared by every host. Entries within each phase retain source order.
type GossipActionPlan struct {
	Snapshots   []gossip.ApplySnapshotAction
	Outbound    []gossip.OutboundMessage
	ObjectPulls []gossip.StartObjectPullAction
	Timers      []gossip.SyncAction
}

// PlanGossipActions is the single common phase-classification switch. Platform
// hosts execute the resulting phases through their state, transport and pull
// controllers without reinterpreting gossip action types.
func PlanGossipActions(actions []gossip.SyncAction) GossipActionPlan {
	var plan GossipActionPlan
	for _, action := range actions {
		if outbound, ok := gossip.OutboundMessageForAction(action); ok {
			plan.Outbound = append(plan.Outbound, outbound)
			continue
		}
		switch typed := action.(type) {
		case gossip.ApplySnapshotAction:
			plan.Snapshots = append(plan.Snapshots, typed)
		case gossip.StartObjectPullAction:
			plan.ObjectPulls = append(plan.ObjectPulls, typed)
		case gossip.StartTimerAction, gossip.CancelTimerAction:
			plan.Timers = append(plan.Timers, action)
		}
	}
	return plan
}
