package host

import (
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestPlanGossipActionsClassifiesInStableOrder(t *testing.T) {
	now := time.Unix(100, 0)

	actions := []gossip.SyncAction{
		gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "a.catofes."},
		gossip.SendPingAction{PeerID: "peer-a"},
		gossip.ApplySnapshotAction{PeerID: "peer-a", Snapshot: &corestate.ZoneSnapshot{Zone: "a.catofes."}},
		gossip.StartTimerAction{PeerID: "peer-a", Kind: gossip.TimerKindRound, Deadline: now},
		gossip.StartObjectPullAction{PeerID: "peer-a", Zone: "b.catofes."},

		gossip.CancelTimerAction{PeerID: "peer-a", Kind: gossip.TimerKindCatalogPage},
	}

	plan := PlanGossipActions(actions)
	if len(plan.Snapshots) != 1 || plan.Snapshots[0].Snapshot.Zone != "a.catofes." {
		t.Fatalf("snapshots = %#v", plan.Snapshots)
	}
	if len(plan.Outbound) != 1 || plan.Outbound[0].PeerID != "peer-a" || plan.Outbound[0].Message.Type != gossip.MessagePing {
		t.Fatalf("outbound = %#v", plan.Outbound)
	}
	if len(plan.ObjectPulls) != 2 || plan.ObjectPulls[0].Zone != "a.catofes." || plan.ObjectPulls[1].Zone != "b.catofes." {
		t.Fatalf("object pulls lost source order: %#v", plan.ObjectPulls)
	}
	if len(plan.Timers) != 2 {
		t.Fatalf("timers = %#v", plan.Timers)
	}
}
