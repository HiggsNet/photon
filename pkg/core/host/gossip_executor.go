package host

import (
	"context"
	"errors"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

const (
	GossipPhaseStateRead   = "state_read"
	GossipPhaseApply       = "snapshot_apply"
	GossipPhaseSend        = "send"
	GossipPhaseObjectPull  = "object_pull"
	GossipPhaseTimer       = "timer"
	GossipPhasePersistence = "persistence"
)

// GossipSnapshotApplyResult returns committed changes and application results.
type GossipSnapshotApplyResult struct {
	NetworkChanged bool
	Events         []gossip.SyncEvent
}

// GossipExecutionIssue reports a failed effect without making platform
// logging part of protocol policy.
type GossipExecutionIssue struct {
	Phase  string
	PeerID string
	Err    error
}

// GossipSender is the narrow outbound datagram capability used by GossipDriver.
type GossipSender interface {
	SendGossip(context.Context, gossip.OutboundMessage) error
}

// GossipExecutionResult is the common executor outcome consumed by the host
// event loop.
type GossipExecutionResult struct {
	NetworkChanged bool
	// Events must advance on the consumer after the ordered effects finish.
	Events []gossip.SyncEvent
}

// ExecuteGossipActions uses the event's catalog for ordered effects:
// apply, refresh/reconcile, send, object pull, timer and checkpoint
// persistence. The sender performs only actual datagram I/O.
func (driver *GossipDriver) ExecuteGossipActions(
	ctx context.Context,
	session *gossip.SyncSession,
	catalog *corestate.CatalogView,
	actions []gossip.SyncAction,
	controller GossipSender,
) GossipExecutionResult {
	var result GossipExecutionResult
	if driver == nil || controller == nil || catalog == nil {
		return result
	}
	if ctx == nil {
		ctx = context.Background()
	}
	plan := PlanGossipActions(actions)
	peerID := ""
	if session != nil {
		peerID = session.PeerID
	}
	if len(plan.Snapshots) > 0 {
		applyResult, err := driver.applyGossipSnapshots(ctx, peerID, plan.Snapshots, catalog.ManagedZone)
		if err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseApply, PeerID: peerID, Err: err})
			for _, snapshot := range plan.Snapshots {
				if snapshot.ReportResult && snapshot.Snapshot != nil {
					result.Events = append(result.Events, &gossip.SnapshotAppliedEvent{PeerID: peerID, Zone: snapshot.Snapshot.Zone, Err: err})
				}
			}
			return result
		}
		result.NetworkChanged = applyResult.NetworkChanged
		result.Events = applyResult.Events
	}

	if session != nil && !session.Done() {
		if result.NetworkChanged {
			catalog = driver.readGossipCatalog()
			if catalog == nil {
				driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseStateRead, PeerID: peerID, Err: errors.New("gossip state unavailable after snapshot apply")})
				return result
			}
		}
		actions = append(actions, session.ReconcilePendingWithDigests(catalog.Digests)...)
		plan = PlanGossipActions(actions)
	}

	for _, outbound := range plan.Outbound {
		if err := controller.SendGossip(ctx, outbound); err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: outbound.PeerID, Err: err})
		}
	}
	for _, pull := range plan.ObjectPulls {
		if err := driver.submitGossipObjectPull(session, pull); err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseObjectPull, PeerID: pull.PeerID, Err: err})
			result.Events = append(result.Events, &gossip.ObjectPullResultEvent{PeerID: pull.PeerID, Zone: pull.Zone, Err: err})
		}
	}
	for _, timer := range plan.Timers {
		if _, err := driver.ApplyGossipTimerAction(timer); err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseTimer, PeerID: syncActionPeerID(timer), Err: err})
		}
	}
	if err := driver.commitGossipEventCheckpoint(ctx, session, driver.schedulerForRead().clock.Now()); err != nil {
		driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhasePersistence, PeerID: peerID, Err: err})
	}
	return result
}

func syncActionPeerID(action gossip.SyncAction) string {
	switch typed := action.(type) {
	case gossip.StartTimerAction:
		return typed.PeerID
	case gossip.CancelTimerAction:
		return typed.PeerID
	default:
		return ""
	}
}
