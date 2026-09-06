package host

import (
	"context"
	"errors"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	GossipPhaseStateRead   = "state_read"
	GossipPhaseApply       = "snapshot_apply"
	GossipPhaseSend        = "send"
	GossipPhaseObjectPull  = "object_pull"
	GossipPhaseTimer       = "timer"
	GossipPhasePersistence = "persistence"
)

var errGossipSenderRequired = errors.New("gossip sender is required")

// GossipStateView is the bounded read projection required by the common
// executor after snapshot application. It never exposes a live state root.
type GossipStateView struct {
	Loaded       bool
	ManagedZone  zone.ZonePath
	Digests      []corestate.ZoneDigest
	SenderPeerID string
}

// GossipSnapshotApplyResult reports whether the verified network changed.
type GossipSnapshotApplyResult struct {
	NetworkChanged bool
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
// event loop. Aborted means state read/apply failed and later effects were not
// executed.
type GossipExecutionResult struct {
	NetworkChanged bool
	Aborted        bool
}

// ExecuteGossipActions owns the shared effect ordering for one FSM event:
// read/apply, refresh/reconcile, send, object pull, timer, backoff and
// persistence. The sender performs only actual datagram I/O.
func (driver *GossipDriver) ExecuteGossipActions(
	ctx context.Context,
	session *gossip.SyncSession,
	actions []gossip.SyncAction,
	controller GossipSender,
) GossipExecutionResult {
	var result GossipExecutionResult
	if driver == nil || controller == nil {
		result.Aborted = true
		return result
	}
	if ctx == nil {
		ctx = context.Background()
	}
	view := driver.gossipStateView()
	if !view.Loaded {
		return result
	}

	plan := PlanGossipActions(actions)
	applyResult := GossipSnapshotApplyResult{}
	if len(plan.Snapshots) > 0 {
		peerID := ""
		if session != nil {
			peerID = session.PeerID
		}
		var err error
		applyResult, err = driver.applyGossipSnapshots(ctx, peerID, plan.Snapshots, view)
		if err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseApply, PeerID: peerID, Err: err})
			result.Aborted = true
			return result
		}
		result.NetworkChanged = applyResult.NetworkChanged
		if result.NetworkChanged {
			view = driver.gossipStateView()
			if !view.Loaded {
				driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseStateRead, PeerID: peerID, Err: errors.New("gossip state unavailable after snapshot apply")})
				result.Aborted = true
				return result
			}
		}
	}

	if session != nil && !session.Done() && view.Loaded {
		actions = append(actions, session.ReconcilePendingWithDigests(view.Digests)...)
		plan = PlanGossipActions(actions)
	}

	for _, outbound := range plan.Outbound {
		if err := controller.SendGossip(ctx, outbound); err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseSend, PeerID: outbound.PeerID, Err: err})
		}
	}
	for _, pull := range plan.ObjectPulls {
		if err := driver.SubmitGossipObjectPull(pull); err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseObjectPull, PeerID: pull.PeerID, Err: err})
			_ = driver.PostGossip(&gossip.ObjectPullResultEvent{PeerID: pull.PeerID, Zone: pull.Zone, Err: err})
		}
	}
	for _, timer := range plan.Timers {
		if _, err := driver.ApplyGossipTimerAction(timer); err != nil {
			driver.reportGossipIssue(GossipExecutionIssue{Phase: GossipPhaseTimer, PeerID: syncActionPeerID(timer), Err: err})
		}
	}
	if err := driver.commitGossipEventCheckpoint(ctx, session, plan.Backoffs, driver.schedulerForRead().clock.Now()); err != nil {
		peerID := ""
		if session != nil {
			peerID = session.PeerID
		}
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
