package host

import (
	"context"
	"errors"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// GossipStateStore is the common committed-state dependency owned by one
// GossipDriver. Platform composition may serialize this store with its own
// driver bucket, but it must not reinterpret the returned verified state or
// maintain a second gossip projection.
type GossipStateStore interface {
	ReadView() corestate.View
	ApplyRemoteBatch(context.Context, string, []corestate.RemoteSnapshot, time.Time) (corestate.RemoteBatchResult, error)
	UpdatePeerCheckpoints(context.Context, map[string]corestate.PeerCheckpointPatch) (corestate.CommitResult, error)
}

// GossipDriverConfig contains platform-neutral values fixed when one
// GossipDriver is constructed. Socket addresses and platform handles do not
// belong here.
type GossipDriverConfig struct {
	PeerID    string
	Limits    corestate.SyncLimits
	Discovery GossipDiscoveryConfig
	Log       func(GossipDriverLog)
}

type GossipDriverLog struct {
	Level  string
	Event  string
	PeerID string
	Phase  string
	Err    error
	Fields map[string]any
}

func cloneGossipDriverConfig(config GossipDriverConfig) GossipDriverConfig {
	config.Discovery.Bootstrap = cloneBootstrapPeers(config.Discovery.Bootstrap)
	config.Discovery.BootstrapPeers = append([]string(nil), config.Discovery.BootstrapPeers...)
	config.Discovery.SourceOrder = append([]string(nil), config.Discovery.SourceOrder...)
	return config
}

func (driver *GossipDriver) logGossip(level, event, peerID, phase string, err error, fields map[string]any) {
	config := driver.GossipConfig()
	if config.Log != nil {
		config.Log(GossipDriverLog{Level: level, Event: event, PeerID: peerID, Phase: phase, Err: err, Fields: fields})
	}
}

func (driver *GossipDriver) reportGossipIssue(issue GossipExecutionIssue) {
	event := "gossip_effect_failed"
	switch issue.Phase {
	case GossipPhaseApply:
		event = "snapshot_batch_commit_failed"
	case GossipPhaseInbound:
		event = "event_dropped"
	case GossipPhaseTimer:
		event = "timer_action_failed"
	case GossipPhasePersistence:
		event = "save_failed"
	}
	driver.logGossip("warn", event, issue.PeerID, issue.Phase, issue.Err, nil)
}

func (driver *GossipDriver) gossipStateView() GossipStateView {
	if driver == nil || driver.gossipState == nil {
		return GossipStateView{}
	}
	view := driver.gossipState.ReadView()
	if view.State == nil || view.State.Network == nil {
		return GossipStateView{}
	}
	return GossipStateView{
		Loaded:       true,
		ManagedZone:  view.State.ManagedZone,
		Digests:      corestate.ZoneDigests(view.State.Network),
		SenderPeerID: driver.GossipConfig().PeerID,
	}
}

// GossipCatalogSummary returns the current committed catalog summary without
// exposing the verified Network back to platform orchestration.
func (driver *GossipDriver) GossipCatalogSummary() *corestate.CatalogSummary {
	view := driver.gossipStateView()
	if !view.Loaded {
		return nil
	}
	return corestate.CatalogSummaryForDigests(view.Digests)
}

func (driver *GossipDriver) applyGossipSnapshots(
	ctx context.Context,
	peerID string,
	actions []gossip.ApplySnapshotAction,
	view GossipStateView,
) (GossipSnapshotApplyResult, error) {
	if driver == nil || driver.gossipState == nil {
		return GossipSnapshotApplyResult{}, errors.New("gossip state store is not configured")
	}
	managedZone := view.ManagedZone
	selected := make([]gossip.ApplySnapshotAction, 0, len(actions))
	batch := make([]corestate.RemoteSnapshot, 0, len(actions))
	for _, action := range actions {
		if action.Snapshot == nil {
			continue
		}
		if action.Snapshot.Zone == managedZone {
			driver.logGossip("debug", "skipping_own_zone_snapshot", peerID, GossipPhaseApply, nil, map[string]any{"zone": action.Snapshot.Zone})
			continue
		}
		limits := driver.GossipConfig().Limits
		if limits.MaxZones <= 0 || limits.MaxRecords <= 0 || limits.MaxBytes <= 0 {
			limits = corestate.DefaultSyncLimits()
		}
		if action.RelaxedLimits {
			limits.MaxBytes = 8 << 20
		}
		selected = append(selected, action)
		batch = append(batch, corestate.RemoteSnapshot{
			Snapshot: action.Snapshot, ExpectedRoot: append([]byte(nil), action.ExpectedRoot...), Limits: limits,
		})
	}
	if len(batch) == 0 {
		return GossipSnapshotApplyResult{}, nil
	}
	result, err := driver.gossipState.ApplyRemoteBatch(ctx, peerID, batch, driver.schedulerForRead().clock.Now())
	if err != nil {
		return GossipSnapshotApplyResult{}, err
	}
	for index, action := range selected {
		outcome := corestate.RemoteApplyOutcome{Zone: action.Snapshot.Zone}
		if index < len(result.Outcomes) {
			outcome = result.Outcomes[index]
		} else {
			outcome.Err = errors.New("snapshot apply produced no outcome")
		}
		driver.logGossipSnapshotOutcome(peerID, managedZone, action, outcome)
		if action.ReportResult {
			_ = driver.PostGossip(&gossip.SnapshotAppliedEvent{PeerID: peerID, Zone: action.Snapshot.Zone, Err: outcome.Err})
		}
	}
	return GossipSnapshotApplyResult{NetworkChanged: result.Changes.NetworkChanged}, nil
}

func (driver *GossipDriver) logGossipSnapshotOutcome(peerID string, managedZone zone.ZonePath, action gossip.ApplySnapshotAction, outcome corestate.RemoteApplyOutcome) {
	if outcome.Err != nil {
		driver.logGossip("warn", "zone_apply_failed", peerID, GossipPhaseApply, outcome.Err, map[string]any{"zone": action.Snapshot.Zone, "reason": gossip.RejectReason(outcome.Err)})
		return
	}
	if outcome.ManagedZoneAdopted {
		driver.logGossip("info", "auto_join_adopted", peerID, GossipPhaseApply, nil, map[string]any{"zone": managedZone})
	}
	if outcome.AuthorityRefreshed {
		driver.logGossip("info", "managed_zone_authority_refreshed", peerID, GossipPhaseApply, nil, map[string]any{"zone": managedZone})
	}
	if outcome.Result == nil || (!outcome.Result.NetworkChanged && !outcome.ManagedZoneAdopted && !outcome.AuthorityRefreshed) {
		return
	}
	via := action.Via
	if via == "" {
		via = "event_loop"
	}
	driver.logGossip("info", "zone_applied", peerID, GossipPhaseApply, nil, map[string]any{
		"zone": action.Snapshot.Zone, "records": outcome.Result.Records, "delegations": outcome.Result.Delegation, "via": via,
	})
}
