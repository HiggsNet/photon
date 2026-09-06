// Package gossip contains the platform-neutral per-peer Photon gossip sync
// state machine. Linux and leaf clients execute its returned actions through
// their own persistence, timer and transport adapters.
package gossip

import (
	"bytes"
	"errors"
	"fmt"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// SyncSessionState is the state of a per-peer sync FSM.
type SyncSessionState string

const (
	SyncSessionIdle           SyncSessionState = "idle"
	SyncSessionPingSent       SyncSessionState = "ping_sent"
	SyncSessionSummarySent    SyncSessionState = "summary_sent"
	SyncSessionCatalogDiffing SyncSessionState = "catalog_diffing"
	SyncSessionObjectPulling  SyncSessionState = "object_pulling"
	SyncSessionChunkFallback  SyncSessionState = "chunk_fallback"
	SyncSessionCompleted      SyncSessionState = "completed"
	SyncSessionFailed         SyncSessionState = "failed"
)

// RTT-aware timeout defaults. These match docs/new/md and docs/new/daemon.md.
const (
	MinCatalogPageTimeout = 250 * time.Millisecond
	MinRoundTimeout       = 5 * time.Second
	ObjectPullBudget      = 5 * time.Second
	InitialRTT            = 1 * time.Second
	TimerKindRound        = "round"
	TimerKindCatalogPage  = "catalog_page"

	kCatalogPageTimeoutMultiplier = 3
	kRoundMultiplier              = 5
)

// SyncEvent advances one per-peer SyncSession. GossipDriver owns delivery;
// platform composition does not dispatch these concrete event types.
type SyncEvent interface {
	SyncEventMarker()
}

type SyncTimerEvent struct {
	PeerID       string
	LocalSummary *corestate.CatalogSummary
}

func (*SyncTimerEvent) SyncEventMarker() {}

type PongReceivedEvent struct {
	PeerID       string
	Pong         *Pong
	MissingZones []zone.ZonePath // populated by the event loop before OnEvent
}

func (*PongReceivedEvent) SyncEventMarker() {}

type CatalogSummaryReceivedEvent struct {
	PeerID  string
	Summary *corestate.CatalogSummary
}

func (*CatalogSummaryReceivedEvent) SyncEventMarker() {}

type CatalogPageReceivedEvent struct {
	PeerID       string
	Page         *corestate.CatalogPage
	LocalEntries []corestate.ZoneDigest
}

func (*CatalogPageReceivedEvent) SyncEventMarker() {}

type CatalogPageTimeoutEvent struct {
	PeerID string
}

func (*CatalogPageTimeoutEvent) SyncEventMarker() {}

// ChunkRepairTimeoutEvent is produced by GossipDriver's scheduler. It is a
// protocol runtime event handled before SyncSession FSM advancement.
type ChunkRepairTimeoutEvent struct {
	PeerID     string
	TransferID []byte
}

func (*ChunkRepairTimeoutEvent) SyncEventMarker() {}

type RoundTimeoutEvent struct {
	PeerID string
}

func (*RoundTimeoutEvent) SyncEventMarker() {}

type ObjectPullResultEvent struct {
	PeerID   string
	Zone     zone.ZonePath
	Snapshot *corestate.ZoneSnapshot
	Err      error
}

func (*ObjectPullResultEvent) SyncEventMarker() {}

type ObjectChunkEvent struct {
	PeerID   string
	Zone     zone.ZonePath
	Snapshot *corestate.ZoneSnapshot
	Err      error
}

func (*ObjectChunkEvent) SyncEventMarker() {}

// SnapshotAppliedEvent is the runtime's acknowledgement for a previously
// emitted ApplySnapshotAction. The action's ExpectedRoot binds the fetched
// snapshot itself; a successful merge may retain newer local objects and
// therefore need not produce that exact root locally.
type SnapshotAppliedEvent struct {
	PeerID string
	Zone   zone.ZonePath
	Err    error
}

func (*SnapshotAppliedEvent) SyncEventMarker() {}

// SyncAction is an action returned by SyncSession.OnEvent for the event loop to execute.
type SyncAction interface {
	isSyncAction()
}

type SendPingAction struct {
	PeerID  string
	Summary *corestate.CatalogSummary
}

func (SendPingAction) isSyncAction() {}

type SendChunkFallbackAction struct {
	PeerID string
	Zone   zone.ZonePath
}

func (SendChunkFallbackAction) isSyncAction() {}

type SendFetchCatalogPageAction struct {
	PeerID string
	Cursor string
}

func (SendFetchCatalogPageAction) isSyncAction() {}

type StartObjectPullAction struct {
	PeerID string
	Zone   zone.ZonePath
}

func (StartObjectPullAction) isSyncAction() {}

type ApplySnapshotAction struct {
	PeerID        string
	Snapshot      *corestate.ZoneSnapshot
	ExpectedRoot  []byte
	ReportResult  bool
	RelaxedLimits bool   // set for object-pull / chunk-fallback snapshots
	Via           string // diagnostic source; execution and transaction semantics are shared
}

func (ApplySnapshotAction) isSyncAction() {}

type RecordBackoffAction struct {
	PeerID string
	Err    error
}

func (RecordBackoffAction) isSyncAction() {}

type StartTimerAction struct {
	PeerID   string
	Kind     string
	Deadline time.Time
}

func (StartTimerAction) isSyncAction() {}

type CancelTimerAction struct {
	PeerID string
	Kind   string
}

func (CancelTimerAction) isSyncAction() {}

// SyncSession is a per-peer sync state machine. It does not perform I/O;
// all side effects are returned as SyncAction values.
type SyncSession struct {
	PeerID string
	State  SyncSessionState

	// pendingZones are zones we believe the peer has and we need.
	pendingZones map[zone.ZonePath]bool
	// objectPullInflight tracks zones with an outstanding async TCP pull.
	objectPullInflight map[zone.ZonePath]bool
	// snapshotApplyPending tracks snapshots handed to the runtime whose apply
	// outcome has not yet been delivered back to the FSM.
	snapshotApplyPending map[zone.ZonePath]bool
	// chunkFallbackZones tracks zones we are trying to receive via UDP chunk.
	chunkFallbackZones map[zone.ZonePath]bool
	// expectedDigests maps pending zones to the remote root hash advertised in
	// the PONG. Used to detect stale or incomplete UDP announces.
	expectedDigests   map[zone.ZonePath]corestate.ZoneDigest
	localCatalogRoot  []byte
	remoteCatalogRoot []byte
	lastCatalogCursor string

	// RTT estimation.
	estimatedRTT time.Duration
	rttVariance  time.Duration
	pingSentAt   time.Time

	lastError error
	// networkChanged accumulates runtime-confirmed Network changes across the
	// multi-event session so completion can save/notify/relay exactly once.
	networkChanged bool
}

// NewSyncSession creates a new sync session for peerID.
func NewSyncSession(peerID string) *SyncSession {
	return &SyncSession{
		PeerID:               peerID,
		State:                SyncSessionIdle,
		pendingZones:         make(map[zone.ZonePath]bool),
		objectPullInflight:   make(map[zone.ZonePath]bool),
		snapshotApplyPending: make(map[zone.ZonePath]bool),
		chunkFallbackZones:   make(map[zone.ZonePath]bool),
		expectedDigests:      make(map[zone.ZonePath]corestate.ZoneDigest),
		estimatedRTT:         InitialRTT,
	}
}

// OnEvent advances the state machine and returns actions for the event loop.
func (s *SyncSession) OnEvent(event SyncEvent, now time.Time) ([]SyncAction, error) {
	switch e := event.(type) {
	case *SyncTimerEvent:
		return s.onSyncTimer(e, now)
	case *PongReceivedEvent:
		return s.onPongReceived(e, now)
	case *CatalogSummaryReceivedEvent:
		return s.onCatalogSummaryReceived(e, now)
	case *CatalogPageReceivedEvent:
		return s.onCatalogPageReceived(e, now)
	case *CatalogPageTimeoutEvent:
		return s.onCatalogPageTimeout(e)
	case *RoundTimeoutEvent:
		return s.onRoundTimeout(e)
	case *ObjectPullResultEvent:
		return s.onObjectPullResult(e)
	case *ObjectChunkEvent:
		return s.onObjectChunk(e)
	case *SnapshotAppliedEvent:
		return s.onSnapshotApplied(e)
	default:
		return nil, fmt.Errorf("unknown sync event type %T", event)
	}
}

func (s *SyncSession) onSyncTimer(e *SyncTimerEvent, now time.Time) ([]SyncAction, error) {
	if s.State != SyncSessionIdle {
		return nil, nil
	}
	s.State = SyncSessionSummarySent
	s.pingSentAt = now
	s.pendingZones = make(map[zone.ZonePath]bool)
	s.objectPullInflight = make(map[zone.ZonePath]bool)
	s.snapshotApplyPending = make(map[zone.ZonePath]bool)
	s.chunkFallbackZones = make(map[zone.ZonePath]bool)
	s.expectedDigests = make(map[zone.ZonePath]corestate.ZoneDigest)
	s.localCatalogRoot = nil
	if e.LocalSummary != nil {
		s.localCatalogRoot = append([]byte(nil), e.LocalSummary.CatalogRoot...)
	}
	s.remoteCatalogRoot = nil
	s.lastCatalogCursor = ""
	s.networkChanged = false

	return []SyncAction{
		SendPingAction{PeerID: e.PeerID, Summary: e.LocalSummary},
		StartTimerAction{PeerID: e.PeerID, Kind: TimerKindRound, Deadline: now.Add(s.roundTimeout())},
	}, nil
}

func (s *SyncSession) onPongReceived(e *PongReceivedEvent, now time.Time) ([]SyncAction, error) {
	if s.State != SyncSessionPingSent && s.State != SyncSessionSummarySent {
		return nil, nil
	}
	if !s.pingSentAt.IsZero() && now.After(s.pingSentAt) {
		s.updateRTT(now.Sub(s.pingSentAt))
	}
	if e.Pong != nil && e.Pong.Summary != nil {
		return s.handleCatalogSummary(e.PeerID, e.Pong.Summary, now)
	}

	var actions []SyncAction

	// We need zones from peer.
	if len(e.MissingZones) > 0 {
		s.State = SyncSessionObjectPulling
		for _, z := range e.MissingZones {
			s.pendingZones[z] = true
			if !s.objectPullInflight[z] {
				s.objectPullInflight[z] = true
				actions = append(actions, StartObjectPullAction{PeerID: e.PeerID, Zone: z})
			}
		}
		return actions, nil
	}

	if len(actions) == 0 {
		s.State = SyncSessionCompleted
	}
	return actions, nil
}

func (s *SyncSession) onCatalogSummaryReceived(e *CatalogSummaryReceivedEvent, now time.Time) ([]SyncAction, error) {
	if e.Summary == nil {
		return nil, nil
	}
	return s.handleCatalogSummary(e.PeerID, e.Summary, now)
}

func (s *SyncSession) handleCatalogSummary(peerID string, summary *corestate.CatalogSummary, now time.Time) ([]SyncAction, error) {
	if summary == nil {
		return nil, nil
	}
	if bytes.Equal(summary.CatalogRoot, s.remoteCatalogRoot) && s.State == SyncSessionCompleted {
		return nil, nil
	}
	s.remoteCatalogRoot = append([]byte(nil), summary.CatalogRoot...)
	if len(s.localCatalogRoot) > 0 && bytes.Equal(summary.CatalogRoot, s.localCatalogRoot) {
		s.State = SyncSessionCompleted
		return nil, nil
	}
	if summary.ZoneCount == 0 || bytes.Equal(summary.CatalogRoot, corestate.CatalogRoot(nil)) {
		s.State = SyncSessionCompleted
		return nil, nil
	}
	if summary.FirstPage != nil {
		return s.onCatalogPageReceived(&CatalogPageReceivedEvent{PeerID: peerID, Page: summary.FirstPage}, now)
	}
	s.State = SyncSessionCatalogDiffing
	s.lastCatalogCursor = ""
	return []SyncAction{
		SendFetchCatalogPageAction{PeerID: peerID},
		StartTimerAction{PeerID: peerID, Kind: TimerKindCatalogPage, Deadline: now.Add(s.catalogPageTimeout())},
	}, nil
}

func (s *SyncSession) onCatalogPageReceived(e *CatalogPageReceivedEvent, now time.Time) ([]SyncAction, error) {
	if e.Page == nil {
		return nil, nil
	}
	if len(s.remoteCatalogRoot) > 0 && !bytes.Equal(e.Page.CatalogRoot, s.remoteCatalogRoot) {
		s.State = SyncSessionFailed
		s.lastError = errors.New("catalog page root mismatch")
		return []SyncAction{
			RecordBackoffAction{PeerID: e.PeerID, Err: s.lastError},
		}, nil
	}
	if len(s.remoteCatalogRoot) == 0 {
		s.remoteCatalogRoot = append([]byte(nil), e.Page.CatalogRoot...)
	}
	s.State = SyncSessionCatalogDiffing
	var actions []SyncAction
	for _, diff := range corestate.CatalogDiff(e.LocalEntries, e.Page.Entries) {
		s.pendingZones[diff.Zone] = true
		s.expectedDigests[diff.Zone] = diff
		if !s.objectPullInflight[diff.Zone] {
			s.objectPullInflight[diff.Zone] = true
			actions = append(actions, StartObjectPullAction{PeerID: e.PeerID, Zone: diff.Zone})
		}
	}
	s.lastCatalogCursor = e.Page.NextCursor
	if e.Page.NextCursor != "" {
		actions = append(actions, SendFetchCatalogPageAction{PeerID: e.PeerID, Cursor: e.Page.NextCursor})
		actions = append(actions, StartTimerAction{PeerID: e.PeerID, Kind: TimerKindCatalogPage, Deadline: now.Add(s.catalogPageTimeout())})
		return actions, nil
	}
	if len(s.objectPullInflight) > 0 {
		s.State = SyncSessionObjectPulling
		return actions, nil
	}
	if s.pendingEmpty() {
		s.State = SyncSessionCompleted
		return actions, nil
	}
	s.State = SyncSessionObjectPulling
	return actions, nil
}

func (s *SyncSession) onCatalogPageTimeout(e *CatalogPageTimeoutEvent) ([]SyncAction, error) {
	if s.State != SyncSessionCatalogDiffing {
		return nil, nil
	}
	s.State = SyncSessionFailed
	s.lastError = errors.New("catalog page timeout")
	return []SyncAction{
		RecordBackoffAction{PeerID: e.PeerID, Err: s.lastError},
	}, nil
}

func (s *SyncSession) reconcilePendingWithDigests(digests []corestate.ZoneDigest) []SyncAction {
	local := make(map[zone.ZonePath][]byte, len(digests))
	for _, digest := range digests {
		local[digest.Zone] = digest.RootHash
	}
	for z := range s.pendingZones {
		if s.snapshotApplyPending[z] {
			continue
		}
		expected, ok := s.expectedDigests[z]
		if !ok {
			continue
		}
		root, ok := local[z]
		if !ok {
			continue
		}
		if bytes.Equal(expected.RootHash, root) {
			delete(s.pendingZones, z)
			delete(s.expectedDigests, z)
			delete(s.objectPullInflight, z)
			delete(s.snapshotApplyPending, z)
			delete(s.chunkFallbackZones, z)
		}
	}
	if s.pendingEmpty() && (s.State == SyncSessionObjectPulling ||
		s.State == SyncSessionChunkFallback) {
		s.State = SyncSessionCompleted
		return nil
	}
	return nil
}

func (s *SyncSession) onRoundTimeout(e *RoundTimeoutEvent) ([]SyncAction, error) {
	if s.State == SyncSessionCompleted || s.State == SyncSessionFailed || s.State == SyncSessionIdle {
		return nil, nil
	}
	s.State = SyncSessionFailed
	s.lastError = errors.New("round timeout")
	return []SyncAction{
		RecordBackoffAction{PeerID: e.PeerID, Err: s.lastError},
		CancelTimerAction{PeerID: e.PeerID, Kind: TimerKindCatalogPage},
	}, nil
}

func (s *SyncSession) onObjectPullResult(e *ObjectPullResultEvent) ([]SyncAction, error) {
	// Only process results for zones that are still in flight. A zone may be
	// removed from objectPullInflight early if an announce arrived first, or if
	// a concurrent result for the same zone was already processed.
	if !s.objectPullInflight[e.Zone] {
		return nil, nil
	}
	delete(s.objectPullInflight, e.Zone)

	var actions []SyncAction

	if e.Err != nil {
		s.chunkFallbackZones[e.Zone] = true
		actions = append(actions, SendChunkFallbackAction{PeerID: e.PeerID, Zone: e.Zone})
	} else if e.Snapshot != nil {
		if e.Snapshot.Zone != e.Zone {
			return s.failSnapshotApply(e.PeerID, e.Zone, fmt.Errorf("object pull zone mismatch: requested %s, received %s", e.Zone, e.Snapshot.Zone), nil)
		}
		s.snapshotApplyPending[e.Zone] = true
		actions = append(actions, ApplySnapshotAction{
			PeerID:        e.PeerID,
			Snapshot:      e.Snapshot,
			ExpectedRoot:  s.expectedRoot(e.Zone),
			ReportResult:  true,
			RelaxedLimits: true,
			Via:           "object_pull",
		})
	}

	// Don't change state until all concurrent object pulls have reported back.
	if len(s.objectPullInflight) > 0 {
		return actions, nil
	}

	// If any zone failed over to UDP chunk fallback, stay in that state so
	// onObjectChunk can process the response. Otherwise complete if nothing is
	// left to fetch; a remaining pending zone without inflight work is a hard
	// error, not a reason to wait for ANNOUNCE payloads.
	if len(s.chunkFallbackZones) > 0 {
		s.State = SyncSessionChunkFallback
	} else if len(s.snapshotApplyPending) > 0 {
		s.State = SyncSessionObjectPulling
	} else if s.pendingEmpty() {
		s.State = SyncSessionCompleted
	} else {
		s.State = SyncSessionFailed
		s.lastError = errors.New("sync has pending zones after object pull without fallback")
		actions = append(actions,
			RecordBackoffAction{PeerID: e.PeerID, Err: s.lastError},
		)
	}
	return actions, nil
}

func (s *SyncSession) onObjectChunk(e *ObjectChunkEvent) ([]SyncAction, error) {
	if s.State != SyncSessionChunkFallback {
		return nil, nil
	}
	if e.Err != nil {
		s.State = SyncSessionFailed
		s.lastError = e.Err
		return []SyncAction{
			RecordBackoffAction{PeerID: e.PeerID, Err: e.Err},
		}, nil
	}
	if e.Snapshot != nil {
		if e.Snapshot.Zone != e.Zone {
			return s.failSnapshotApply(e.PeerID, e.Zone, fmt.Errorf("chunk snapshot zone mismatch: requested %s, received %s", e.Zone, e.Snapshot.Zone), nil)
		}
		delete(s.chunkFallbackZones, e.Zone)
		s.snapshotApplyPending[e.Zone] = true
		return []SyncAction{ApplySnapshotAction{
			PeerID:        e.PeerID,
			Snapshot:      e.Snapshot,
			ExpectedRoot:  s.expectedRoot(e.Zone),
			ReportResult:  true,
			RelaxedLimits: true,
			Via:           "udp_chunks",
		}}, nil
	}
	return nil, nil
}

func (s *SyncSession) onSnapshotApplied(e *SnapshotAppliedEvent) ([]SyncAction, error) {
	if !s.snapshotApplyPending[e.Zone] {
		return nil, nil
	}
	delete(s.snapshotApplyPending, e.Zone)
	if e.Err != nil {
		return s.failSnapshotApply(e.PeerID, e.Zone, e.Err, nil)
	}

	delete(s.pendingZones, e.Zone)
	delete(s.expectedDigests, e.Zone)
	delete(s.chunkFallbackZones, e.Zone)
	if len(s.objectPullInflight) > 0 || len(s.snapshotApplyPending) > 0 {
		s.State = SyncSessionObjectPulling
		return nil, nil
	}
	if len(s.chunkFallbackZones) > 0 {
		s.State = SyncSessionChunkFallback
		return nil, nil
	}
	if s.pendingEmpty() {
		s.State = SyncSessionCompleted
		return nil, nil
	}
	return s.failSnapshotApply(e.PeerID, e.Zone, errors.New("sync has pending zones without transport or apply work"), nil)
}

func (s *SyncSession) expectedRoot(path zone.ZonePath) []byte {
	digest, ok := s.expectedDigests[path]
	if !ok {
		return nil
	}
	return append([]byte(nil), digest.RootHash...)
}

func (s *SyncSession) failSnapshotApply(peerID string, path zone.ZonePath, err error, actions []SyncAction) ([]SyncAction, error) {
	s.State = SyncSessionFailed
	s.lastError = err
	delete(s.snapshotApplyPending, path)
	actions = append(actions,
		RecordBackoffAction{PeerID: peerID, Err: err},
	)
	return actions, nil
}

// Done returns true when the session has reached a terminal state.
func (s *SyncSession) Done() bool {
	return s.State == SyncSessionCompleted || s.State == SyncSessionFailed
}

// AccumulateNetworkChanged records that at least one applied snapshot in this
// session changed verified network state.
func (s *SyncSession) AccumulateNetworkChanged(changed bool) {
	s.networkChanged = s.networkChanged || changed
}

// NetworkChanged reports whether this session changed verified network state.
func (s *SyncSession) NetworkChanged() bool { return s.networkChanged }

// EstimatedRTT returns the current estimated RTT for this peer.
func (s *SyncSession) EstimatedRTT() time.Duration {
	if s.estimatedRTT <= 0 {
		return InitialRTT
	}
	return s.estimatedRTT
}

// LastError is the terminal error recorded by the state machine, if any.
func (s *SyncSession) LastError() error {
	return s.lastError
}

// PendingCount reports how many advertised zones still need reconciliation.
func (s *SyncSession) PendingCount() int {
	return len(s.pendingZones)
}

// PendingZones returns a detached list of zones not yet reconciled.
func (s *SyncSession) PendingZones() []zone.ZonePath {
	out := make([]zone.ZonePath, 0, len(s.pendingZones))
	for path := range s.pendingZones {
		out = append(out, path)
	}
	return out
}

// InflightCount reports outstanding object-pull operations.
func (s *SyncSession) InflightCount() int {
	return len(s.objectPullInflight)
}

// ReconcilePendingWithDigests completes pending zones whose verified local
// digest now matches the peer's advertised digest.
func (s *SyncSession) ReconcilePendingWithDigests(digests []corestate.ZoneDigest) []SyncAction {
	return s.reconcilePendingWithDigests(digests)
}

// Fail records an adapter or executor error as a terminal session failure.
func (s *SyncSession) Fail(err error) {
	s.State = SyncSessionFailed
	s.lastError = err
}

func (s *SyncSession) catalogPageTimeout() time.Duration {
	d := max(time.Duration(kCatalogPageTimeoutMultiplier)*s.EstimatedRTT(), MinCatalogPageTimeout)
	return d
}

func (s *SyncSession) roundTimeout() time.Duration {
	d := max(time.Duration(kRoundMultiplier)*s.EstimatedRTT()+ObjectPullBudget, MinRoundTimeout)
	return d
}

func (s *SyncSession) updateRTT(sample time.Duration) {
	if sample <= 0 {
		return
	}
	if s.estimatedRTT <= 0 {
		s.estimatedRTT = sample
		s.rttVariance = sample / 2
		return
	}
	s.estimatedRTT = (7*s.estimatedRTT + sample) / 8
	diff := sample - s.estimatedRTT
	if diff < 0 {
		diff = -diff
	}
	s.rttVariance = (3*s.rttVariance + diff) / 4
}

func (s *SyncSession) pendingEmpty() bool {
	for _, v := range s.pendingZones {
		if v {
			return false
		}
	}
	return true
}
