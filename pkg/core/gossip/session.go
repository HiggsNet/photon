// Package gossip contains the platform-neutral per-peer Photon gossip sync
// state machine. Linux and leaf clients execute its returned actions through
// their own persistence, timer and transport adapters.
package gossip

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

// SyncSessionState is the state of a per-peer sync FSM.
type SyncSessionState string

// ErrPingTimeout identifies a round that expired while awaiting the peer's summary.
var ErrPingTimeout = errors.New("ping timeout")

const (
	SyncSessionIdle           SyncSessionState = "idle"
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
	TimerKindChunkPrefix  = "chunk:"

	kCatalogPageTimeoutMultiplier = 3
	kRoundMultiplier              = 5
)

// Bound one peer's work. A slot remains occupied until validation/apply or
// chunk fallback finishes.
const maxSessionObjectPulls = 2

// SyncEvent advances one per-peer SyncSession. GossipDriver owns delivery;
// platform composition does not dispatch these concrete event types.
type SyncEvent interface {
	SyncEventMarker()
}

type SyncTimerEvent struct {
	PeerID       string
	LocalSummary *corestate.CatalogSummary
	// RemoteSummary starts a session from an inbound PING without sending another PING.
	RemoteSummary  *corestate.CatalogSummary
	DatagramBudget int
}

func (*SyncTimerEvent) SyncEventMarker() {}

type PongReceivedEvent struct {
	PeerID string
	Pong   *Pong
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
	// Only a transport reachability failure justifies another bulk transfer
	// over UDP. Local capacity and invalid responses use normal session backoff.
	Unreachable bool
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
	PeerID       string
	Zone         zone.ZonePath
	Err          error
	LocalEntries []corestate.ZoneDigest
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
	PeerID                string
	Snapshot              *corestate.ZoneSnapshot
	ExpectedRoot          []byte
	Via                   string // diagnostic source; execution and transaction semantics are shared
	RefreshOnRootMismatch bool   // first mismatch requests a fresh catalog before rejection
}

func (ApplySnapshotAction) isSyncAction() {}

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

type zoneStage uint8

const (
	zoneQueued zoneStage = iota + 1
	zoneWaitingTCP
	zoneWaitingUDP
	zoneWaitingApply
)

type pendingZone struct {
	expectedRoot []byte
	stage        zoneStage
}

// SyncSession is a per-peer sync state machine. It does not perform I/O;
// all side effects are returned as SyncAction values.
type SyncSession struct {
	PeerID string
	State  SyncSessionState

	pendingZones      map[zone.ZonePath]pendingZone
	localCatalogRoot  []byte
	remoteCatalogRoot []byte
	lastCatalogCursor string
	// For a fixed root, each accepted page has a distinct next cursor.
	acceptedCatalogPages map[string]bool
	// A page with a different root superseded this catalog. Late pages
	// from it must not seed or advance the refresh.
	supersededCatalogRoot []byte
	// A catalog and its objects are separate reads. Refresh once after drift,
	// draining outstanding work before reusing the per-zone result slots.
	catalogRefreshPending bool
	catalogRefreshed      bool

	// RTT estimation.
	estimatedRTT   time.Duration
	pingSentAt     time.Time
	datagramBudget int

	lastError error
}

// NewSyncSession creates a new sync session for peerID.
func NewSyncSession(peerID string) *SyncSession {
	return &SyncSession{
		PeerID:       peerID,
		State:        SyncSessionIdle,
		pendingZones: make(map[zone.ZonePath]pendingZone),
		estimatedRTT: InitialRTT,
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
		return s.onObjectPullResult(e, now)
	case *ObjectChunkEvent:
		return s.onObjectChunk(e)
	case *SnapshotAppliedEvent:
		return s.onSnapshotApplied(e, now)
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
	s.datagramBudget = e.DatagramBudget
	if s.datagramBudget <= 0 {
		s.datagramBudget = DefaultDatagramBudget
	}
	s.pendingZones = make(map[zone.ZonePath]pendingZone)
	s.localCatalogRoot = nil
	if e.LocalSummary != nil {
		s.localCatalogRoot = append([]byte(nil), e.LocalSummary.CatalogRoot...)
	}
	s.remoteCatalogRoot = nil
	s.lastCatalogCursor = ""
	s.catalogRefreshPending = false
	s.catalogRefreshed = false

	var actions []SyncAction
	if e.RemoteSummary != nil {
		actions = s.handleCatalogSummary(e.PeerID, e.RemoteSummary, now)
	} else {
		actions = append(actions, SendPingAction{PeerID: e.PeerID, Summary: e.LocalSummary})
	}
	return append(actions, StartTimerAction{PeerID: e.PeerID, Kind: TimerKindRound, Deadline: now.Add(s.roundTimeout())}), nil
}

func (s *SyncSession) onPongReceived(e *PongReceivedEvent, now time.Time) ([]SyncAction, error) {
	if s.State != SyncSessionSummarySent || e.Pong == nil || e.Pong.Summary == nil || len(e.Pong.Summary.CatalogRoot) == 0 {
		return nil, nil
	}
	if !s.pingSentAt.IsZero() && now.After(s.pingSentAt) {
		s.updateRTT(now.Sub(s.pingSentAt))
	}
	return s.handleCatalogSummary(e.PeerID, e.Pong.Summary, now), nil
}

func (s *SyncSession) onCatalogSummaryReceived(e *CatalogSummaryReceivedEvent, now time.Time) ([]SyncAction, error) {
	if e.Summary == nil {
		return nil, nil
	}
	return s.handleCatalogSummary(e.PeerID, e.Summary, now), nil
}

func (s *SyncSession) handleCatalogSummary(peerID string, summary *corestate.CatalogSummary, now time.Time) []SyncAction {
	if summary == nil {
		return nil
	}
	// Keep the catalog pinned until its pages and objects are processed.
	// A mismatching page or snapshot can still trigger the bounded refresh.
	if s.State == SyncSessionCatalogDiffing || len(s.acceptedCatalogPages) > 0 {
		return nil
	}
	if bytes.Equal(summary.CatalogRoot, s.remoteCatalogRoot) && s.State == SyncSessionCompleted {
		return nil
	}
	s.remoteCatalogRoot = append([]byte(nil), summary.CatalogRoot...)
	if len(s.localCatalogRoot) > 0 && bytes.Equal(summary.CatalogRoot, s.localCatalogRoot) {
		s.State = SyncSessionCompleted
		return nil
	}
	if summary.ZoneCount == 0 || bytes.Equal(summary.CatalogRoot, corestate.CatalogRoot(nil)) {
		s.State = SyncSessionCompleted
		return nil
	}
	s.State = SyncSessionCatalogDiffing
	s.lastCatalogCursor = ""
	return []SyncAction{
		SendFetchCatalogPageAction{PeerID: peerID},
		StartTimerAction{PeerID: peerID, Kind: TimerKindCatalogPage, Deadline: now.Add(s.catalogPageTimeout())},
	}
}

func (s *SyncSession) onCatalogPageReceived(e *CatalogPageReceivedEvent, now time.Time) ([]SyncAction, error) {
	if e.Page == nil {
		return nil, nil
	}
	if len(s.supersededCatalogRoot) > 0 && bytes.Equal(e.Page.CatalogRoot, s.supersededCatalogRoot) {
		return nil, nil
	}
	if s.acceptedCatalogPages[""] || (bytes.Equal(e.Page.CatalogRoot, s.remoteCatalogRoot) && s.acceptedCatalogPages[e.Page.NextCursor]) {
		return nil, nil
	}
	if len(s.remoteCatalogRoot) > 0 && !bytes.Equal(e.Page.CatalogRoot, s.remoteCatalogRoot) {
		if !s.catalogRefreshed {
			s.supersededCatalogRoot = s.remoteCatalogRoot
			s.catalogRefreshPending = true
			s.lastCatalogCursor = ""
			s.State = SyncSessionObjectPulling
			return s.refreshCatalog(e.PeerID, now), nil
		}
		s.State = SyncSessionFailed
		s.lastError = errors.New("catalog page root mismatch")
		return nil, nil
	}
	if len(s.remoteCatalogRoot) == 0 {
		s.remoteCatalogRoot = append([]byte(nil), e.Page.CatalogRoot...)
	}
	if s.acceptedCatalogPages == nil {
		s.acceptedCatalogPages = make(map[string]bool)
	}
	s.acceptedCatalogPages[e.Page.NextCursor] = true
	s.State = SyncSessionCatalogDiffing
	var actions []SyncAction
	for _, diff := range corestate.CatalogDiff(e.LocalEntries, e.Page.Entries) {
		work := s.pendingZones[diff.Zone]
		if work.stage == 0 {
			work.stage = zoneQueued
		}
		work.expectedRoot = diff.RootHash
		s.pendingZones[diff.Zone] = work
	}
	s.lastCatalogCursor = e.Page.NextCursor
	if e.Page.NextCursor != "" {
		actions = append(actions, SendFetchCatalogPageAction{PeerID: e.PeerID, Cursor: e.Page.NextCursor})
		actions = append(actions, StartTimerAction{PeerID: e.PeerID, Kind: TimerKindCatalogPage, Deadline: now.Add(s.catalogPageTimeout())})
		actions = append(actions, StartTimerAction{PeerID: e.PeerID, Kind: TimerKindRound, Deadline: now.Add(s.roundTimeout())})
		return actions, nil
	}
	if refresh := s.refreshCatalog(e.PeerID, now); refresh != nil {
		return append(actions, refresh...), nil
	}
	// A parent may be on a later page than its children. Do not start any
	// object until the complete catalog can be ordered by ancestry.
	s.pruneSatisfiedPending(e.LocalEntries)
	actions = append(actions, s.startPendingPulls(e.PeerID)...)
	if len(s.pendingZones) == 0 {
		s.State = SyncSessionCompleted
		return actions, nil
	}
	s.State = SyncSessionObjectPulling
	// Size the finite round budget for every pending object, including a
	// sequential ancestor chain. Each TCP exchange and UDP fallback has its
	// own shorter deadline; a successful wave does not restart this clock.
	budget := s.roundTimeout()
	for path := range s.pendingZones {
		budget += ObjectPullBudget + s.chunkTimeout(path)
	}
	actions = append(actions, CancelTimerAction{PeerID: e.PeerID, Kind: TimerKindCatalogPage},
		StartTimerAction{PeerID: e.PeerID, Kind: TimerKindRound, Deadline: now.Add(budget)})
	return actions, nil
}

func (s *SyncSession) onCatalogPageTimeout(e *CatalogPageTimeoutEvent) ([]SyncAction, error) {
	if s.State != SyncSessionCatalogDiffing {
		return nil, nil
	}
	s.State = SyncSessionFailed
	s.lastError = errors.New("catalog page timeout")
	return nil, nil
}

// pruneSatisfiedPending drops queued work already satisfied by a committed
// copy. In-flight zones keep their slots until their own results arrive.
func (s *SyncSession) pruneSatisfiedPending(digests []corestate.ZoneDigest) {
	for _, local := range digests {
		path := local.Zone
		if work := s.pendingZones[path]; work.stage == zoneQueued && bytes.Equal(work.expectedRoot, local.RootHash) {
			delete(s.pendingZones, path)
		}
	}
}

// startPendingPulls schedules only the shallowest pending layer. A downloaded
// parent is still pending until its verified apply acknowledgement, so children
// cannot race the installation of their authority. All stages past queued
// occupy one of the bounded transport/apply slots.
func (s *SyncSession) startPendingPulls(peerID string) []SyncAction {
	if s.Done() || s.lastCatalogCursor != "" || s.catalogRefreshPending || len(s.pendingZones) == 0 {
		return nil
	}
	depth := func(path zone.ZonePath) int {
		if path.IsRoot() {
			return 0
		}
		return strings.Count(path.String(), ".")
	}
	minimum := int(^uint(0) >> 1)
	available := maxSessionObjectPulls
	for path, work := range s.pendingZones {
		minimum = min(minimum, depth(path))
		if work.stage != zoneQueued {
			available--
		}
	}
	if available <= 0 {
		return nil
	}
	var queued []zone.ZonePath
	for path, work := range s.pendingZones {
		if work.stage == zoneQueued && depth(path) == minimum {
			queued = append(queued, path)
		}
	}
	sort.Slice(queued, func(i, j int) bool { return queued[i] < queued[j] })
	var actions []SyncAction
	for _, path := range queued {
		if available <= 0 {
			break
		}
		work := s.pendingZones[path]
		work.stage = zoneWaitingTCP
		s.pendingZones[path] = work
		available--
		actions = append(actions, StartObjectPullAction{PeerID: peerID, Zone: path})
	}
	if len(actions) > 0 {
		s.State = SyncSessionObjectPulling
	}
	return actions
}

func (s *SyncSession) onRoundTimeout(e *RoundTimeoutEvent) ([]SyncAction, error) {
	if s.State == SyncSessionCompleted || s.State == SyncSessionFailed || s.State == SyncSessionIdle {
		return nil, nil
	}
	if s.State == SyncSessionSummarySent {
		s.lastError = ErrPingTimeout
	} else {
		s.lastError = errors.New("round timeout")
	}
	s.State = SyncSessionFailed
	return []SyncAction{
		CancelTimerAction{PeerID: e.PeerID, Kind: TimerKindCatalogPage},
	}, nil
}

func (s *SyncSession) onObjectPullResult(e *ObjectPullResultEvent, now time.Time) ([]SyncAction, error) {
	work := s.pendingZones[e.Zone]
	if work.stage != zoneWaitingTCP {
		return nil, nil
	}

	work.stage = zoneQueued
	var actions []SyncAction
	switch {
	case e.Err != nil:
		if e.Unreachable {
			work.stage = zoneWaitingUDP
			actions = append(actions, SendChunkFallbackAction{PeerID: e.PeerID, Zone: e.Zone})
			actions = append(actions, StartTimerAction{PeerID: e.PeerID, Kind: TimerKindChunkPrefix + e.Zone.String(), Deadline: now.Add(s.chunkTimeout(e.Zone))})
		} else {
			s.Fail(e.Err)
		}
	case e.Snapshot != nil && e.Snapshot.Zone != e.Zone:
		s.Fail(fmt.Errorf("object pull zone mismatch: requested %s, received %s", e.Zone, e.Snapshot.Zone))
	case e.Snapshot != nil:
		work.stage = zoneWaitingApply
		actions = append(actions, s.snapshotApplyAction(e.PeerID, e.Snapshot, work.expectedRoot, "object_pull"))
	}
	s.pendingZones[e.Zone] = work
	if s.Done() {
		return actions, nil
	}

	// Don't change state until all concurrent object pulls have reported back.
	counts := s.zoneStageCounts()
	if counts[zoneWaitingTCP] > 0 {
		return actions, nil
	}
	if refresh := s.refreshCatalog(e.PeerID, now); refresh != nil {
		return append(actions, refresh...), nil
	}

	// If any zone failed over to UDP chunk fallback, stay in that state so
	// onObjectChunk can process the response. Otherwise complete if nothing is
	// left to fetch; a remaining pending zone without inflight work is a hard
	// error.
	if counts[zoneWaitingUDP] > 0 {
		s.State = SyncSessionChunkFallback
	} else if counts[zoneWaitingApply] > 0 {
		s.State = SyncSessionObjectPulling
	} else if s.lastCatalogCursor != "" {
		s.State = SyncSessionCatalogDiffing
	} else if len(s.pendingZones) == 0 {
		s.State = SyncSessionCompleted
	} else {
		s.State = SyncSessionFailed
		s.lastError = errors.New("sync has pending zones after object pull without fallback")
	}
	return actions, nil
}

func (s *SyncSession) onObjectChunk(e *ObjectChunkEvent) ([]SyncAction, error) {
	work := s.pendingZones[e.Zone]
	if work.stage != zoneWaitingUDP {
		return nil, nil
	}
	if e.Err != nil {
		s.Fail(e.Err)
		return nil, nil
	}
	if e.Snapshot == nil {
		return nil, nil
	}
	if e.Snapshot.Zone != e.Zone {
		s.Fail(fmt.Errorf("chunk snapshot zone mismatch: requested %s, received %s", e.Zone, e.Snapshot.Zone))
		return nil, nil
	}
	work.stage = zoneWaitingApply
	s.pendingZones[e.Zone] = work
	return []SyncAction{s.snapshotApplyAction(e.PeerID, e.Snapshot, work.expectedRoot, "udp_chunks"),
		CancelTimerAction{PeerID: e.PeerID, Kind: TimerKindChunkPrefix + e.Zone.String()}}, nil
}

func (s *SyncSession) snapshotApplyAction(peerID string, snapshot *corestate.ZoneSnapshot, expectedRoot []byte, via string) ApplySnapshotAction {
	return ApplySnapshotAction{
		PeerID:                peerID,
		Snapshot:              snapshot,
		ExpectedRoot:          bytes.Clone(expectedRoot),
		Via:                   via,
		RefreshOnRootMismatch: !s.catalogRefreshed,
	}
}

func (s *SyncSession) onSnapshotApplied(e *SnapshotAppliedEvent, now time.Time) ([]SyncAction, error) {
	work := s.pendingZones[e.Zone]
	if work.stage != zoneWaitingApply {
		return nil, nil
	}
	if e.Err != nil {
		work.stage = zoneQueued
		s.pendingZones[e.Zone] = work
		if s.catalogRefreshed || !errors.Is(e.Err, corestate.ErrSnapshotRootMismatch) {
			s.Fail(e.Err)
			return nil, nil
		}
		s.catalogRefreshPending = true
	} else {
		delete(s.pendingZones, e.Zone)
	}
	if refresh := s.refreshCatalog(e.PeerID, now); refresh != nil {
		return refresh, nil
	}
	s.pruneSatisfiedPending(e.LocalEntries)
	actions := s.startPendingPulls(e.PeerID)
	counts := s.zoneStageCounts()
	if counts[zoneWaitingTCP] > 0 || counts[zoneWaitingApply] > 0 {
		s.State = SyncSessionObjectPulling
		return actions, nil
	}
	if counts[zoneWaitingUDP] > 0 {
		s.State = SyncSessionChunkFallback
		return actions, nil
	}
	if s.lastCatalogCursor != "" {
		s.State = SyncSessionCatalogDiffing
		return actions, nil
	}
	if len(s.pendingZones) == 0 {
		s.State = SyncSessionCompleted
		return actions, nil
	}
	s.Fail(errors.New("sync has pending zones without transport or apply work"))
	return nil, nil
}

func (s *SyncSession) refreshCatalog(peerID string, now time.Time) []SyncAction {
	if !s.catalogRefreshPending || s.lastCatalogCursor != "" || s.zoneStageCounts()[zoneQueued] != len(s.pendingZones) {
		return nil
	}
	s.catalogRefreshPending = false
	s.catalogRefreshed = true
	clear(s.pendingZones)
	s.remoteCatalogRoot = nil
	s.lastCatalogCursor = ""
	s.acceptedCatalogPages = nil
	s.State = SyncSessionCatalogDiffing
	// Only one catalog refresh is allowed. It gets the control-message budget;
	// the complete replacement catalog determines the next finite object budget.
	return []SyncAction{
		SendFetchCatalogPageAction{PeerID: peerID},
		StartTimerAction{PeerID: peerID, Kind: TimerKindCatalogPage, Deadline: now.Add(s.catalogPageTimeout())},
		StartTimerAction{PeerID: peerID, Kind: TimerKindRound, Deadline: now.Add(s.roundTimeout())},
	}
}

// Done returns true when the session has reached a terminal state.
func (s *SyncSession) Done() bool {
	return s.State == SyncSessionCompleted || s.State == SyncSessionFailed
}

// ExpectsUDPZone allows the host to reject unsolicited and late chunks before
// allocating assembly state or scheduling repair.
func (s *SyncSession) ExpectsUDPZone(path zone.ZonePath) bool {
	return !s.Done() && s.pendingZones[path].stage == zoneWaitingUDP
}

func (s *SyncSession) chunkTimeout(path zone.ZonePath) time.Duration {
	budget := s.datagramBudget
	if budget <= 0 {
		budget = DefaultDatagramBudget
	}
	payload := MaxObjectChunkDataSize(budget, s.PeerID, path)
	if payload <= 0 {
		return ChunkTransferTTL
	}
	chunks := int64((MaxChunkObjectBytes + payload - 1) / payload)
	return (QuotaConfig{}).TransferBudget(chunks*int64(budget), chunks)
}

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

// InflightCount reports outstanding object-pull operations.
func (s *SyncSession) InflightCount() int {
	return s.zoneStageCounts()[zoneWaitingTCP]
}

func (s *SyncSession) zoneStageCounts() [zoneWaitingApply + 1]int {
	var counts [zoneWaitingApply + 1]int
	for _, work := range s.pendingZones {
		counts[work.stage]++
	}
	return counts
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
		return
	}
	s.estimatedRTT = (7*s.estimatedRTT + sample) / 8
}
