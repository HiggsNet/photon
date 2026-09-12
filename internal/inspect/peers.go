package inspect

import (
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"
	"time"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/core/gossip"
	"github.com/HiggsNet/photon/pkg/core/observability"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

type PeerSetInput struct {
	RuntimeIDs   []string
	BootstrapIDs []string
	SignedIDs    []string
	LocalIDs     []string
}

type PeerEndpointInput struct {
	BootstrapAddr  string
	Signed         []PeerSignedEndpoint
	SelectedAddr   string
	ObservedAddr   string
	ObservedSource string
	Grace          []PeerGraceEndpoint
}

type PeerSignedEndpoint struct {
	Address      string
	Port         uint16
	Protocol     string
	Scope        string
	Source       string
	Priority     int
	LastObserved int64
}

type PeerGraceEndpoint struct {
	Addr string
}

type PeerEndpointView struct {
	Addr         string `json:"addr"`
	Address      string `json:"address,omitempty"`
	Port         uint16 `json:"port,omitempty"`
	Protocol     string `json:"protocol,omitempty"`
	Scope        string `json:"scope,omitempty"`
	Source       string `json:"source,omitempty"`
	Priority     int    `json:"priority,omitempty"`
	LastObserved int64  `json:"last_observed,omitempty"`
	Selected     bool   `json:"selected,omitempty"`
}

// PeersView is the canonical detailed peer projection. It intentionally keeps
// restartable gossip checkpoint fields separate from live observability while
// presenting one stable read model to transports.
type PeersView struct {
	Peers []PeerView `json:"peers"`
}

type PeerView struct {
	PeerID         string             `json:"peer_id"`
	Source         string             `json:"source,omitempty"`
	ConfiguredAddr string             `json:"configured_addr,omitempty"`
	Endpoints      []PeerEndpointView `json:"endpoints,omitempty"`
	PeerRuntimeView
}

type PeerRuntimeView struct {
	LastSyncUnix          int64                                     `json:"last_sync_unix"`
	LastAttemptUnix       int64                                     `json:"last_attempt_unix"`
	BackoffUntilUnix      int64                                     `json:"backoff_until_unix"`
	LastRelayUnix         int64                                     `json:"last_relay_unix,omitempty"`
	FailureCount          int                                       `json:"failure_count"`
	LastError             string                                    `json:"last_error,omitempty"`
	LastUpdateSource      string                                    `json:"last_update_source,omitempty"`
	LastRelaySuppression  string                                    `json:"last_relay_suppression,omitempty"`
	LastRelaySuppressedAt int64                                     `json:"last_relay_suppressed_at,omitempty"`
	DiscoveredAddr        string                                    `json:"discovered_addr,omitempty"`
	DiscoveredAtUnix      int64                                     `json:"discovered_at_unix,omitempty"`
	ObservedAddr          string                                    `json:"observed_addr,omitempty"`
	ObservedFirstSeenUnix int64                                     `json:"observed_first_seen_unix,omitempty"`
	ObservedLastSeenUnix  int64                                     `json:"observed_last_seen_unix,omitempty"`
	ObservedLastSyncUnix  int64                                     `json:"observed_last_sync_unix,omitempty"`
	ObservedUntilUnix     int64                                     `json:"observed_until_unix,omitempty"`
	ObservedSource        string                                    `json:"observed_source,omitempty"`
	ObservedFailureCount  int                                       `json:"observed_failure_count,omitempty"`
	ObservedGraceAddrs    []photonstate.PeerObservedGraceAddrState  `json:"observed_grace_addrs,omitempty"`
	ActivePullState       string                                    `json:"active_pull_state,omitempty"`
	ActivePullLastEvent   string                                    `json:"active_pull_last_event,omitempty"`
	ActivePullUpdatedUnix int64                                     `json:"active_pull_updated_unix,omitempty"`
	HintAccepted          int64                                     `json:"hint_accepted,omitempty"`
	HintSuppressed        int64                                     `json:"hint_suppressed,omitempty"`
	LastHintUnix          int64                                     `json:"last_hint_unix,omitempty"`
	LastHintReason        string                                    `json:"last_hint_reason,omitempty"`
	LastHintSuppression   string                                    `json:"last_hint_suppression,omitempty"`
	ReadOnlyResponder     int64                                     `json:"read_only_responder,omitempty"`
	LastResponderUnix     int64                                     `json:"last_responder_unix,omitempty"`
	LastResponderKind     string                                    `json:"last_responder_kind,omitempty"`
	LastResponderZone     string                                    `json:"last_responder_zone,omitempty"`
	DatagramStats         *observability.PeerDatagramStats          `json:"datagram_stats,omitempty"`
	ObjectPullStats       *observability.PeerObjectPullStats        `json:"object_pull_stats,omitempty"`
	RejectedDigests       map[string]photonstate.PeerRejectedDigest `json:"rejected_digests,omitempty"`
}

func BuildPeerView(id, configuredAddr string, endpoints []PeerEndpointView, state photonstate.PeerRuntimeState, diagnostics observability.PeerDiagnostics) PeerView {
	source := "discovered"
	if configuredAddr != "" {
		source = "bootstrap"
	} else if state.ObservedAddr != "" {
		source = "observed"
	}
	return PeerView{
		PeerID:          id,
		Source:          source,
		ConfiguredAddr:  configuredAddr,
		Endpoints:       endpoints,
		PeerRuntimeView: BuildPeerRuntimeView(state, diagnostics),
	}
}

func BuildPeerViewFromCheckpoint(id, configuredAddr string, endpoints []PeerEndpointView, checkpoint corestate.PeerCheckpoint, diagnostics observability.PeerDiagnostics) PeerView {
	return BuildPeerView(id, configuredAddr, endpoints, peerLinuxStateFromCheckpoint(checkpoint), diagnostics)
}

func BuildPeerRuntimeView(state photonstate.PeerRuntimeState, diagnostics observability.PeerDiagnostics) PeerRuntimeView {
	return PeerRuntimeView{
		LastSyncUnix:          state.LastSyncUnix,
		LastAttemptUnix:       state.LastAttemptUnix,
		BackoffUntilUnix:      state.BackoffUntilUnix,
		LastRelayUnix:         state.LastRelayUnix,
		FailureCount:          state.FailureCount,
		LastError:             state.LastError,
		LastUpdateSource:      diagnostics.LastUpdateSource,
		LastRelaySuppression:  diagnostics.LastRelaySuppression,
		LastRelaySuppressedAt: diagnostics.LastRelaySuppressedAt,
		DiscoveredAddr:        state.DiscoveredAddr,
		DiscoveredAtUnix:      state.DiscoveredAtUnix,
		ObservedAddr:          state.ObservedAddr,
		ObservedFirstSeenUnix: state.ObservedFirstSeenUnix,
		ObservedLastSeenUnix:  state.ObservedLastSeenUnix,
		ObservedLastSyncUnix:  state.ObservedLastSyncUnix,
		ObservedUntilUnix:     state.ObservedUntilUnix,
		ObservedSource:        diagnostics.ObservedSource,
		ObservedFailureCount:  state.ObservedFailureCount,
		ObservedGraceAddrs:    state.ObservedGraceAddrs,
		ActivePullState:       diagnostics.ActivePullState,
		ActivePullLastEvent:   diagnostics.ActivePullLastEvent,
		ActivePullUpdatedUnix: diagnostics.ActivePullUpdatedUnix,
		HintAccepted:          diagnostics.HintAccepted,
		HintSuppressed:        diagnostics.HintSuppressed,
		LastHintUnix:          diagnostics.LastHintUnix,
		LastHintReason:        diagnostics.LastHintReason,
		LastHintSuppression:   diagnostics.LastHintSuppression,
		ReadOnlyResponder:     diagnostics.ReadOnlyResponder,
		LastResponderUnix:     diagnostics.LastResponderUnix,
		LastResponderKind:     diagnostics.LastResponderKind,
		LastResponderZone:     diagnostics.LastResponderZone,
		DatagramStats:         diagnostics.DatagramStats,
		ObjectPullStats:       diagnostics.ObjectPullStats,
		RejectedDigests:       state.RejectedDigests,
	}
}

type EndpointDebugView struct {
	ManagedPeerID string
	Peers         []EndpointPeerView
}

type EndpointPeerView struct {
	PeerID    string
	Endpoints []PeerSignedEndpoint
}

func BuildEndpointDebug(state *corestate.VerifiedState, now time.Time) EndpointDebugView {
	view := EndpointDebugView{}
	if state == nil || state.Network == nil {
		return view
	}
	view.ManagedPeerID = string(state.ManagedZone)
	discovered := gossip.ExtractPeerEndpointsAt(state.Network, now)
	peerIDs := make([]string, 0, len(discovered))
	for peerID := range discovered {
		peerIDs = append(peerIDs, peerID)
	}
	SortZoneStrings(peerIDs)
	for _, peerID := range peerIDs {
		signed := discovered[peerID]
		endpoints := make([]PeerSignedEndpoint, 0, len(signed))
		for _, endpoint := range signed {
			endpoints = append(endpoints, PeerSignedEndpoint{
				Address: endpoint.Address, Port: endpoint.Port, Scope: endpoint.Scope,
				Priority: endpoint.Priority, Protocol: endpoint.Protocol, Source: endpoint.Source,
				LastObserved: endpoint.LastObserved,
			})
		}
		sort.SliceStable(endpoints, func(i, j int) bool {
			return signedEndpointLess(endpoints[i], endpoints[j])
		})
		view.Peers = append(view.Peers, EndpointPeerView{
			PeerID:    peerID,
			Endpoints: endpoints,
		})
	}
	return view
}

func signedEndpointLess(a, b PeerSignedEndpoint) bool {
	if a.Priority != b.Priority {
		return a.Priority > b.Priority
	}
	if a.LastObserved != b.LastObserved {
		return a.LastObserved > b.LastObserved
	}
	if a.Source != b.Source {
		return a.Source < b.Source
	}
	if a.Scope != b.Scope {
		return a.Scope < b.Scope
	}
	if a.Address != b.Address {
		return a.Address < b.Address
	}
	if a.Port != b.Port {
		return a.Port < b.Port
	}
	return a.Protocol < b.Protocol
}

// PeerStatusInfo is the derived runtime status view for a peer. Producers
// compute it from committed state and runtime observations; presenters render
// it without depending on app-private stateFile internals.
type PeerStatusInfo struct {
	PeerID            string        `json:"peer_id"`
	Zone              zone.ZonePath `json:"zone"`
	State             string        `json:"state"`
	Reason            string        `json:"reason,omitempty"`
	Detail            string        `json:"detail,omitempty"`
	LastSeenUnix      int64         `json:"last_seen_unix,omitempty"`
	LastSyncUnix      int64         `json:"last_sync_unix,omitempty"`
	LastEndpointUnix  int64         `json:"last_endpoint_change_unix,omitempty"`
	LastReconcileUnix int64         `json:"last_reconcile_unix,omitempty"`
	DesiredLinks      int           `json:"desired_links,omitempty"`
	ActualLinks       int           `json:"actual_links,omitempty"`
	UpLinks           int           `json:"up_links,omitempty"`
	OfflineSinceUnix  int64         `json:"offline_since_unix,omitempty"`
	NextCleanupUnix   int64         `json:"next_cleanup_unix,omitempty"`
}

type PeerDebugView struct {
	PeerID           string
	Source           string
	ConfiguredAddr   string
	ResolvedAddr     string
	Status           string
	LastSuccess      string
	LastError        string
	Backoff          string
	NextRetry        string
	KnownEndpoint    string
	DiscoveredAddr   string
	ObservedAddr     string
	ObservedStatus   string
	LastUpdateSource string
	LastRelay        string
	RelaySuppression string
	SyncFlow         PeerSyncFlowView
	DatagramStats    PeerDatagramStatsView
	ObjectPullStats  PeerObjectPullStatsView
}

type PeerDebugInput struct {
	PeerID         string
	Source         string
	ConfiguredAddr string
	ResolvedAddr   string
	photonstate.PeerRuntimeState
	Diagnostics observability.PeerDiagnostics
	Now         time.Time
}

type PeerSyncFlowView struct {
	ActivePullState     string
	ActivePullLastEvent string
	ActivePullUpdated   string
	HintAccepted        int64
	HintSuppressed      int64
	LastHint            string
	LastHintReason      string
	LastHintSuppression string
	ReadOnlyResponder   int64
	LastResponder       string
	LastResponderKind   string
	LastResponderZone   string
}

type PeerDatagramStatsView struct {
	TooLargeDropped           int64
	DigestOnlyAnnounces       int64
	ChunkFallbacks            int64
	ChunkRepairNACKs          int64
	ChunkRepairChunks         int64
	ChunkRepairIgnored        int64
	LastCatalogRootHex        string
	LastCatalogZoneCount      int
	LastCatalogCursor         string
	LastCatalogPageEntries    int
	LastCatalogRejectedReason string
	LastCatalog               string
	LastTooLarge              string
	LastTooLargeDirection     string
	LastTooLargeObject        string
	LastTooLargeZone          string
	LastTooLargeKey           string
	LastTooLargeBytes         int
	LastTooLargeLimit         int
}

type PeerObjectPullStatsView struct {
	Attempts               int64
	Successes              int64
	Failures               int64
	LargeObjectUnreachable int64
	Last                   string
	LastObject             string
	LastZone               string
	LastKey                string
	LastBytes              int
	LastSourcePeer         string
	LastUnreachable        bool
	LastError              string
}

func buildPeerDebugFromCheckpoint(peerID, source, configuredAddr, resolvedAddr string, checkpoint corestate.PeerCheckpoint, diagnostics observability.PeerDiagnostics, now time.Time) PeerDebugView {
	return BuildPeerDebug(PeerDebugInput{
		PeerID:           peerID,
		Source:           source,
		ConfiguredAddr:   configuredAddr,
		ResolvedAddr:     resolvedAddr,
		PeerRuntimeState: peerLinuxStateFromCheckpoint(checkpoint),
		Diagnostics:      diagnostics,
		Now:              now,
	})
}

func peerLinuxStateFromCheckpoint(checkpoint corestate.PeerCheckpoint) photonstate.PeerRuntimeState {
	state := photonstate.PeerRuntimeState{
		LastSyncUnix: checkpoint.LastSyncUnix, LastAttemptUnix: checkpoint.LastAttemptUnix,
		BackoffUntilUnix: checkpoint.BackoffUntilUnix, LastRelayUnix: checkpoint.LastRelayUnix,
		LastRelayCatalogRootHex: checkpoint.LastRelayCatalogRootHex, FailureCount: checkpoint.FailureCount,
		DiscoveredAddr: checkpoint.DiscoveredEndpoint, DiscoveredAtUnix: checkpoint.DiscoveredAtUnix,
		ObservedAddr: checkpoint.ObservedEndpoint, ObservedFirstSeenUnix: checkpoint.ObservedFirstSeenUnix,
		ObservedLastSeenUnix: checkpoint.ObservedLastSeenUnix, ObservedLastSyncUnix: checkpoint.ObservedLastSyncUnix,
		ObservedUntilUnix: checkpoint.ObservedUntilUnix, ObservedFailureCount: checkpoint.ObservedFailureCount,
	}
	if checkpoint.LastFailure != nil {
		state.LastError = checkpoint.LastFailure.Error()
	}
	for _, grace := range checkpoint.ObservedGraceEndpoints {
		state.ObservedGraceAddrs = append(state.ObservedGraceAddrs, photonstate.PeerObservedGraceAddrState{
			Addr: grace.Endpoint, UntilUnix: grace.UntilUnix,
		})
	}
	if len(checkpoint.RejectedObjects) > 0 {
		state.RejectedDigests = make(map[string]photonstate.PeerRejectedDigest, len(checkpoint.RejectedObjects))
		for path, rejected := range checkpoint.RejectedObjects {
			state.RejectedDigests[string(path)] = photonstate.PeerRejectedDigest{
				Zone: path, RootHashHex: hex.EncodeToString(rejected.RootHash), Reason: rejected.Reason,
				RejectedAtUnix: rejected.UpdatedUnix, UntilUnix: rejected.UntilUnix,
			}
		}
	}
	return state
}

func BuildPeerDebug(input PeerDebugInput) PeerDebugView {
	return PeerDebugView{
		PeerID:           input.PeerID,
		Source:           input.Source,
		ConfiguredAddr:   input.ConfiguredAddr,
		ResolvedAddr:     input.ResolvedAddr,
		Status:           peerDebugStatus(input, input.Now),
		LastSuccess:      formatPeerDebugLastSuccess(input.LastSyncUnix),
		LastError:        input.LastError,
		Backoff:          formatPeerDebugBackoff(input.BackoffUntilUnix, input.Now),
		NextRetry:        formatPeerDebugNextRetry(input.BackoffUntilUnix, input.Now),
		KnownEndpoint:    input.ResolvedAddr,
		DiscoveredAddr:   input.DiscoveredAddr,
		ObservedAddr:     input.ObservedAddr,
		ObservedStatus:   formatPeerDebugObservedPath(input, input.Now),
		LastUpdateSource: input.Diagnostics.LastUpdateSource,
		LastRelay:        formatPeerDebugUnixTime(input.LastRelayUnix),
		RelaySuppression: formatPeerDebugRelaySuppression(input.Diagnostics.LastRelaySuppression, input.Diagnostics.LastRelaySuppressedAt),
		SyncFlow:         BuildPeerSyncFlowFromObservability(input.Diagnostics),
		DatagramStats:    BuildPeerDatagramStats(input.Diagnostics.DatagramStats),
		ObjectPullStats:  BuildPeerObjectPullStats(input.Diagnostics.ObjectPullStats),
	}
}

func BuildPeerSyncFlowFromObservability(state observability.PeerDiagnostics) PeerSyncFlowView {
	return PeerSyncFlowView{
		ActivePullState:     state.ActivePullState,
		ActivePullLastEvent: state.ActivePullLastEvent,
		ActivePullUpdated:   formatPeerDebugUnixTime(state.ActivePullUpdatedUnix),
		HintAccepted:        state.HintAccepted,
		HintSuppressed:      state.HintSuppressed,
		LastHint:            formatPeerDebugUnixTime(state.LastHintUnix),
		LastHintReason:      state.LastHintReason,
		LastHintSuppression: state.LastHintSuppression,
		ReadOnlyResponder:   state.ReadOnlyResponder,
		LastResponder:       formatPeerDebugUnixTime(state.LastResponderUnix),
		LastResponderKind:   state.LastResponderKind,
		LastResponderZone:   state.LastResponderZone,
	}
}

func BuildPeerDatagramStats(stats *observability.PeerDatagramStats) PeerDatagramStatsView {
	if stats == nil {
		return PeerDatagramStatsView{}
	}
	return buildPeerDatagramStatsView(*stats)
}

func BuildPeerObjectPullStats(stats *observability.PeerObjectPullStats) PeerObjectPullStatsView {
	if stats == nil {
		return PeerObjectPullStatsView{}
	}
	return buildPeerObjectPullStatsView(*stats)
}

func buildPeerDatagramStatsView(input observability.PeerDatagramStats) PeerDatagramStatsView {
	return PeerDatagramStatsView{
		TooLargeDropped:           input.TooLargeDropped,
		DigestOnlyAnnounces:       input.DigestOnlyAnnounces,
		ChunkFallbacks:            input.ChunkFallbacks,
		ChunkRepairNACKs:          input.ChunkRepairNACKs,
		ChunkRepairChunks:         input.ChunkRepairChunks,
		ChunkRepairIgnored:        input.ChunkRepairIgnored,
		LastCatalogRootHex:        input.LastCatalogRootHex,
		LastCatalogZoneCount:      input.LastCatalogZoneCount,
		LastCatalogCursor:         input.LastCatalogCursor,
		LastCatalogPageEntries:    input.LastCatalogPageEntries,
		LastCatalogRejectedReason: input.LastCatalogRejectedReason,
		LastCatalog:               formatPeerDebugUnixTime(input.LastCatalogUnix),
		LastTooLarge:              formatPeerDebugUnixTime(input.LastTooLargeUnix),
		LastTooLargeDirection:     input.LastTooLargeDirection,
		LastTooLargeObject:        input.LastTooLargeObject,
		LastTooLargeZone:          input.LastTooLargeZone,
		LastTooLargeKey:           input.LastTooLargeKey,
		LastTooLargeBytes:         input.LastTooLargeBytes,
		LastTooLargeLimit:         input.LastTooLargeLimit,
	}
}

func buildPeerObjectPullStatsView(input observability.PeerObjectPullStats) PeerObjectPullStatsView {
	return PeerObjectPullStatsView{
		Attempts:               input.Attempts,
		Successes:              input.Successes,
		Failures:               input.Failures,
		LargeObjectUnreachable: input.LargeObjectUnreachable,
		Last:                   formatPeerDebugUnixTime(input.LastUnix),
		LastObject:             input.LastObject,
		LastZone:               input.LastZone,
		LastKey:                input.LastKey,
		LastBytes:              input.LastBytes,
		LastSourcePeer:         input.LastSourcePeer,
		LastUnreachable:        input.LastUnreachable,
		LastError:              input.LastError,
	}
}

func BuildPeerIDs(input PeerSetInput) []string {
	local := make(map[string]bool, len(input.LocalIDs))
	for _, id := range input.LocalIDs {
		if id != "" {
			local[id] = true
		}
	}
	seen := map[string]bool{}
	add := func(ids []string) {
		for _, id := range ids {
			if id == "" || local[id] || seen[id] {
				continue
			}
			seen[id] = true
		}
	}
	add(input.RuntimeIDs)
	add(input.BootstrapIDs)
	add(input.SignedIDs)
	out := make([]string, 0, len(seen))
	for id := range seen {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool { return ZonePathLess(out[i], out[j]) })
	return out
}

func peerDebugStatus(input PeerDebugInput, now time.Time) string {
	if peerDebugBackoffRemaining(input.BackoffUntilUnix, now) > 0 {
		return "backoff"
	}
	if input.LastError != "" {
		return "stale"
	}
	if input.LastSyncUnix == 0 {
		return "unknown"
	}
	if now.Sub(time.Unix(input.LastSyncUnix, 0)) > 2*time.Minute {
		return "stale"
	}
	return "online"
}

func formatPeerDebugLastSuccess(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return formatPeerDebugUnixTime(unix)
}

func formatPeerDebugBackoff(untilUnix int64, now time.Time) string {
	remaining := peerDebugBackoffRemaining(untilUnix, now)
	if remaining <= 0 {
		return "-"
	}
	return remaining.Round(time.Second).String()
}

func formatPeerDebugNextRetry(untilUnix int64, now time.Time) string {
	if peerDebugBackoffRemaining(untilUnix, now) <= 0 {
		return "-"
	}
	return formatPeerDebugUnixTime(untilUnix)
}

func formatPeerDebugUnixTime(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}

func formatPeerDebugRelaySuppression(reason string, suppressedAtUnix int64) string {
	if reason == "" {
		return "-"
	}
	at := formatPeerDebugUnixTime(suppressedAtUnix)
	if at == "never" {
		return reason
	}
	return fmt.Sprintf("%s at=%s", reason, at)
}

func formatPeerDebugObservedPath(input PeerDebugInput, now time.Time) string {
	if input.ObservedAddr == "" {
		return "-"
	}
	state := "expired"
	if input.ObservedUntilUnix != 0 && now.Before(time.Unix(input.ObservedUntilUnix, 0)) {
		state = "active"
	}
	return fmt.Sprintf("%s until=%s last_seen=%s last_success=%s failures=%d source=%s",
		state,
		formatPeerDebugUnixTime(input.ObservedUntilUnix),
		formatPeerDebugUnixTime(input.ObservedLastSeenUnix),
		formatPeerDebugUnixTime(input.ObservedLastSyncUnix),
		input.ObservedFailureCount,
		debugDash(input.Diagnostics.ObservedSource),
	)
}

func peerDebugBackoffRemaining(untilUnix int64, now time.Time) time.Duration {
	if untilUnix == 0 {
		return 0
	}
	until := time.Unix(untilUnix, 0)
	if !until.After(now) {
		return 0
	}
	return until.Sub(now)
}

func PeerKnown(input PeerSetInput, peerID string) bool {
	if peerID == "" {
		return false
	}
	if slices.Contains(input.LocalIDs, peerID) {
		return false
	}
	for _, ids := range [][]string{input.RuntimeIDs, input.BootstrapIDs, input.SignedIDs} {
		if slices.Contains(ids, peerID) {
			return true
		}
	}
	return false
}

func ZonePathLess(a, b string) bool {
	aLabels, aOK := zonePathLabels(a)
	bLabels, bOK := zonePathLabels(b)
	if !aOK || !bOK {
		return a < b
	}
	for i := 0; i < len(aLabels) && i < len(bLabels); i++ {
		if aLabels[i] != bLabels[i] {
			return aLabels[i] < bLabels[i]
		}
	}
	if len(aLabels) != len(bLabels) {
		return len(aLabels) < len(bLabels)
	}
	return a < b
}

func SortZoneStrings(paths []string) {
	sort.SliceStable(paths, func(i, j int) bool {
		return ZonePathLess(paths[i], paths[j])
	})
}

func SortZonePaths(paths []zone.ZonePath) {
	sort.SliceStable(paths, func(i, j int) bool {
		return ZonePathLess(string(paths[i]), string(paths[j]))
	})
}

func zonePathLabels(path string) ([]string, bool) {
	zp := zone.ZonePath(path)
	if !zp.Valid() {
		return nil, false
	}
	if zp.IsRoot() {
		return nil, true
	}
	labels := strings.FieldsFunc(strings.TrimSuffix(path, "."), func(r rune) bool {
		return r == '.' || r == '-'
	})
	for i, j := 0, len(labels)-1; i < j; i, j = i+1, j-1 {
		labels[i], labels[j] = labels[j], labels[i]
	}
	return labels, true
}

func BuildPeerEndpoints(input PeerEndpointInput) []PeerEndpointView {
	var out []PeerEndpointView
	appendEndpoint := func(ep PeerEndpointView) {
		if ep.Addr == "" && ep.Address != "" && ep.Port != 0 {
			ep.Addr = fmt.Sprintf("%s:%d", ep.Address, ep.Port)
		}
		if ep.Protocol == "" {
			ep.Protocol = "udp"
		}
		for i := range out {
			if out[i].Addr == ep.Addr && out[i].Source == ep.Source {
				if ep.Selected {
					out[i].Selected = true
				}
				return
			}
		}
		out = append(out, ep)
	}
	if input.BootstrapAddr != "" {
		appendEndpoint(PeerEndpointView{
			Addr:     input.BootstrapAddr,
			Source:   "bootstrap",
			Selected: input.SelectedAddr == input.BootstrapAddr,
		})
	}
	for _, ep := range input.Signed {
		addr := ""
		if ep.Address != "" && ep.Port != 0 {
			addr = fmt.Sprintf("%s:%d", ep.Address, ep.Port)
		}
		appendEndpoint(PeerEndpointView{
			Addr:         addr,
			Address:      ep.Address,
			Port:         ep.Port,
			Protocol:     ep.Protocol,
			Scope:        ep.Scope,
			Source:       firstNonEmpty(ep.Source, "signed"),
			Priority:     ep.Priority,
			LastObserved: ep.LastObserved,
			Selected:     input.SelectedAddr == addr,
		})
	}
	if input.SelectedAddr != "" {
		appendEndpoint(PeerEndpointView{Addr: input.SelectedAddr, Source: "selected", Selected: true})
	}
	if input.ObservedAddr != "" {
		appendEndpoint(PeerEndpointView{
			Addr:     input.ObservedAddr,
			Source:   firstNonEmpty(input.ObservedSource, "observed"),
			Selected: input.SelectedAddr == "",
		})
	}
	for _, grace := range input.Grace {
		appendEndpoint(PeerEndpointView{Addr: grace.Addr, Source: "observed_grace"})
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Selected != out[j].Selected {
			return out[i].Selected
		}
		if out[i].Source != out[j].Source {
			return out[i].Source < out[j].Source
		}
		return out[i].Addr < out[j].Addr
	})
	return out
}
