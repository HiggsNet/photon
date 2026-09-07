package inspect

import (
	"sort"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

const (
	StatusModeRunning  = "running"
	StatusModeAutoJoin = "auto-join"
	StatusModeNoState  = "no-state"
)

type StatusInput struct {
	DaemonOnline   bool
	GossipSource   string
	PlatformSource string
	ManagedZone    zone.ZonePath
	Admission      AdmissionDiagnosis
	Peers          []PeerStatusInfo
	Links          LinkInspection
}

type StatusCount struct {
	State string
	Count int
}

type StatusPeerSummary struct {
	Total    int
	LastSync int64
	States   []StatusCount
}

type StatusLinkSummary struct {
	Desired   int
	Total     int
	Up        int
	States    []StatusCount
	Health    []StatusCount
	LastError string
}

type StatusView struct {
	DaemonOnline   bool
	GossipSource   string
	PlatformSource string
	ManagedZone    zone.ZonePath
	Mode           string
	AutoJoinStage  string
	Admission      AdmissionDiagnosis
	Peers          StatusPeerSummary
	Links          StatusLinkSummary
}

// DaemonStatusView is the canonical operational status read model used by the
// Observer API. It is distinct from StatusView, the human CLI summary.
type DaemonStatusView struct {
	PeerID            string `json:"peer_id,omitempty"`
	ManagedZone       string `json:"managed_zone,omitempty"`
	ListenAddr        string `json:"listen_addr,omitempty"`
	DaemonOnline      bool   `json:"daemon_online"`
	StateRevision     uint64 `json:"state_revision"`
	Dirty             any    `json:"dirty,omitempty"`
	ReconcileProgress any    `json:"reconcile_progress,omitempty"`
	KnownZones        int    `json:"known_zones,omitempty"`
	KnownPeers        int    `json:"known_peers,omitempty"`
	LinkInstances     int    `json:"link_instances,omitempty"`
	DesiredLinks      int    `json:"desired_links,omitempty"`
	LastLinkError     string `json:"last_link_error,omitempty"`
	LastRoutingError  string `json:"last_routing_error,omitempty"`
	LastSyncUnix      int64  `json:"last_sync_unix,omitempty"`
	LastReconcileUnix int64  `json:"last_reconcile_unix,omitempty"`
}

type DaemonStatusInput struct {
	PeerID             string
	ManagedZone        string
	ListenAddr         string
	DaemonOnline       bool
	StateRevision      uint64
	Dirty              any
	ReconcileProgress  any
	KnownZones         int
	KnownPeers         int
	LinkInstances      int
	DesiredLinks       int
	LastLinkError      string
	LastRoutingError   string
	LastSyncUnix       int64
	IPsecLastRunUnix   int64
	RoutingLastRunUnix int64
}

func BuildDaemonStatus(input DaemonStatusInput) DaemonStatusView {
	return DaemonStatusView{
		PeerID:            input.PeerID,
		ManagedZone:       input.ManagedZone,
		ListenAddr:        input.ListenAddr,
		DaemonOnline:      input.DaemonOnline,
		StateRevision:     input.StateRevision,
		Dirty:             input.Dirty,
		ReconcileProgress: input.ReconcileProgress,
		KnownZones:        input.KnownZones,
		KnownPeers:        input.KnownPeers,
		LinkInstances:     input.LinkInstances,
		DesiredLinks:      input.DesiredLinks,
		LastLinkError:     input.LastLinkError,
		LastRoutingError:  input.LastRoutingError,
		LastSyncUnix:      input.LastSyncUnix,
		LastReconcileUnix: max(input.RoutingLastRunUnix, input.IPsecLastRunUnix),
	}
}

func BuildStatus(input StatusInput) StatusView {
	view := StatusView{
		DaemonOnline:   input.DaemonOnline,
		GossipSource:   input.GossipSource,
		PlatformSource: input.PlatformSource,
		ManagedZone:    input.ManagedZone,
		Mode:           StatusModeRunning,
		Admission:      input.Admission,
	}
	if view.ManagedZone == "" {
		view.ManagedZone = input.Admission.ManagedZone
	}
	if view.ManagedZone == "" {
		view.Mode = StatusModeNoState
	}
	if input.Admission.Pending {
		view.Mode = StatusModeAutoJoin
		view.AutoJoinStage = AutoJoinStage(input.Admission.Reason)
	}

	peerStates := make(map[string]int)
	for _, peer := range input.Peers {
		peerStates[statusName(peer.State)]++
		if peer.LastSyncUnix > view.Peers.LastSync {
			view.Peers.LastSync = peer.LastSyncUnix
		}
	}
	view.Peers.Total = len(input.Peers)
	view.Peers.States = sortedStatusCounts(peerStates)

	linkStates := make(map[string]int)
	healthStates := make(map[string]int)
	view.Links.Desired = input.Links.Summary.DesiredLinks
	view.Links.Total = input.Links.Summary.LinkInstances
	view.Links.LastError = input.Links.Summary.LastError
	for _, link := range input.Links.Links {
		state := statusName(link.State)
		linkStates[state]++
		if state == "up" {
			view.Links.Up++
		}
		if link.Health != nil {
			healthStates[statusName(link.Health.State)]++
		}
	}
	view.Links.States = sortedStatusCounts(linkStates)
	view.Links.Health = sortedStatusCounts(healthStates)
	return view
}

func AutoJoinStage(reason string) string {
	switch reason {
	case AdmissionReasonMissingZoneKey:
		return "preparing_identity"
	case AdmissionReasonNoBootstrapSync, AdmissionReasonMissingParentZone:
		return "syncing_parent"
	case AdmissionReasonMissingDelegation:
		return "awaiting_delegation"
	case AdmissionReasonDelegationKeyMismatch, AdmissionReasonVerifyDelegationFailed:
		return "delegation_invalid"
	case AdmissionReasonWaitingForAdoption:
		return "adopting"
	default:
		return "pending"
	}
}

func sortedStatusCounts(counts map[string]int) []StatusCount {
	states := make([]string, 0, len(counts))
	for state := range counts {
		states = append(states, state)
	}
	sort.Strings(states)
	out := make([]StatusCount, 0, len(states))
	for _, state := range states {
		out = append(out, StatusCount{State: state, Count: counts[state]})
	}
	return out
}

func statusName(value string) string {
	if value == "" {
		return "unknown"
	}
	return value
}
