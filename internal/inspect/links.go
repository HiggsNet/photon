package inspect

import (
	"net/netip"
	"sort"
	"strings"

	photonstate "github.com/HiggsNet/photon/internal/state"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

type LinkInput struct {
	Instances      []LinkInstance
	LastDesired    []DesiredLink
	PlannedDesired []DesiredLink
	ActualSAs      []LinkSA
	Health         []HealthSample
	Actions        []LinkAction
	Skipped        []LinkSkip
	LastRunUnix    int64
	DesiredLinks   int
	LastFailure    error
}

type LinkInspection struct {
	Summary LinkSummary
	Links   []LinkView
	Actions []LinkAction
	Skipped []LinkSkip
}

type LinksDebugView struct {
	Inspection        LinkInspection
	StoredSAs         []LinkSA
	LiveSAs           []LinkSA
	LiveSAError       string
	ReplannedDesired  int
	ReplanIgnored     bool
	LastDesiredLinks  int
	DesiredPlanSource string
	Filter            string
}

type LinkSummary struct {
	LastRunUnix       int64
	DesiredLinks      int
	PlannedDesired    int
	ActualSAs         int
	LinkInstances     int
	LastFailure       *FailureView
	DesiredPlanError  string
	HasPlannedDesired bool
	HasMissingPlanned bool
}

type LinkView struct {
	ID              string
	PeerZone        string
	GroupID         string
	TransportKind   string
	LinkID          string
	PathKey         string
	TransportID     string
	IKEName         string
	State           string
	ActualState     string
	Endpoint        string
	InterfaceName   string
	XFRMIfID        uint32
	LocalTunnelAddr string
	PeerTunnelAddr  string
	ChildSAName     string
	DesiredSpecHash string
	Desired         *DesiredLink
	ActualSA        *LinkSA
	Health          *HealthSample
	Routing         LinkRouting
	Rotation        LinkRotation
	Takeover        LinkTakeover
	Owner           LinkOwner
	FailureCount    int
	BackoffUntil    int64
	LastTransition  int64
	LastFailure     *FailureView
	Missing         bool
}

type LinkInstance struct {
	ID                    string
	GroupID               string
	PeerZone              string
	TransportKind         string
	LinkID                string
	PathKey               string
	TransportID           string
	DesiredSpecHash       string
	ActualState           string
	InterfaceName         string
	XFRMIfID              uint32
	LocalTunnelAddr       string
	PeerTunnelAddr        string
	IKEName               string
	ChildSAName           string
	Endpoint              string
	RemoteGeneration      uint64
	StagedGeneration      uint64
	RotatePhase           string
	StagedIKEName         string
	StagedChildSAName     string
	StagedInterfaceName   string
	StagedXFRMIfID        uint32
	StagedLocalTunnelAddr string
	StagedPeerTunnelAddr  string
	RotateDeadline        int64
	LastFailure           error
	FailureCount          int
	BackoffUntil          int64
	LastTransition        int64
	Owner                 LinkOwner
	InitiatorRole         string
	TakeoverPhase         string
	TakeoverStartedAt     int64
	TakeoverUntil         int64
	LastTakeoverFailure   error
	ObservedInitiator     string
	Routing               LinkRouting
}

// LinkOwner is the inspect/JSON projection of an IPsec resource owner.
type LinkOwner struct {
	Manager     string `json:"manager,omitempty"`
	GroupID     string `json:"group_id,omitempty"`
	InstanceID  string `json:"instance_id,omitempty"`
	LinkID      string `json:"link_id,omitempty"`
	TransportID string `json:"transport_id,omitempty"`
	Token       string `json:"token,omitempty"`
}

type DesiredLink = photonstate.DesiredLinkObservation
type LinkSA = photonstate.LinkSAObservation

type LinkRouting struct {
	BirdState      string `json:"bird_state,omitempty"`
	BirdNeighbors  string `json:"bird_neighbors,omitempty"`
	BirdBestRoutes string `json:"bird_best_routes,omitempty"`
}

type LinkRotation struct {
	Phase                 string `json:"phase,omitempty"`
	RemoteGeneration      uint64 `json:"remote_generation,omitempty"`
	StagedGeneration      uint64 `json:"staged_generation,omitempty"`
	StagedIKEName         string `json:"staged_ike_name,omitempty"`
	StagedChildSAName     string `json:"staged_child_sa_name,omitempty"`
	StagedInterfaceName   string `json:"staged_interface_name,omitempty"`
	StagedXFRMIfID        uint32 `json:"staged_xfrm_if_id,omitempty"`
	StagedLocalTunnelAddr string `json:"staged_local_tunnel_addr,omitempty"`
	StagedPeerTunnelAddr  string `json:"staged_peer_tunnel_addr,omitempty"`
	RotateDeadline        int64  `json:"rotate_deadline,omitempty"`
}

type LinkTakeover struct {
	InitiatorRole     string       `json:"initiator_role,omitempty"`
	Phase             string       `json:"phase,omitempty"`
	StartedAt         int64        `json:"started_at,omitempty"`
	Until             int64        `json:"until,omitempty"`
	ObservedInitiator string       `json:"observed_initiator,omitempty"`
	LastFailure       *FailureView `json:"last_failure,omitempty"`
}

type LinkAction = photonstate.LinkActionObservation
type LinkSkip = photonstate.LinkSkipObservation

// BuildLinkInstanceFromRuntime builds an inspect view of an observed IPsec
// link. Routing is supplied separately because it is
// derived from the BIRD runtime snapshot.
func BuildLinkInstanceFromRuntime(inst ipsec.LinkInstance, routing LinkRouting) LinkInstance {
	return LinkInstance{
		ID:                    inst.ID,
		GroupID:               inst.GroupID,
		PeerZone:              string(inst.PeerZone),
		TransportKind:         inst.TransportKind,
		LinkID:                inst.LinkID,
		PathKey:               inst.PathKey,
		TransportID:           inst.TransportID,
		DesiredSpecHash:       inst.DesiredSpecHash,
		ActualState:           inst.ActualState,
		InterfaceName:         inst.InterfaceName,
		XFRMIfID:              inst.XFRMIfID,
		LocalTunnelAddr:       formatObservedAddr(inst.LocalTunnelAddr),
		PeerTunnelAddr:        formatObservedAddr(inst.PeerTunnelAddr),
		IKEName:               inst.IKEName,
		ChildSAName:           inst.ChildSAName,
		Endpoint:              inst.Endpoint,
		RemoteGeneration:      inst.RemoteGeneration,
		StagedGeneration:      inst.StagedGeneration,
		RotatePhase:           inst.RotatePhase,
		StagedIKEName:         inst.StagedIKEName,
		StagedChildSAName:     inst.StagedChildSAName,
		StagedInterfaceName:   inst.StagedInterfaceName,
		StagedXFRMIfID:        inst.StagedXFRMIfID,
		StagedLocalTunnelAddr: formatObservedAddr(inst.StagedLocalTunnelAddr),
		StagedPeerTunnelAddr:  formatObservedAddr(inst.StagedPeerTunnelAddr),
		RotateDeadline:        inst.RotateDeadline,
		LastFailure:           inst.LastFailure,
		FailureCount:          inst.FailureCount,
		BackoffUntil:          inst.BackoffUntil,
		LastTransition:        inst.LastTransition,
		Owner: LinkOwner{
			Manager: inst.Owner.Manager, GroupID: inst.Owner.GroupID,
			InstanceID: inst.Owner.InstanceID, LinkID: inst.Owner.LinkID,
			TransportID: inst.Owner.TransportID, Token: inst.Owner.Token,
		},
		InitiatorRole:       inst.InitiatorRole,
		TakeoverPhase:       inst.TakeoverPhase,
		TakeoverStartedAt:   inst.TakeoverStartedAt,
		TakeoverUntil:       inst.TakeoverUntil,
		LastTakeoverFailure: inst.LastTakeoverFailure,
		ObservedInitiator:   inst.ObservedInitiator,
		Routing:             routing,
	}
}

func formatObservedAddr(addr netip.Addr) string {
	if !addr.IsValid() {
		return ""
	}
	return addr.String()
}

func FilterLinkViews(links []LinkView, filter string) []LinkView {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return links
	}
	out := make([]LinkView, 0, len(links))
	for _, link := range links {
		if linkMatchesFilter(link, filter) {
			out = append(out, link)
		}
	}
	return out
}

func FilterLinkActions(actions []LinkAction, filter string) []LinkAction {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return actions
	}
	out := make([]LinkAction, 0, len(actions))
	for _, action := range actions {
		if stringMatchesFilter(filter, action.InstanceID, action.GroupID, string(action.PeerZone), action.Action, action.Reason) {
			out = append(out, action)
		}
	}
	return out
}

func FilterLinkSkips(skips []LinkSkip, filter string) []LinkSkip {
	filter = strings.ToLower(strings.TrimSpace(filter))
	if filter == "" {
		return skips
	}
	out := make([]LinkSkip, 0, len(skips))
	for _, skip := range skips {
		if stringMatchesFilter(filter, skip.GroupID, string(skip.Peer), skip.Reason, skip.Detail) {
			out = append(out, skip)
		}
	}
	return out
}

func linkMatchesFilter(link LinkView, filter string) bool {
	values := []string{
		link.ID,
		link.PeerZone,
		link.GroupID,
		link.TransportKind,
		link.LinkID,
		link.PathKey,
		link.TransportID,
		link.IKEName,
		link.Endpoint,
		link.InterfaceName,
		link.ChildSAName,
		link.Rotation.Phase,
		link.Rotation.StagedIKEName,
		link.Rotation.StagedChildSAName,
		link.Rotation.StagedInterfaceName,
		link.Takeover.InitiatorRole,
		link.Takeover.ObservedInitiator,
	}
	if link.Desired != nil {
		values = append(values,
			link.Desired.InstanceID,
			string(link.Desired.PeerZone),
			link.Desired.GroupID,
			link.Desired.LinkID,
			link.Desired.PathKey,
			link.Desired.TransportID,
			link.Desired.InterfaceName,
			link.Desired.Endpoint,
		)
	}
	if link.ActualSA != nil {
		values = append(values,
			link.ActualSA.Name,
			link.ActualSA.Peer,
			link.ActualSA.ChildSA,
			link.ActualSA.LocalIdentity,
			link.ActualSA.RemoteIdentity,
			link.ActualSA.LocalEndpoint,
			link.ActualSA.RemoteEndpoint,
			link.ActualSA.Endpoint,
		)
	}
	if link.Health != nil {
		values = append(values, link.Health.InstanceID, link.Health.ProbeID, link.Health.InterfaceName, link.Health.State)
	}
	return stringMatchesFilter(filter, values...)
}

func stringMatchesFilter(filter string, values ...string) bool {
	for _, value := range values {
		if strings.Contains(strings.ToLower(value), filter) {
			return true
		}
	}
	return false
}

func BuildLinks(input LinkInput) LinkInspection {
	lastDesired := desiredByID(input.LastDesired)
	plannedDesired := desiredByID(input.PlannedDesired)
	sas := sasByID(input.ActualSAs)
	health := healthByID(input.Health)

	ids := make([]string, 0, len(input.Instances))
	instances := make(map[string]LinkInstance, len(input.Instances))
	for _, inst := range input.Instances {
		if inst.ID == "" {
			continue
		}
		instances[inst.ID] = inst
		ids = append(ids, inst.ID)
	}
	sort.Strings(ids)

	links := make([]LinkView, 0, len(ids))
	for _, id := range ids {
		inst := instances[id]
		desired, hasDesired := lastDesired[id]
		if planned, ok := plannedDesired[id]; ok {
			desired = planned
			hasDesired = true
		}
		links = append(links, linkFromInstance(inst, desired, hasDesired, linkSAForView(id, inst, desired, sas), health[id]))
	}
	if len(ids) == 0 && len(plannedDesired) > 0 {
		plannedIDs := make([]string, 0, len(plannedDesired))
		for id := range plannedDesired {
			plannedIDs = append(plannedIDs, id)
		}
		sort.Strings(plannedIDs)
		for _, id := range plannedIDs {
			desired := plannedDesired[id]
			links = append(links, missingLinkFromDesired(desired))
		}
	}
	sort.SliceStable(links, func(i, j int) bool {
		if links[i].PeerZone != links[j].PeerZone {
			return ZonePathLess(links[j].PeerZone, links[i].PeerZone)
		}
		return links[i].ID < links[j].ID
	})

	return LinkInspection{
		Summary: LinkSummary{
			LastRunUnix:       input.LastRunUnix,
			DesiredLinks:      input.DesiredLinks,
			PlannedDesired:    len(plannedDesired),
			ActualSAs:         len(input.ActualSAs),
			LinkInstances:     len(ids),
			LastFailure:       BuildFailure(FailureCodeIPsecReconcile, input.LastFailure),
			HasPlannedDesired: len(plannedDesired) > 0,
			HasMissingPlanned: len(ids) == 0 && len(plannedDesired) > 0,
		},
		Links:   links,
		Actions: append([]LinkAction(nil), input.Actions...),
		Skipped: append([]LinkSkip(nil), input.Skipped...),
	}
}

func linkSAForView(id string, inst LinkInstance, desired DesiredLink, sas map[string]*LinkSA) *LinkSA {
	for _, key := range []string{id, inst.IKEName, inst.ChildSAName, inst.TransportID, desired.TransportID} {
		if key == "" {
			continue
		}
		if sa := sas[key]; sa != nil {
			return sa
		}
	}
	return nil
}

func linkFromInstance(inst LinkInstance, desired DesiredLink, hasDesired bool, sa *LinkSA, health *HealthSample) LinkView {
	var desiredPtr *DesiredLink
	if hasDesired {
		desiredCopy := desired
		desiredPtr = &desiredCopy
	}
	localTunnel := inst.LocalTunnelAddr
	peerTunnel := inst.PeerTunnelAddr
	if linkInstanceMatchesDesiredRuntime(inst, desired) {
		localTunnel = firstNonEmpty(localTunnel, desired.LocalTunnelAddr)
		peerTunnel = firstNonEmpty(peerTunnel, desired.PeerTunnelAddr)
	}
	return LinkView{
		ID:              inst.ID,
		PeerZone:        inst.PeerZone,
		GroupID:         inst.GroupID,
		TransportKind:   inst.TransportKind,
		LinkID:          inst.LinkID,
		PathKey:         inst.PathKey,
		TransportID:     inst.TransportID,
		IKEName:         inst.IKEName,
		State:           firstNonEmpty(inst.ActualState, "unknown"),
		ActualState:     inst.ActualState,
		Endpoint:        firstNonEmpty(inst.Endpoint, desired.Endpoint),
		InterfaceName:   firstNonEmpty(inst.InterfaceName, desired.InterfaceName),
		XFRMIfID:        firstNonZeroUint32(inst.XFRMIfID, desired.XFRMIfID),
		LocalTunnelAddr: localTunnel,
		PeerTunnelAddr:  peerTunnel,
		ChildSAName:     inst.ChildSAName,
		DesiredSpecHash: firstNonEmpty(inst.DesiredSpecHash, desired.DesiredSpecHash),
		Desired:         desiredPtr,
		ActualSA:        sa,
		Health:          health,
		Routing:         inst.Routing,
		Rotation: LinkRotation{
			Phase:                 inst.RotatePhase,
			RemoteGeneration:      inst.RemoteGeneration,
			StagedGeneration:      inst.StagedGeneration,
			StagedIKEName:         inst.StagedIKEName,
			StagedChildSAName:     inst.StagedChildSAName,
			StagedInterfaceName:   inst.StagedInterfaceName,
			StagedXFRMIfID:        inst.StagedXFRMIfID,
			StagedLocalTunnelAddr: inst.StagedLocalTunnelAddr,
			StagedPeerTunnelAddr:  inst.StagedPeerTunnelAddr,
			RotateDeadline:        inst.RotateDeadline,
		},
		Takeover: LinkTakeover{
			InitiatorRole:     inst.InitiatorRole,
			Phase:             inst.TakeoverPhase,
			StartedAt:         inst.TakeoverStartedAt,
			Until:             inst.TakeoverUntil,
			ObservedInitiator: inst.ObservedInitiator,
			LastFailure:       BuildFailure(FailureCodeIPsecTakeover, inst.LastTakeoverFailure),
		},
		Owner:          inst.Owner,
		FailureCount:   inst.FailureCount,
		BackoffUntil:   inst.BackoffUntil,
		LastTransition: inst.LastTransition,
		LastFailure:    BuildFailure(FailureCodeIPsecLink, inst.LastFailure),
	}
}

func linkInstanceMatchesDesiredRuntime(inst LinkInstance, desired DesiredLink) bool {
	if desired.InterfaceName != "" && inst.InterfaceName != "" && desired.InterfaceName != inst.InterfaceName {
		return false
	}
	if desired.XFRMIfID != 0 && inst.XFRMIfID != 0 && desired.XFRMIfID != inst.XFRMIfID {
		return false
	}
	if desired.TransportID != "" && inst.TransportID != "" && desired.TransportID != inst.TransportID {
		return false
	}
	return true
}

func missingLinkFromDesired(desired DesiredLink) LinkView {
	desiredCopy := desired
	return LinkView{
		ID:              desired.InstanceID,
		PeerZone:        string(desired.PeerZone),
		GroupID:         desired.GroupID,
		LinkID:          desired.LinkID,
		PathKey:         desired.PathKey,
		TransportID:     desired.TransportID,
		State:           "missing",
		Endpoint:        desired.Endpoint,
		InterfaceName:   desired.InterfaceName,
		XFRMIfID:        desired.XFRMIfID,
		DesiredSpecHash: desired.DesiredSpecHash,
		Desired:         &desiredCopy,
		Missing:         true,
	}
}

func desiredByID(items []DesiredLink) map[string]DesiredLink {
	out := make(map[string]DesiredLink, len(items))
	for _, item := range items {
		if item.InstanceID != "" {
			out[item.InstanceID] = item
		}
	}
	return out
}

func sasByID(items []LinkSA) map[string]*LinkSA {
	out := make(map[string]*LinkSA, len(items))
	for i := range items {
		item := &items[i]
		if item.Name != "" {
			out[item.Name] = item
		}
		if item.ChildSA != "" {
			out[item.ChildSA] = item
		}
	}
	return out
}

func healthByID(items []HealthSample) map[string]*HealthSample {
	out := make(map[string]*HealthSample, len(items))
	for i := range items {
		item := &items[i]
		if item.InstanceID != "" {
			if _, exists := out[item.InstanceID]; !exists || item.ProbeRole == "" || item.ProbeRole == "active" || item.ProbeRole == "staged" {
				out[item.InstanceID] = item
			}
		}
		if item.ProbeID != "" {
			out[item.ProbeID] = item
		}
	}
	return out
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}

func firstNonZeroUint32(values ...uint32) uint32 {
	for _, value := range values {
		if value != 0 {
			return value
		}
	}
	return 0
}
