package http

import "github.com/HiggsNet/photon/internal/inspect"

type LinksResponse struct {
	Instances    []LinkJSON           `json:"instances"`
	LastRunUnix  int64                `json:"last_run_unix,omitempty"`
	DesiredLinks int                  `json:"desired_links,omitempty"`
	ActualSAs    int                  `json:"actual_sas,omitempty"`
	Actions      []inspect.LinkAction `json:"actions,omitempty"`
	Skipped      []inspect.LinkSkip   `json:"skipped,omitempty"`
	LastFailure  *inspect.FailureView `json:"last_failure,omitempty"`
}

type LinkJSON struct {
	ID              string                `json:"id"`
	PeerZone        string                `json:"peer_zone"`
	GroupID         string                `json:"group_id,omitempty"`
	TransportKind   string                `json:"transport_kind,omitempty"`
	TransportID     string                `json:"transport_id,omitempty"`
	IKEName         string                `json:"ike_name,omitempty"`
	State           string                `json:"state,omitempty"`
	ActualState     string                `json:"actual_state,omitempty"`
	Endpoint        string                `json:"endpoint,omitempty"`
	InterfaceName   string                `json:"interface_name,omitempty"`
	XFRMIfID        uint32                `json:"xfrm_if_id,omitempty"`
	DesiredSpecHash string                `json:"desired_spec_hash,omitempty"`
	Desired         *inspect.DesiredLink  `json:"desired,omitempty"`
	ActualSA        *inspect.LinkSA       `json:"actual_sa,omitempty"`
	Health          *inspect.HealthSample `json:"health,omitempty"`
	Routing         inspect.LinkRouting   `json:"routing"`
	Rotation        inspect.LinkRotation  `json:"rotation"`
	Takeover        inspect.LinkTakeover  `json:"takeover"`
	Owner           inspect.LinkOwner     `json:"owner,omitempty"`
	FailureCount    int                   `json:"failure_count,omitempty"`
	BackoffUntil    int64                 `json:"backoff_until,omitempty"`
	LastTransition  int64                 `json:"last_transition,omitempty"`
	LastFailure     *inspect.FailureView  `json:"last_failure,omitempty"`
	Raw             inspect.LinkView      `json:"raw"`
}

func LinksFromInspection(view inspect.LinkInspection) LinksResponse {
	instances := make([]LinkJSON, 0, len(view.Links))
	for _, link := range view.Links {
		instances = append(instances, LinkFromInspect(link))
	}
	return LinksResponse{
		Instances:    instances,
		LastRunUnix:  view.Summary.LastRunUnix,
		DesiredLinks: view.Summary.DesiredLinks,
		ActualSAs:    view.Summary.ActualSAs,
		Actions:      view.Actions,
		Skipped:      view.Skipped,
		LastFailure:  view.Summary.LastFailure,
	}
}

func LinkFromInspect(link inspect.LinkView) LinkJSON {
	return LinkJSON{
		ID:              link.ID,
		PeerZone:        link.PeerZone,
		GroupID:         link.GroupID,
		TransportKind:   link.TransportKind,
		TransportID:     link.TransportID,
		IKEName:         link.IKEName,
		State:           link.State,
		ActualState:     link.ActualState,
		Endpoint:        link.Endpoint,
		InterfaceName:   link.InterfaceName,
		XFRMIfID:        link.XFRMIfID,
		DesiredSpecHash: link.DesiredSpecHash,
		Desired:         link.Desired,
		ActualSA:        link.ActualSA,
		Health:          link.Health,
		Routing:         link.Routing,
		Rotation:        link.Rotation,
		Takeover:        link.Takeover,
		Owner:           link.Owner,
		FailureCount:    link.FailureCount,
		BackoffUntil:    link.BackoffUntil,
		LastTransition:  link.LastTransition,
		LastFailure:     link.LastFailure,
		Raw:             link,
	}
}
