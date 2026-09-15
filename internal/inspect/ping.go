package inspect

import (
	"sort"
	"time"
)

type PingDebugView struct {
	Zone           string             `json:"zone"`
	Targets        []PingTargetView   `json:"targets,omitempty"`
	Instances      []PingInstanceView `json:"instances,omitempty"`
	AvailableZones []string           `json:"available_zones,omitempty"`
	Count          int                `json:"count"`
	Timeout        time.Duration      `json:"timeout"`
}

type PingInstanceView struct {
	InstanceID string           `json:"instance_id"`
	Rows       []PingTargetView `json:"rows,omitempty"`
}

type PingTargetView struct {
	InstanceID   string        `json:"instance_id"`
	ProbeID      string        `json:"probe_id,omitempty"`
	Role         string        `json:"role"`
	Family       string        `json:"family"`
	TunnelFamily string        `json:"tunnel_family"`
	Interface    string        `json:"interface,omitempty"`
	NetNS        string        `json:"netns,omitempty"`
	LocalTunnel  string        `json:"local_tunnel,omitempty"`
	PeerTunnel   string        `json:"peer_tunnel,omitempty"`
	Success      bool          `json:"success"`
	RTT          time.Duration `json:"rtt"`
	Failure      *FailureView  `json:"failure,omitempty"`
}

func BuildPingDebugView(view PingDebugView) PingDebugView {
	out := view
	out.Targets = append([]PingTargetView(nil), view.Targets...)
	out.AvailableZones = append([]string(nil), view.AvailableZones...)
	SortZoneStrings(out.AvailableZones)
	sort.SliceStable(out.Targets, func(i, j int) bool {
		a, b := out.Targets[i], out.Targets[j]
		if ai, bi := PingTargetInstanceID(a), PingTargetInstanceID(b); ai != bi {
			return ai < bi
		}
		if ar, br := PingTargetRole(a), PingTargetRole(b); ar != br {
			return ar < br
		}
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		if a.ProbeID != b.ProbeID {
			return a.ProbeID < b.ProbeID
		}
		return a.Interface < b.Interface
	})
	out.Instances = nil
	for _, target := range out.Targets {
		id := PingTargetInstanceID(target)
		if len(out.Instances) == 0 || out.Instances[len(out.Instances)-1].InstanceID != id {
			out.Instances = append(out.Instances, PingInstanceView{InstanceID: id})
		}
		idx := len(out.Instances) - 1
		out.Instances[idx].Rows = append(out.Instances[idx].Rows, target)
	}
	return out
}

func PingTargetInstanceID(target PingTargetView) string {
	if target.InstanceID != "" {
		return target.InstanceID
	}
	return target.ProbeID
}

func PingTargetRole(target PingTargetView) string {
	if target.Role != "" {
		return target.Role
	}
	return "active"
}
