package inspect

import (
	"sort"
	"time"
)

type PingDebugView struct {
	Zone           string
	Targets        []PingTargetView
	Instances      []PingInstanceView
	AvailableZones []string
	Count          int
	Timeout        time.Duration
}

type PingInstanceView struct {
	InstanceID string
	Rows       []PingTargetView
}

type PingTargetView struct {
	InstanceID   string
	ProbeID      string
	Role         string
	Family       string
	TunnelFamily string
	Interface    string
	NetNS        string
	LocalTunnel  string
	PeerTunnel   string
	Success      bool
	RTT          time.Duration
	Failure      *FailureView
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
