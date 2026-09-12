package http

import (
	"sort"

	"github.com/HiggsNet/photon/internal/inspect"
)

type HealthResponse struct {
	Datasource any                 `json:"datasource"`
	Links      []HealthContextItem `json:"links"`
}

type HealthSeriesResponse struct {
	Datasource any    `json:"datasource"`
	LinkID     string `json:"link_id"`
	Series     any    `json:"series"`
}

type HealthContextItem struct {
	Health          inspect.HealthSample `json:"health"`
	Instance        any                  `json:"instance,omitempty"`
	Desired         any                  `json:"desired,omitempty"`
	PeerZone        any                  `json:"peer_zone,omitempty"`
	GroupID         string               `json:"group_id,omitempty"`
	InterfaceName   string               `json:"interface_name,omitempty"`
	Endpoint        string               `json:"endpoint,omitempty"`
	ActualState     string               `json:"actual_state,omitempty"`
	LocalTunnelAddr string               `json:"local_tunnel_addr,omitempty"`
	PeerTunnelAddr  string               `json:"peer_tunnel_addr,omitempty"`
}

type HealthContextInput struct {
	View      inspect.HealthView
	Instances map[string]HealthInstanceContextInput
	Desired   map[string]HealthDesiredContextInput
}

type HealthInstanceContextInput struct {
	ID            string
	PeerZone      any
	GroupID       string
	InterfaceName string
	Endpoint      string
	ActualState   string
	Instance      any
}

type HealthDesiredContextInput struct {
	InstanceID      string
	PeerZone        any
	GroupID         string
	InterfaceName   string
	LocalTunnelAddr string
	PeerTunnelAddr  string
	Desired         any
}

func BuildHealthContext(input HealthContextInput) []HealthContextItem {
	targetsByProbe := make(map[string]inspect.HealthTarget, len(input.View.Targets))
	for _, target := range input.View.Targets {
		targetsByProbe[healthProbeID(target.ProbeID, target.InstanceID)] = target
	}
	coveredProbes := make(map[string]bool, len(input.View.Samples))
	coveredInstances := make(map[string]bool, len(input.View.Samples)+len(input.View.Targets))
	out := make([]HealthContextItem, 0, len(input.View.Samples)+len(input.View.Targets)+len(input.Instances))
	for _, sample := range input.View.Samples {
		if sample.InstanceID == "" {
			continue
		}
		probeID := healthProbeID(sample.ProbeID, sample.InstanceID)
		coveredProbes[probeID] = true
		coveredInstances[sample.InstanceID] = true
		out = append(out, buildHealthContextItem(sample, targetsByProbe[probeID], input.Instances[sample.InstanceID], input.Desired[sample.InstanceID]))
	}
	for _, target := range input.View.Targets {
		probeID := healthProbeID(target.ProbeID, target.InstanceID)
		if target.InstanceID == "" || coveredProbes[probeID] {
			continue
		}
		coveredInstances[target.InstanceID] = true
		sample := inspect.HealthSample{
			ProbeID: target.ProbeID, InstanceID: target.InstanceID,
			ProbeRole: target.ProbeRole, InterfaceName: target.InterfaceName, State: "unknown",
		}
		out = append(out, buildHealthContextItem(sample, target, input.Instances[target.InstanceID], input.Desired[target.InstanceID]))
	}
	ids := make([]string, 0, len(input.Instances))
	for id := range input.Instances {
		if !coveredInstances[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		sample := inspect.HealthSample{InstanceID: id, State: "unknown"}
		out = append(out, buildHealthContextItem(sample, inspect.HealthTarget{}, input.Instances[id], input.Desired[id]))
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Health.InstanceID != out[j].Health.InstanceID {
			return out[i].Health.InstanceID < out[j].Health.InstanceID
		}
		return out[i].Health.ProbeRole < out[j].Health.ProbeRole
	})
	return out
}

func buildHealthContextItem(sample inspect.HealthSample, target inspect.HealthTarget, inst HealthInstanceContextInput, desired HealthDesiredContextInput) HealthContextItem {
	item := HealthContextItem{
		Health:          sample,
		GroupID:         target.GroupID,
		InterfaceName:   firstNonEmpty(sample.InterfaceName, target.InterfaceName),
		ActualState:     target.State,
		LocalTunnelAddr: target.LocalTunnelAddr,
		PeerTunnelAddr:  target.PeerTunnelAddr,
	}
	if target.PeerZone != "" {
		item.PeerZone = target.PeerZone
	}
	if inst.ID != "" {
		item.Instance = inst.Instance
		item.PeerZone = inst.PeerZone
		item.GroupID = inst.GroupID
		item.InterfaceName = firstNonEmpty(sample.InterfaceName, target.InterfaceName, inst.InterfaceName)
		item.Endpoint = inst.Endpoint
		item.ActualState = inst.ActualState
	}
	if desired.InstanceID != "" {
		item.Desired = desired.Desired
		if item.PeerZone == nil {
			item.PeerZone = desired.PeerZone
		}
		if item.GroupID == "" {
			item.GroupID = desired.GroupID
		}
		if item.InterfaceName == "" {
			item.InterfaceName = firstNonEmpty(sample.InterfaceName, desired.InterfaceName)
		}
		item.LocalTunnelAddr = desired.LocalTunnelAddr
		item.PeerTunnelAddr = desired.PeerTunnelAddr
	}
	if item.InterfaceName == "" && sample.InterfaceName != "" {
		item.InterfaceName = sample.InterfaceName
	}
	return item
}

func healthProbeID(probeID, instanceID string) string {
	if probeID != "" {
		return probeID
	}
	return instanceID
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
