package inspect

import (
	"sort"

	"github.com/HiggsNet/photon/pkg/health"
)

const (
	HealthSortPeer = "peer"
	HealthSortRTT  = "rtt"
)

// HealthInput joins desired probe targets, current samples and the safe link
// observations needed to explain each result. A target may not have completed
// its first probe yet, and an observed link may temporarily have no target.
type HealthInput struct {
	Targets   []health.ProbeTarget
	Samples   []HealthSample
	Instances map[string]LinkInstance
	Desired   map[string]DesiredLink
}

// HealthView is the canonical read model shared by control, text and HTTP.
// Links are keyed by probe rather than instance because rotation can keep
// active and staged probes for the same link at the same time.
type HealthView struct {
	Links []HealthLinkView `json:"links"`
}

type HealthLinkView struct {
	Health          HealthSample `json:"health"`
	Desired         *DesiredLink `json:"desired,omitempty"`
	PeerZone        string       `json:"peer_zone,omitempty"`
	GroupID         string       `json:"group_id,omitempty"`
	Overlay         string       `json:"overlay,omitempty"`
	UnderlayFamily  string       `json:"underlay_family,omitempty"`
	InterfaceName   string       `json:"interface_name,omitempty"`
	Endpoint        string       `json:"endpoint,omitempty"`
	ActualState     string       `json:"actual_state,omitempty"`
	LocalTunnelAddr string       `json:"local_tunnel_addr,omitempty"`
	PeerTunnelAddr  string       `json:"peer_tunnel_addr,omitempty"`
	Staged          bool         `json:"staged,omitempty"`
	Observed        bool         `json:"observed,omitempty"`
}

type HealthSample struct {
	ProbeID         string       `json:"probe_id,omitempty"`
	InstanceID      string       `json:"instance_id"`
	ProbeRole       string       `json:"probe_role,omitempty"`
	InterfaceName   string       `json:"interface_name,omitempty"`
	State           string       `json:"state"`
	ProbeType       string       `json:"probe_type"`
	Sent            int          `json:"sent"`
	Received        int          `json:"received"`
	Lost            int          `json:"lost"`
	LossRatio       int          `json:"loss_ratio_pct"`
	LastRTTMs       int64        `json:"last_rtt_ms"`
	EWMARTTMs       int64        `json:"ewma_rtt_ms"`
	P50RTTMs        int64        `json:"p50_rtt_ms"`
	P95RTTMs        int64        `json:"p95_rtt_ms"`
	P99RTTMs        int64        `json:"p99_rtt_ms"`
	JitterMs        int64        `json:"jitter_ms"`
	ConsecutiveFail int          `json:"consecutive_fail"`
	LastFailure     *FailureView `json:"last_failure,omitempty"`
	NextProbeUnix   int64        `json:"next_probe_unix,omitempty"`
	CutoverBlocking bool         `json:"cutover_blocking,omitempty"`
}

func BuildHealthView(input HealthInput) HealthView {
	targetsByProbe := make(map[string]health.ProbeTarget, len(input.Targets))
	for _, target := range input.Targets {
		targetsByProbe[healthProbeID(target.ProbeID, target.InstanceID)] = target
	}
	coveredProbes := make(map[string]bool, len(input.Samples))
	coveredInstances := make(map[string]bool, len(input.Samples)+len(input.Targets))
	links := make([]HealthLinkView, 0, len(input.Samples)+len(input.Targets)+len(input.Instances))
	for _, sample := range input.Samples {
		if sample.InstanceID == "" {
			continue
		}
		probeID := healthProbeID(sample.ProbeID, sample.InstanceID)
		target := targetsByProbe[probeID]
		coveredProbes[probeID] = true
		coveredInstances[sample.InstanceID] = true
		links = append(links, buildHealthLinkView(sample, target, input.Instances[sample.InstanceID], input.Desired[sample.InstanceID], true))
	}
	for _, target := range input.Targets {
		probeID := healthProbeID(target.ProbeID, target.InstanceID)
		if target.InstanceID == "" || coveredProbes[probeID] {
			continue
		}
		coveredInstances[target.InstanceID] = true
		sample := HealthSample{
			ProbeID: target.ProbeID, InstanceID: target.InstanceID,
			ProbeRole: target.ProbeRole, InterfaceName: target.InterfaceName, State: "unknown",
		}
		links = append(links, buildHealthLinkView(sample, target, input.Instances[target.InstanceID], input.Desired[target.InstanceID], false))
	}
	ids := make([]string, 0, len(input.Instances))
	for id := range input.Instances {
		if !coveredInstances[id] {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	for _, id := range ids {
		sample := HealthSample{InstanceID: id, State: "unknown"}
		links = append(links, buildHealthLinkView(sample, health.ProbeTarget{}, input.Instances[id], input.Desired[id], false))
	}
	sort.SliceStable(links, func(i, j int) bool {
		if links[i].Health.InstanceID != links[j].Health.InstanceID {
			return links[i].Health.InstanceID < links[j].Health.InstanceID
		}
		if links[i].Health.ProbeRole != links[j].Health.ProbeRole {
			return links[i].Health.ProbeRole < links[j].Health.ProbeRole
		}
		return links[i].Health.ProbeID < links[j].Health.ProbeID
	})
	return HealthView{Links: links}
}

func SortHealthView(view HealthView, sortBy string) HealthView {
	out := HealthView{Links: append([]HealthLinkView(nil), view.Links...)}
	sort.SliceStable(out.Links, func(i, j int) bool {
		left, right := out.Links[i], out.Links[j]
		if sortBy == HealthSortRTT {
			leftRTT, leftOK := healthSortRTT(left.Health)
			rightRTT, rightOK := healthSortRTT(right.Health)
			if leftOK != rightOK {
				return leftOK
			}
			if leftOK && leftRTT != rightRTT {
				return leftRTT < rightRTT
			}
		}
		if left.PeerZone != right.PeerZone {
			return ZonePathLess(right.PeerZone, left.PeerZone)
		}
		if left.Health.InstanceID != right.Health.InstanceID {
			return left.Health.InstanceID < right.Health.InstanceID
		}
		if left.Health.ProbeRole != right.Health.ProbeRole {
			return left.Health.ProbeRole < right.Health.ProbeRole
		}
		return left.Health.ProbeID < right.Health.ProbeID
	})
	return out
}

func buildHealthLinkView(sample HealthSample, target health.ProbeTarget, inst LinkInstance, desired DesiredLink, observed bool) HealthLinkView {
	item := HealthLinkView{
		Health:          sample,
		GroupID:         target.GroupID,
		Overlay:         target.Overlay,
		UnderlayFamily:  target.UnderlayFamily,
		InterfaceName:   firstNonEmpty(sample.InterfaceName, target.InterfaceName),
		ActualState:     target.State,
		LocalTunnelAddr: FormatAddr(target.LocalTunnelAddr),
		PeerTunnelAddr:  FormatAddr(target.PeerTunnelAddr),
		Staged:          target.Staged || target.ProbeRole == "staged",
		Observed:        observed,
	}
	if target.PeerZone != "" {
		item.PeerZone = target.PeerZone
	}
	if inst.ID != "" {
		item.PeerZone = inst.PeerZone
		item.GroupID = inst.GroupID
		item.InterfaceName = firstNonEmpty(sample.InterfaceName, target.InterfaceName, inst.InterfaceName)
		item.Endpoint = inst.Endpoint
		item.ActualState = inst.ActualState
	}
	if desired.InstanceID != "" {
		item.Desired = &desired
		if item.PeerZone == "" {
			item.PeerZone = string(desired.PeerZone)
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
	return item
}

func healthProbeID(probeID, instanceID string) string {
	if probeID != "" {
		return probeID
	}
	return instanceID
}

func healthSortRTT(sample HealthSample) (int64, bool) {
	if sample.EWMARTTMs > 0 {
		return sample.EWMARTTMs, true
	}
	if sample.LastRTTMs > 0 {
		return sample.LastRTTMs, true
	}
	return 0, false
}
