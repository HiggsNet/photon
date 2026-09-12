package inspect

import "sort"

const (
	HealthSortPeer = "peer"
	HealthSortRTT  = "rtt"
)

// HealthView is the canonical read model shared by control, text and HTTP
// presentation layers. Targets describe what should be probed; Samples are the
// current in-memory observations and may be absent for a target that has not
// completed a probe yet.
type HealthView struct {
	Targets []HealthTarget `json:"targets"`
	Samples []HealthSample `json:"samples"`
}

type HealthTarget struct {
	ProbeID         string `json:"probe_id,omitempty"`
	InstanceID      string `json:"instance_id"`
	GroupID         string `json:"group_id,omitempty"`
	PeerZone        string `json:"peer_zone,omitempty"`
	LocalZone       string `json:"local_zone,omitempty"`
	Overlay         string `json:"overlay,omitempty"`
	NetNS           string `json:"netns,omitempty"`
	InterfaceName   string `json:"interface_name,omitempty"`
	UnderlayFamily  string `json:"underlay_family,omitempty"`
	LocalTunnelAddr string `json:"local_tunnel_addr,omitempty"`
	PeerTunnelAddr  string `json:"peer_tunnel_addr,omitempty"`
	Generation      uint64 `json:"generation,omitempty"`
	ProbeRole       string `json:"probe_role,omitempty"`
	Role            string `json:"role,omitempty"`
	State           string `json:"state,omitempty"`
	Staged          bool   `json:"staged,omitempty"`
}

type HealthSample struct {
	ProbeID         string `json:"probe_id,omitempty"`
	InstanceID      string `json:"instance_id"`
	ProbeRole       string `json:"probe_role,omitempty"`
	InterfaceName   string `json:"interface_name,omitempty"`
	State           string `json:"state"`
	ProbeType       string `json:"probe_type"`
	Sent            int    `json:"sent"`
	Received        int    `json:"received"`
	Lost            int    `json:"lost"`
	LossRatio       int    `json:"loss_ratio_pct"`
	LastRTTMs       int64  `json:"last_rtt_ms"`
	EWMARTTMs       int64  `json:"ewma_rtt_ms"`
	P50RTTMs        int64  `json:"p50_rtt_ms"`
	P95RTTMs        int64  `json:"p95_rtt_ms"`
	P99RTTMs        int64  `json:"p99_rtt_ms"`
	JitterMs        int64  `json:"jitter_ms"`
	ConsecutiveFail int    `json:"consecutive_fail"`
	LastError       string `json:"last_error,omitempty"`
	NextProbeUnix   int64  `json:"next_probe_unix,omitempty"`
	CutoverBlocking bool   `json:"cutover_blocking,omitempty"`
}

func BuildHealthView(view HealthView, sortBy string) HealthView {
	out := view
	out.Targets = append([]HealthTarget(nil), view.Targets...)
	out.Samples = append([]HealthSample(nil), view.Samples...)
	samplesByProbe := make(map[string]HealthSample, len(out.Samples))
	for _, sample := range out.Samples {
		key := sample.ProbeID
		if key == "" {
			key = sample.InstanceID
		}
		samplesByProbe[key] = sample
	}
	sort.SliceStable(out.Targets, func(i, j int) bool {
		left, right := out.Targets[i], out.Targets[j]
		if sortBy == HealthSortRTT {
			leftRTT, leftOK := healthSortRTT(samplesByProbe[healthTargetProbeID(left)])
			rightRTT, rightOK := healthSortRTT(samplesByProbe[healthTargetProbeID(right)])
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
		if left.InstanceID != right.InstanceID {
			return left.InstanceID < right.InstanceID
		}
		if left.ProbeRole != right.ProbeRole {
			return left.ProbeRole < right.ProbeRole
		}
		return left.ProbeID < right.ProbeID
	})
	return out
}

func healthTargetProbeID(target HealthTarget) string {
	if target.ProbeID != "" {
		return target.ProbeID
	}
	return target.InstanceID
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
