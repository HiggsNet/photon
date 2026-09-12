package inspect

import (
	"sort"

	"github.com/HiggsNet/photon/pkg/health"
)

const (
	HealthSortPeer = "peer"
	HealthSortRTT  = "rtt"
)

// HealthView is the canonical read model shared by control, text and HTTP
// presentation layers. Targets describe what should be probed; Samples are the
// current in-memory observations and may be absent for a target that has not
// completed a probe yet.
type HealthView struct {
	Targets []health.ProbeTarget `json:"targets"`
	Samples []HealthSample       `json:"samples"`
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

func BuildHealthView(view HealthView, sortBy string) HealthView {
	out := view
	out.Targets = append([]health.ProbeTarget(nil), view.Targets...)
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

func healthTargetProbeID(target health.ProbeTarget) string {
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
