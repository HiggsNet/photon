package health

import (
	"fmt"
	"io"
	"sort"
	"strconv"
	"strings"
)

// MetricsSnapshot is a transport-neutral OpenMetrics snapshot.
type MetricsSnapshot struct {
	Samples []MetricSample
}

type MetricSample struct {
	Name   string
	Value  float64
	Labels MetricsLabels
}

// CollectMetrics converts current link health into gauges. Packet metrics are
// rolling-window values, not monotonic process counters.
func CollectMetrics(healths []LinkHealth) MetricsSnapshot {
	snapshot := MetricsSnapshot{}
	for _, link := range healths {
		labels := link.Labels
		if link.LastRTT > 0 {
			snapshot.Samples = append(snapshot.Samples, MetricSample{Name: "photon_link_probe_rtt_seconds", Value: link.LastRTT.Seconds(), Labels: labels})
		}
		if link.Sent > 0 {
			snapshot.Samples = append(snapshot.Samples,
				MetricSample{Name: "photon_link_probe_packets_sent", Value: float64(link.Sent), Labels: labels},
				MetricSample{Name: "photon_link_probe_packets_received", Value: float64(link.Received), Labels: labels},
				MetricSample{Name: "photon_link_probe_packets_lost", Value: float64(link.Lost), Labels: labels},
				MetricSample{Name: "photon_link_probe_loss_ratio", Value: link.LossRatio, Labels: labels},
			)
		}
		if link.Jitter > 0 {
			snapshot.Samples = append(snapshot.Samples, MetricSample{Name: "photon_link_probe_jitter_seconds", Value: link.Jitter.Seconds(), Labels: labels})
		}
		snapshot.Samples = append(snapshot.Samples, MetricSample{Name: "photon_link_health_state", Value: healthStateValue(link.State), Labels: labels})
		if large := link.LargeProbe; large != nil {
			snapshot.Samples = append(snapshot.Samples, MetricSample{Name: "photon_link_large_probe_packet_size_bytes", Value: float64(large.PacketSize), Labels: labels})
			if large.Sent > 0 {
				snapshot.Samples = append(snapshot.Samples,
					MetricSample{Name: "photon_link_large_probe_packets_sent", Value: float64(large.Sent), Labels: labels},
					MetricSample{Name: "photon_link_large_probe_packets_received", Value: float64(large.Received), Labels: labels},
					MetricSample{Name: "photon_link_large_probe_packets_lost", Value: float64(large.Lost), Labels: labels},
					MetricSample{Name: "photon_link_large_probe_loss_ratio", Value: large.LossRatio, Labels: labels},
				)
			}
			if large.LastRTT > 0 {
				snapshot.Samples = append(snapshot.Samples, MetricSample{Name: "photon_link_large_probe_rtt_seconds", Value: large.LastRTT.Seconds(), Labels: labels})
			}
		}
	}
	return snapshot
}

// RenderOpenMetrics writes an OpenMetrics 1.0 text response. errorsTotal is
// keyed by ProbeID (or InstanceID when ProbeID is empty).
func RenderOpenMetrics(w io.Writer, snapshot MetricsSnapshot, errorsTotal map[string]int) error {
	byName := make(map[string][]MetricSample)
	for _, sample := range snapshot.Samples {
		byName[sample.Name] = append(byName[sample.Name], sample)
	}
	names := make([]string, 0, len(byName))
	for name := range byName {
		names = append(names, name)
	}
	sort.Strings(names)

	var output strings.Builder
	for _, name := range names {
		help, metricType := healthMetricMeta(name)
		fmt.Fprintf(&output, "# HELP %s %s\n# TYPE %s %s\n", name, help, name, metricType)
		for _, sample := range byName[name] {
			output.WriteString(name)
			writeHealthMetricLabels(&output, sample.Labels)
			fmt.Fprintf(&output, " %s\n", strconv.FormatFloat(sample.Value, 'g', -1, 64))
		}
	}
	output.WriteString("# HELP photon_link_probe_errors_total Total health probe execution errors per link.\n")
	output.WriteString("# TYPE photon_link_probe_errors_total counter\n")
	for _, sample := range byName["photon_link_health_state"] {
		key := sample.Labels.ProbeID
		if key == "" {
			key = sample.Labels.InstanceID
		}
		if total := errorsTotal[key]; total > 0 {
			output.WriteString("photon_link_probe_errors_total")
			writeHealthMetricLabels(&output, sample.Labels)
			fmt.Fprintf(&output, " %d\n", total)
		}
	}
	output.WriteString("# EOF\n")
	_, err := io.WriteString(w, output.String())
	return err
}

func healthMetricMeta(name string) (string, string) {
	switch name {
	case "photon_link_large_probe_packet_size_bytes":
		return "Configured large probe inner IP packet size, including IP and ICMP headers.", "gauge"
	case "photon_link_large_probe_packets_sent":
		return "Large ICMP packets sent in the separate rolling sample window.", "gauge"
	case "photon_link_large_probe_packets_received":
		return "Large ICMP replies received in the separate rolling sample window.", "gauge"
	case "photon_link_large_probe_packets_lost":
		return "Large ICMP packets lost in the separate rolling sample window.", "gauge"
	case "photon_link_large_probe_loss_ratio":
		return "Round-trip packet loss ratio in the large probe sample window.", "gauge"
	case "photon_link_large_probe_rtt_seconds":
		return "Last large probe RTT, omitted when the latest probe had no reply.", "gauge"
	case "photon_link_probe_rtt_seconds":
		return "Last successful reply RTT from the latest probe burst.", "gauge"
	case "photon_link_probe_packets_sent":
		return "ICMP packets sent in the rolling probe-burst window.", "gauge"
	case "photon_link_probe_packets_received":
		return "ICMP replies received in the rolling probe-burst window.", "gauge"
	case "photon_link_probe_packets_lost":
		return "ICMP packets lost in the rolling probe-burst window.", "gauge"
	case "photon_link_probe_loss_ratio":
		return "Packet loss ratio in the rolling probe-burst window.", "gauge"
	case "photon_link_probe_jitter_seconds":
		return "Mean absolute RTT delta between consecutive replied bursts.", "gauge"
	case "photon_link_health_state":
		return "Link health state (0=healthy,1=degraded,2=down,3=unknown,4=probe_error,5=suppressed).", "gauge"
	default:
		return "Photon link health metric.", "gauge"
	}
}

func healthStateValue(state string) float64 {
	switch state {
	case HealthStateHealthy:
		return 0
	case HealthStateDegraded:
		return 1
	case HealthStateDown:
		return 2
	case HealthStateProbeError:
		return 4
	case HealthStateSuppressed:
		return 5
	default:
		return 3
	}
}

func writeHealthMetricLabels(output *strings.Builder, labels MetricsLabels) {
	values := [][2]string{
		{"local_zone", labels.LocalZone},
		{"peer_zone", labels.PeerZone},
		{"overlay", labels.Overlay},
		{"probe_id", labels.ProbeID},
		{"instance_id", labels.InstanceID},
		{"netns", labels.NetNS},
		{"generation", labels.Generation},
		{"probe_role", labels.ProbeRole},
		{"probe_type", labels.ProbeType},
		{"reason", labels.Reason},
	}
	first := true
	output.WriteByte('{')
	for _, value := range values {
		if value[1] == "" {
			continue
		}
		if !first {
			output.WriteByte(',')
		}
		first = false
		fmt.Fprintf(output, "%s=%q", value[0], escapeHealthMetricLabel(value[1]))
	}
	output.WriteByte('}')
}

func escapeHealthMetricLabel(value string) string {
	value = strings.ReplaceAll(value, `\`, `\\`)
	value = strings.ReplaceAll(value, `"`, `\"`)
	return strings.ReplaceAll(value, "\n", `\n`)
}
