package text

import (
	"fmt"
	"io"
	"text/tabwriter"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteHealth(w io.Writer, view inspect.HealthView, sortBy string, verbose bool) error {
	view = inspect.BuildHealthView(view, sortBy)
	if w == nil {
		return nil
	}
	targets := view.Targets
	if len(targets) == 0 {
		out := newLineWriter(w)
		out.Println("No link instances to probe.")
		return out.Err()
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	samplesByProbe := make(map[string]inspect.HealthSample, len(view.Samples))
	for _, sample := range view.Samples {
		key := firstNonEmpty(sample.ProbeID, sample.InstanceID)
		samplesByProbe[key] = sample
	}
	out.Linef("Link health (%d links):", len(targets))
	if !verbose {
		rows := [][]string{{"PEER", "ROLE", "FAMILY", "HEALTH", "LOSS", "RTT", "JITTER", "CUTOVER"}}
		for _, t := range targets {
			probeID := firstNonEmpty(t.ProbeID, t.InstanceID)
			sample, hasSample := samplesByProbe[probeID]
			rows = append(rows, []string{
				dash(t.PeerZone),
				firstNonEmpty(t.ProbeRole, "active"),
				dash(t.UnderlayFamily),
				healthSampleState(sample, hasSample),
				healthLoss(sample, hasSample),
				healthPrimaryRTT(sample, hasSample),
				healthMillis(sample.JitterMs, hasSample),
				healthCutover(sample, hasSample, t.Staged || t.ProbeRole == "staged"),
			})
		}
		writeAlignedRows(out, rows, 0)
		if err := out.Err(); err != nil {
			return err
		}
		return table.Flush()
	}
	rows := [][]string{{"LINK", "PROBE ID", "PEER", "OVERLAY", "ROLE", "FAMILY", "INTERFACE", "LOCAL->PEER", "LINK STATE", "HEALTH", "PROBE", "PACKETS", "LOSS", "RTT (LAST/EWMA/P50/P95/P99)", "JITTER", "FAILS", "CUTOVER", "ERROR"}}
	for _, t := range targets {
		probeID := firstNonEmpty(t.ProbeID, t.InstanceID)
		sample, hasSample := samplesByProbe[probeID]
		rows = append(rows, []string{
			t.InstanceID,
			probeID,
			dash(t.PeerZone),
			dash(t.Overlay),
			firstNonEmpty(t.ProbeRole, "active"),
			dash(t.UnderlayFamily),
			dash(t.InterfaceName),
			formatHealthTunnel(t.LocalTunnelAddr, t.PeerTunnelAddr),
			dash(t.State),
			healthSampleState(sample, hasSample),
			dash(sample.ProbeType),
			healthPackets(sample, hasSample),
			healthLoss(sample, hasSample),
			healthRTT(sample, hasSample),
			healthMillis(sample.JitterMs, hasSample),
			healthFailures(sample, hasSample),
			healthCutover(sample, hasSample, t.Staged || t.ProbeRole == "staged"),
			escapeTableCell(failureDisplay(sample.LastFailure)),
		})
	}
	writeAlignedRows(out, rows, 2)
	if err := out.Err(); err != nil {
		return err
	}
	return table.Flush()
}

func formatHealthTunnel(local, peer string) string {
	if local == "" && peer == "" {
		return "-"
	}
	return dash(local) + "->" + dash(peer)
}

func healthSampleState(sample inspect.HealthSample, ok bool) string {
	if !ok {
		return "-"
	}
	return dash(sample.State)
}

func healthPackets(sample inspect.HealthSample, ok bool) string {
	if !ok || sample.Sent == 0 {
		return "-"
	}
	return fmt.Sprintf("%d/%d/%d", sample.Sent, sample.Received, sample.Lost)
}

func healthLoss(sample inspect.HealthSample, ok bool) string {
	if !ok || sample.Sent == 0 {
		return "-"
	}
	return fmt.Sprintf("%d%%", sample.LossRatio)
}

func healthRTT(sample inspect.HealthSample, ok bool) string {
	if !ok || (sample.LastRTTMs == 0 && sample.EWMARTTMs == 0 && sample.P95RTTMs == 0) {
		return "-"
	}
	return fmt.Sprintf("%d/%d/%d/%d/%dms", sample.LastRTTMs, sample.EWMARTTMs, sample.P50RTTMs, sample.P95RTTMs, sample.P99RTTMs)
}

func healthPrimaryRTT(sample inspect.HealthSample, ok bool) string {
	if !ok {
		return "-"
	}
	if sample.EWMARTTMs > 0 {
		return fmt.Sprintf("%dms", sample.EWMARTTMs)
	}
	if sample.LastRTTMs > 0 {
		return fmt.Sprintf("%dms", sample.LastRTTMs)
	}
	return "-"
}

func healthMillis(value int64, ok bool) string {
	if !ok || value == 0 {
		return "-"
	}
	return fmt.Sprintf("%dms", value)
}

func healthFailures(sample inspect.HealthSample, ok bool) string {
	if !ok {
		return "-"
	}
	return fmt.Sprintf("%d", sample.ConsecutiveFail)
}

func healthCutover(sample inspect.HealthSample, ok, staged bool) string {
	if !ok {
		return "-"
	}
	if sample.CutoverBlocking {
		return "blocked"
	}
	if staged {
		return "ready"
	}
	return "-"
}

func firstNonEmpty(values ...string) string {
	for _, value := range values {
		if value != "" {
			return value
		}
	}
	return ""
}
