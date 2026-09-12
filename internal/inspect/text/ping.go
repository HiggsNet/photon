package text

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WritePingDebug(w io.Writer, view inspect.PingDebugView) error {
	view = inspect.BuildPingDebugView(view)
	out := newLineWriter(w)
	out.Linef("zone: %s", view.Zone)
	out.Linef("targets: %d", len(view.Targets))
	if len(view.Targets) == 0 {
		out.Linef("no IPsec link instances for zone %s", view.Zone)
		out.LineIf(len(view.AvailableZones) > 0, "available peer zones: %s", strings.Join(view.AvailableZones, ", "))
		return out.Err()
	}
	out.Linef("count: %d timeout: %s", view.Count, view.Timeout)
	out.Blank()
	for i, instance := range view.Instances {
		if i > 0 {
			out.Blank()
		}
		out.Linef("instance %s", instance.InstanceID)
		for _, row := range instance.Rows {
			out.Linef("  role=%s underlay=%s tunnel=%s", inspect.PingTargetRole(row), row.Family, dash(row.TunnelFamily))
			if row.NetNS != "" {
				out.Linef("    interface: %s  netns: %s", dash(row.Interface), row.NetNS)
			} else {
				out.Linef("    interface: %s", dash(row.Interface))
			}
			out.Linef("    local: %s  peer: %s", dash(row.LocalTunnel), dash(row.PeerTunnel))
			out.Linef("    result: %s", formatPingResult(row))
		}
	}
	return out.Err()
}

func formatPingResult(target inspect.PingTargetView) string {
	if target.Success {
		if target.RTT > 0 {
			return fmt.Sprintf("ok rtt=%s", target.RTT.Round(time.Microsecond))
		}
		return "ok"
	}
	if target.Failure != nil {
		return fmt.Sprintf("fail %s", failureDisplay(target.Failure))
	}
	return "fail"
}
