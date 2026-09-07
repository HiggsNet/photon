package text

import (
	"fmt"
	"io"
	"strings"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteStatus(w io.Writer, view inspect.StatusView) error {
	out := newLineWriter(w)
	daemon := "offline"
	if view.DaemonOnline {
		daemon = "online"
	}
	out.Linef("Photon status:")
	out.Linef("  daemon: %s", daemon)
	out.Linef("  gossip_source: %s", dash(view.GossipSource))
	out.Linef("  platform_source: %s", dash(view.PlatformSource))
	out.Linef("  zone: %s", dash(string(view.ManagedZone)))
	out.Linef("  mode: %s", view.Mode)
	if view.Mode == inspect.StatusModeAutoJoin {
		writeAutoJoinStatus(out, view)
	} else if view.Mode == inspect.StatusModeRunning {
		writeRunningStatus(out, view)
	}
	return out.Err()
}

func writeAutoJoinStatus(out *lineWriter, view inspect.StatusView) {
	d := view.Admission
	out.Linef("Auto-join:")
	out.Linef("  stage: %s", view.AutoJoinStage)
	out.Linef("  reason: %s", dash(d.Reason))
	out.LineIf(d.ReasonDetail != "", "  detail: %s", d.ReasonDetail)
	out.Linef("  parent_zone: %s", dash(string(d.ParentZone)))
	out.Linef("  last_bootstrap_sync: %s", formatUnixTime(d.LastBootstrapSyncUnix))
	out.Linef("  join_request: %s", dash(d.JoinRequestB64))
	if d.JoinRequestB64 != "" {
		out.Linef("  next: photon gossip delegate issue <request> (on parent zone admin)")
	}
}

func writeRunningStatus(out *lineWriter, view inspect.StatusView) {
	out.Linef("Gossip:")
	out.Linef("  peers: %d", view.Peers.Total)
	out.Linef("  states: %s", formatStatusCounts(view.Peers.States))
	out.Linef("  last_sync: %s", formatUnixTime(view.Peers.LastSync))
	out.Linef("Links:")
	out.Linef("  desired: %d", view.Links.Desired)
	out.Linef("  total: %d", view.Links.Total)
	out.Linef("  up: %d", view.Links.Up)
	out.Linef("  states: %s", formatStatusCounts(view.Links.States))
	out.Linef("  health: %s", formatStatusCounts(view.Links.Health))
	out.LineIf(view.Links.LastError != "", "  last_error: %s", view.Links.LastError)
}

func formatStatusCounts(counts []inspect.StatusCount) string {
	if len(counts) == 0 {
		return "-"
	}
	items := make([]string, 0, len(counts))
	for _, count := range counts {
		items = append(items, fmt.Sprintf("%s=%d", count.State, count.Count))
	}
	return strings.Join(items, ", ")
}
