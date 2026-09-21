package text

import (
	"io"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteRotateDebug(w io.Writer, view inspect.RotateDebugView) error {
	out := newLineWriter(w)
	out.Linef("last_run: %s", formatRotateUnixTime(view.LastRunUnix))
	out.Linef("last_failure: %s", failureDisplay(view.LastFailure))
	out.Linef("link_instances: %d", view.LinkInstances)
	out.Linef("planned_desired_links: %d", view.PlannedDesired)
	if view.ReplanIgnored {
		out.Linef("planned_desired_status: ignored_partial last_reconcile_desired=%d", view.LastDesiredLinks)
	}
	out.Linef("desired_source: %s", dash(view.DesiredPlanSource))
	if view.Filter != "" {
		out.Linef("filter: %s", view.Filter)
		out.Linef("matched_links: %d", len(view.Links))
	}
	out.Linef("%s: %d", view.StoredLabel, view.ReconcileSACount)
	out.Linef("%s: %d", view.LiveLabel, view.LiveSACount)
	out.LineIf(view.LiveSAError != "", "live_sa_error: %s", view.LiveSAError)
	for _, link := range view.Links {
		writeRotateLink(out, link)
	}
	return out.Err()
}

func WriteManualPortRotateResult(w io.Writer, mode string, view inspect.ManualPortRotateView) error {
	out := newLineWriter(w)
	out.Linef("mode: %s", mode)
	out.Linef("zone: %s", view.Zone)
	out.Linef("previous_generation: %d", view.PreviousGeneration)
	out.Linef("current_generation: %d", view.CurrentGeneration)
	if view.PreviousGeneration > 0 {
		out.Linef("previous_ike: %d", view.PreviousIKE)
		out.Linef("previous_natt: %d", view.PreviousNATT)
		out.Linef("previous_valid_until: %d", view.PreviousValidUntil)
	}
	out.Linef("current_ike: %d", view.CurrentIKE)
	out.Linef("current_natt: %d", view.CurrentNATT)
	return out.Err()
}

func writeRotateLink(out *lineWriter, item inspect.RotateDebugLink) {
	link := item.Link
	out.Linef("")
	out.Linef("link %s", link.ID)
	out.Linef("  peer: %s", link.PeerZone)
	out.Linef("  group: %s", dash(link.GroupID))
	out.Linef("  link_id: %s", dash(link.LinkID))
	out.Linef("  path_key: %s", dash(link.PathKey))
	out.Linef("  rotate:")
	out.Linef("    phase: %s", dash(link.Rotation.Phase))
	out.Linef("    port_generation select/runtime/staged: %s", item.PortGenerationSummary)
	out.Linef("    port local/remote/runtime/staged: %s", item.PortSummary)
	out.Linef("    deadline: %s", formatRotateUnixTime(link.Rotation.RotateDeadline))
	out.Linef("    last_failure: %s", failureDisplay(link.LastFailure))
	rows := [][]string{{"ROLE", "STATE", "PORT", "RUNTIME", "CHILD_SA", "INTERFACE", "ENDPOINT"}}
	rows = append(rows, rotateRuntimeRow("current", item.Current))
	if item.HasStaged {
		rows = append(rows, rotateRuntimeRow("staged", item.Staged))
	} else {
		rows = append(rows, []string{"staged", "absent", "-", "-", "-", "-", "-"})
	}
	writeDebugTable(out, rows)
	tunnels := [][]string{{"ROLE", "LOCAL_TUNNEL", "PEER_TUNNEL"}, {"current", dash(item.Current.LocalTunnelAddr), dash(item.Current.PeerTunnelAddr)}}
	if item.HasStaged {
		tunnels = append(tunnels, []string{"staged", dash(item.Staged.LocalTunnelAddr), dash(item.Staged.PeerTunnelAddr)})
	}
	writeDebugTable(out, tunnels)
	writeRotateSAs(out, "reconcile_matching_sas", item.ReconcileMatchingSAs)
	writeRotateSAs(out, "live_matching_sas", item.LiveMatchingSAs)
}

func rotateRuntimeRow(role string, runtime inspect.RotateRuntimeView) []string {
	return []string{role, dash(runtime.State), dash(runtime.Port), dash(runtime.RuntimeID), dash(runtime.ChildSAName), formatInterfaceWithIfID(runtime.InterfaceName, runtime.XFRMIfID), dash(runtime.Endpoint)}
}

func writeRotateSAs(out *lineWriter, label string, sas []inspect.LinkSA) {
	out.Linef("  %s: %d", label, len(sas))
	if len(sas) == 0 {
		return
	}
	rows := [][]string{{"NAME", "CHILD", "STATE", "IF_ID", "REQID", "LOCAL", "REMOTE", "LOCAL_IDENTITY", "REMOTE_IDENTITY"}}
	for _, sa := range sas {
		rows = append(rows, []string{dash(sa.Name), dash(sa.ChildSA), formatSAState(sa), formatUint32OrDash(sa.XFRMIfID), formatUint32OrDash(sa.ReqID), dash(sa.LocalEndpoint), dash(firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint)), dash(sa.LocalIdentity), dash(sa.RemoteIdentity)})
	}
	writeDebugTable(out, rows)
}

func formatRotateUnixTime(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}
