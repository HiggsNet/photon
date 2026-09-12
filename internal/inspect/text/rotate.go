package text

import (
	"io"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteRotateDebug(w io.Writer, view inspect.RotateDebugView) error {
	out := newLineWriter(w)
	out.Linef("last_run: %s", formatRotateUnixTime(view.LastRunUnix))
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
	out.Linef("%s: %d", view.StoredLabel, view.StoredSACount)
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
	writeRotateRuntime(out, "current", item.Current)
	if item.HasStaged {
		writeRotateRuntime(out, "staged", item.Staged)
	} else {
		out.Linef("  staged:")
		out.Linef("    state: absent")
	}
	writeRotateSAs(out, "stored_matching_sas", item.StoredMatchingSAs)
	writeRotateSAs(out, "live_matching_sas", item.LiveMatchingSAs)
}

func writeRotateRuntime(out *lineWriter, label string, runtime inspect.RotateRuntimeView) {
	out.Linef("  %s:", label)
	out.Linef("    state: %s", dash(runtime.State))
	out.Linef("    port: %s", dash(runtime.Port))
	out.Linef("    runtime_id: %s", dash(runtime.RuntimeID))
	out.Linef("    child_sa: %s", dash(runtime.ChildSAName))
	out.Linef("    interface: %s", formatInterfaceWithIfID(runtime.InterfaceName, runtime.XFRMIfID))
	out.Linef("    endpoint: %s", dash(runtime.Endpoint))
	out.Linef("    local_tunnel: %s", dash(runtime.LocalTunnelAddr))
	out.Linef("    peer_tunnel: %s", dash(runtime.PeerTunnelAddr))
}

func writeRotateSAs(out *lineWriter, label string, sas []inspect.LinkSA) {
	out.Linef("  %s: %d", label, len(sas))
	for _, sa := range sas {
		out.Linef("    - name=%s child=%s state=%s if_id=%s reqid=%s local=%s remote=%s identities=%s/%s",
			dash(sa.Name),
			dash(sa.ChildSA),
			formatSAState(sa),
			formatUint32OrDash(sa.XFRMIfID),
			formatUint32OrDash(sa.ReqID),
			dash(sa.LocalEndpoint),
			dash(firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint)),
			dash(sa.LocalIdentity),
			dash(sa.RemoteIdentity),
		)
	}
}

func formatRotateUnixTime(unix int64) string {
	if unix == 0 {
		return "never"
	}
	return time.Unix(unix, 0).UTC().Format(time.RFC3339)
}
