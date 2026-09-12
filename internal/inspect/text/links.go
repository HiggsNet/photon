package text

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"github.com/HiggsNet/photon/internal/inspect"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func WriteLinks(w io.Writer, inspection inspect.LinkInspection, filter string, verbose bool) error {
	links := inspect.FilterLinkViews(inspection.Links, filter)
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	out.Linef("links: %s", filteredCount(len(links), len(inspection.Links), filter))
	out.Linef("desired: %d  actual_sas: %d  actions: %d  skipped: %d",
		inspection.Summary.DesiredLinks,
		inspection.Summary.ActualSAs,
		len(inspect.FilterLinkActions(inspection.Actions, filter)),
		len(inspect.FilterLinkSkips(inspection.Skipped, filter)),
	)
	if failure := inspection.Summary.LastFailure; failure != nil {
		out.Linef("last_failure: %s", escapeTableCell(failureDisplay(failure)))
	}
	rows := make([][]string, 0, len(links)+1)
	if verbose {
		rows = append(rows, []string{"LINK", "PEER", "GROUP", "PATH", "TRANSPORT", "STATE", "ENDPOINT", "INTERFACE", "TUNNEL", "SA", "HEALTH", "ROTATION", "ROUTING", "OWNER", "ERROR"})
	} else {
		rows = append(rows, []string{"LINK", "PEER", "TRANSPORT", "STATE", "ENDPOINT", "INTERFACE"})
	}
	for _, link := range links {
		if verbose {
			rows = append(rows, []string{
				link.ID,
				link.PeerZone,
				dash(link.GroupID),
				dash(link.PathKey),
				dash(link.TransportKind),
				linkDisplayState(link),
				dash(link.Endpoint),
				formatInterfaceWithIfID(link.InterfaceName, link.XFRMIfID),
				linkTunnelSummary(link),
				linkSASummary(link),
				linkHealthSummary(link),
				dash(link.Rotation.Phase),
				dash(link.Routing.BirdState),
				dash(link.Owner.Manager),
				escapeTableCell(failureMessage(link.LastFailure)),
			})
		} else {
			rows = append(rows, []string{
				link.ID,
				link.PeerZone,
				dash(link.TransportKind),
				linkDisplayState(link),
				dash(link.Endpoint),
				formatInterfaceWithIfID(link.InterfaceName, link.XFRMIfID),
			})
		}
	}
	writeAlignedRows(out, rows, 1)
	if err := out.Err(); err != nil {
		return err
	}
	return table.Flush()
}

func linkDisplayState(link inspect.LinkView) string {
	if link.Missing {
		return "missing"
	}
	return dash(firstNonEmpty(link.ActualState, link.State))
}

func linkTunnelSummary(link inspect.LinkView) string {
	if link.LocalTunnelAddr == "" && link.PeerTunnelAddr == "" {
		return "-"
	}
	return dash(link.LocalTunnelAddr) + "->" + dash(link.PeerTunnelAddr)
}

func linkSASummary(link inspect.LinkView) string {
	if link.ActualSA == nil {
		return dash(link.ChildSAName)
	}
	state := formatSAState(*link.ActualSA)
	name := firstNonEmpty(link.ActualSA.ChildSA, link.ChildSAName)
	if name == "" {
		return state
	}
	return name + ":" + state
}

func linkHealthSummary(link inspect.LinkView) string {
	if link.Health == nil {
		return "-"
	}
	if link.Health.LastFailure != nil {
		return defaultText(link.Health.State, "error") + ":" + escapeTableCell(failureDisplay(link.Health.LastFailure))
	}
	return defaultText(link.Health.State, "-")
}

func WriteLinksDebug(w io.Writer, view inspect.LinksDebugView) error {
	out := newLineWriter(w)
	inspection := view.Inspection
	inspection.Links = inspect.FilterLinkViews(inspection.Links, view.Filter)
	inspection.Actions = inspect.FilterLinkActions(inspection.Actions, view.Filter)
	inspection.Skipped = inspect.FilterLinkSkips(inspection.Skipped, view.Filter)
	out.LineIf(inspection.Summary.DesiredPlanError != "", "desired_plan_error: %s", inspection.Summary.DesiredPlanError)
	out.Linef("last_run: %s", formatUnixTime(inspection.Summary.LastRunUnix))
	out.Linef("desired_links: %d", inspection.Summary.DesiredLinks)
	out.Linef("planned_desired_links: %d", view.ReplannedDesired)
	out.LineIf(view.ReplanIgnored, "planned_desired_status: ignored_partial last_reconcile_desired=%d", view.LastDesiredLinks)
	out.Linef("desired_source: %s", dash(view.DesiredPlanSource))
	out.Linef("actual_sas: %d", inspection.Summary.ActualSAs)
	out.Linef("last_failure: %s", failureDisplay(inspection.Summary.LastFailure))
	out.Linef("link_instances: %d", inspection.Summary.LinkInstances)
	if strings.TrimSpace(view.Filter) != "" {
		out.Linef("filter: %s", view.Filter)
		out.Linef("matched_links: %d", len(inspection.Links))
	}
	for _, link := range inspection.Links {
		if link.Missing {
			writeDebugMissingLink(out, link, nil)
			continue
		}
		writeDebugLinkInstance(out, link, nil)
	}
	out.Linef("actions: %d", len(inspection.Actions))
	for _, action := range inspection.Actions {
		out.Linef("- action=%s instance=%s group=%s peer=%s sa_unique_id=%s reason=%s",
			action.Action,
			dash(action.InstanceID),
			dash(action.GroupID),
			action.PeerZone,
			formatUint64OrDash(action.SAUniqueID),
			dash(action.Reason),
		)
	}
	out.Linef("skipped: %d", len(inspection.Skipped))
	for _, skip := range inspection.Skipped {
		out.Linef("- group=%s peer=%s reason=%s detail=%s",
			dash(skip.GroupID),
			skip.Peer,
			dash(skip.Reason),
			dash(skip.Detail),
		)
	}
	return out.Err()
}

func writeDebugLinkInstance(out *lineWriter, link inspect.LinkView, spec *ipsec.TransportLinkSpec) {
	desired := inspect.DesiredLink{}
	if link.Desired != nil {
		desired = *link.Desired
	}
	sa := inspect.LinkSA{}
	if link.ActualSA != nil {
		sa = *link.ActualSA
	}
	out.Blank()
	out.Linef("link %s", link.ID)
	out.Linef("  peer: %s", link.PeerZone)
	out.Linef("  group: %s", dash(link.GroupID))
	out.Linef("  state: %s", dash(link.ActualState))
	out.Linef("  planner:")
	out.Linef("    link_id: %s", dash(firstNonEmpty(link.LinkID, desired.LinkID)))
	out.Linef("    path_key: %s", dash(firstNonEmpty(link.PathKey, desired.PathKey)))
	out.Linef("    runtime_id: %s", dash(firstNonEmpty(link.IKEName, link.TransportID, desired.TransportID)))
	out.Linef("    desired_hash: %s", dash(shortTextHash(desired.DesiredSpecHash)))
	out.Linef("    actual_hash: %s", dash(shortTextHash(link.DesiredSpecHash)))
	out.Linef("    endpoint: %s", dash(link.Endpoint))
	out.Linef("    local_tunnel: %s", dash(link.LocalTunnelAddr))
	out.Linef("    peer_tunnel: %s", dash(link.PeerTunnelAddr))
	out.Linef("  xfrm:")
	out.Linef("    interface: %s", formatInterfaceWithIfID(link.InterfaceName, link.XFRMIfID))
	out.Linef("  strongswan:")
	out.Linef("    child_sa: %s", dash(firstNonEmpty(sa.ChildSA, link.ChildSAName, specChildSAName(spec))))
	out.Linef("    sa_state: %s", formatSAState(sa))
	out.Linef("    local_endpoint: %s", dash(sa.LocalEndpoint))
	out.Linef("    remote_endpoint: %s", dash(firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint)))
	out.Linef("    local_identity: %s", dash(sa.LocalIdentity))
	out.Linef("    remote_identity: %s", dash(sa.RemoteIdentity))
	out.Linef("    reqid: %s", formatUint32OrDash(sa.ReqID))
	out.Linef("    observed_interface: %s", formatDerivedInterfaceWithIfID(sa.XFRMIfID))
	writeDebugStrongSwanConfig(out, spec)
	out.Linef("  rotation:")
	out.Linef("    phase: %s", dash(link.Rotation.Phase))
	out.Linef("    port_generation select/runtime/staged: %s", inspect.DebugPortGenerationSummary(spec, link.Rotation))
	out.Linef("    port local/remote/runtime/staged: %s", inspect.DebugPortSummary(spec, link.Endpoint, firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint), link.Rotation.StagedGeneration))
	out.Linef("    staged_ike: %s", dash(link.Rotation.StagedIKEName))
	out.Linef("    staged_interface: %s", formatInterfaceWithIfID(link.Rotation.StagedInterfaceName, link.Rotation.StagedXFRMIfID))
	out.Linef("    deadline: %s", formatUnixTime(link.Rotation.RotateDeadline))
	out.Linef("  takeover:")
	out.Linef("    initiator_role: %s", dash(link.Takeover.InitiatorRole))
	out.Linef("    phase: %s", dash(link.Takeover.Phase))
	out.Linef("    until: %s", formatUnixTime(link.Takeover.Until))
	out.Linef("    observed_initiator: %s", dash(link.Takeover.ObservedInitiator))
	out.Linef("  lifecycle:")
	out.Linef("    owner: %s", dash(link.Owner.Manager))
	out.Linef("    failures: %d", link.FailureCount)
	out.Linef("    backoff_until: %s", formatUnixTime(link.BackoffUntil))
	out.Linef("    last_failure: %s", failureDisplay(link.LastFailure))
	out.Linef("    takeover_failure: %s", failureDisplay(link.Takeover.LastFailure))
	out.Linef("  health:")
	if link.Health == nil {
		out.Linef("    state: unavailable")
	} else {
		health := link.Health
		out.Linef("    state: %s", dash(health.State))
		out.Linef("    probe_id: %s", dash(firstNonEmpty(health.ProbeID, health.InstanceID)))
		out.Linef("    role: %s", dash(firstNonEmpty(health.ProbeRole, "active")))
		out.Linef("    probe_type: %s", dash(health.ProbeType))
		out.Linef("    sent/received/lost: %d/%d/%d", health.Sent, health.Received, health.Lost)
		out.Linef("    loss: %d%%", health.LossRatio)
		out.Linef("    rtt last/ewma: %dms/%dms", health.LastRTTMs, health.EWMARTTMs)
		out.Linef("    consecutive_fail: %d", health.ConsecutiveFail)
		out.Linef("    last_failure: %s", failureDisplay(health.LastFailure))
		out.Linef("    next_probe: %s", formatUnixTime(health.NextProbeUnix))
		out.Linef("    cutover_blocking: %t", health.CutoverBlocking)
	}
	out.Linef("  routing:")
	out.Linef("    bird_state: %s", link.Routing.BirdState)
	out.Linef("    bird_neighbors: %s", link.Routing.BirdNeighbors)
	out.Linef("    bird_best_routes: %s", link.Routing.BirdBestRoutes)
}

func writeDebugMissingLink(out *lineWriter, link inspect.LinkView, spec *ipsec.TransportLinkSpec) {
	desired := inspect.DesiredLink{}
	if link.Desired != nil {
		desired = *link.Desired
	}
	out.Blank()
	out.Linef("link %s", link.ID)
	out.Linef("  peer: %s", link.PeerZone)
	out.Linef("  group: %s", dash(link.GroupID))
	out.Linef("  state: missing")
	out.Linef("  planner:")
	out.Linef("    desired_hash: %s", dash(shortTextHash(desired.DesiredSpecHash)))
	out.Linef("    actual_hash: -")
	out.Linef("    endpoint: %s", dash(desired.Endpoint))
	out.Linef("    local_tunnel: %s", dash(desired.LocalTunnelAddr))
	out.Linef("    peer_tunnel: %s", dash(desired.PeerTunnelAddr))
	out.Linef("  xfrm:")
	out.Linef("    interface: %s", formatInterfaceWithIfID(link.InterfaceName, link.XFRMIfID))
	out.Linef("  strongswan:")
	out.Linef("    child_sa: -")
	out.Linef("    sa_state: -")
	writeDebugStrongSwanConfig(out, spec)
	out.Linef("  health:")
	out.Linef("    owner: -")
	out.Linef("    failures: 0")
	out.Linef("    backoff_until: -")
	out.Linef("    last_failure: -")
	out.Linef("  routing:")
	out.Linef("    bird_state: %s", link.Routing.BirdState)
	out.Linef("    bird_neighbors: %s", link.Routing.BirdNeighbors)
	out.Linef("    bird_best_routes: %s", link.Routing.BirdBestRoutes)
}

func specChildSAName(spec *ipsec.TransportLinkSpec) string {
	if spec == nil {
		return ""
	}
	return ipsec.ChildSAName(*spec)
}

func writeDebugStrongSwanConfig(out *lineWriter, spec *ipsec.TransportLinkSpec) {
	out.Linef("    config:")
	if spec == nil {
		out.Linef("      load_conn: -")
		return
	}
	conn, err := ipsec.BuildStrongSwanConnection(*spec)
	if err != nil {
		out.Linef("      load_conn_error: %s", err)
		return
	}
	childName := ipsec.ChildSAName(*spec)
	local, _ := conn["local"].(map[string]any)
	remote, _ := conn["remote"].(map[string]any)
	children, _ := conn["children"].(map[string]any)
	child, _ := children[childName].(map[string]any)
	out.Linef("      connection: %s", dash(spec.TransportID))
	out.Linef("      version: %s", dash(debugString(conn["version"])))
	out.Linef("      local_addrs: %s", debugStringList(conn["local_addrs"]))
	out.Linef("      remote_addrs: %s", debugStringList(conn["remote_addrs"]))
	out.Linef("      local_port: %s", dash(debugString(conn["local_port"])))
	out.Linef("      remote_port: %s", dash(debugString(conn["remote_port"])))
	out.Linef("      encap: %s", dash(debugString(conn["encap"])))
	out.Linef("      mobike: %s", dash(debugString(conn["mobike"])))
	out.Linef("      local_auth: %s", dash(debugString(local["auth"])))
	out.Linef("      local_id: %s", dash(debugString(local["id"])))
	out.Linef("      remote_auth: %s", dash(debugString(remote["auth"])))
	out.Linef("      remote_id: %s", dash(debugString(remote["id"])))
	out.Linef("      local_key_algorithm: %s", dash(spec.LocalPrivateKeyAlgorithm))
	out.Linef("      local_private_key: %s", presentOrDash(len(spec.LocalPrivateKey) > 0))
	out.Linef("      peer_public_key: %s", presentOrDash(len(spec.PeerPublicKey) > 0))
	out.Linef("      child: %s", dash(childName))
	out.Linef("      child_mode: %s", dash(debugString(child["mode"])))
	out.Linef("      child_start_action: %s", dash(debugString(child["start_action"])))
	out.Linef("      child_local_ts: %s", debugStringList(child["local_ts"]))
	out.Linef("      child_remote_ts: %s", debugStringList(child["remote_ts"]))
	out.Linef("      child_if_id_in: %s", formatDebugChildIfID(child["if_id_in"]))
	out.Linef("      child_if_id_out: %s", formatDebugChildIfID(child["if_id_out"]))
}

func formatInterfaceWithIfID(name string, ifID uint32) string {
	if name == "" && ifID == 0 {
		return "-"
	}
	if name == "" {
		name = ipsec.StableInterfaceName(ifID)
	}
	if ifID == 0 {
		return dash(name)
	}
	return fmt.Sprintf("%s(%d)", name, ifID)
}

func formatDerivedInterfaceWithIfID(ifID uint32) string {
	if ifID == 0 {
		return "-"
	}
	return formatInterfaceWithIfID(ipsec.StableInterfaceName(ifID), ifID)
}

func formatDebugChildIfID(value any) string {
	s := debugString(value)
	if s == "" {
		return "-"
	}
	var id uint32
	if _, err := fmt.Sscanf(s, "%d", &id); err == nil && id != 0 {
		return formatDerivedInterfaceWithIfID(id)
	}
	return s
}

func debugString(value any) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case fmt.Stringer:
		return v.String()
	default:
		return fmt.Sprint(v)
	}
}

func debugStringList(value any) string {
	switch v := value.(type) {
	case nil:
		return "-"
	case []string:
		if len(v) == 0 {
			return "-"
		}
		return strings.Join(v, ",")
	case []any:
		if len(v) == 0 {
			return "-"
		}
		parts := make([]string, 0, len(v))
		for _, item := range v {
			parts = append(parts, debugString(item))
		}
		return strings.Join(parts, ",")
	default:
		s := debugString(value)
		if s == "" {
			return "-"
		}
		return s
	}
}

func formatSAState(sa inspect.LinkSA) string {
	if sa.Name == "" && sa.ChildSA == "" {
		return "-"
	}
	if sa.Established {
		return "established"
	}
	if sa.ChildState != "" {
		return strings.ToLower(sa.ChildState)
	}
	if sa.IKEState != "" {
		return strings.ToLower(sa.IKEState)
	}
	return "present"
}

func formatUint64OrDash(value uint64) string {
	if value == 0 {
		return "-"
	}
	return fmt.Sprintf("%d", value)
}
