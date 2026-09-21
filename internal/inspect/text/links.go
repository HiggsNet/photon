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
		inspection.DesiredLinks,
		inspection.ActualSAs,
		len(inspect.FilterLinkActions(inspection.Actions, filter)),
		len(inspect.FilterLinkSkips(inspection.Skipped, filter)),
	)
	if failure := inspection.LastFailure; failure != nil {
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
				dash(link.OwnerManager),
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
	out.LineIf(inspection.DesiredPlanError != "", "desired_plan_error: %s", inspection.DesiredPlanError)
	out.Linef("last_run: %s", formatUnixTime(inspection.LastRunUnix))
	out.Linef("desired_links: %d", inspection.DesiredLinks)
	out.Linef("planned_desired_links: %d", view.LastDesiredCount)
	out.LineIf(view.ReplanIgnored, "planned_desired_status: ignored_partial last_reconcile_desired=%d", view.LastDesiredLinks)
	out.Linef("desired_source: %s", dash(view.DesiredPlanSource))
	out.Linef("actual_sas: %d", inspection.ActualSAs)
	out.Linef("last_failure: %s", failureDisplay(inspection.LastFailure))
	out.Linef("link_instances: %d", inspection.LinkInstances)
	if strings.TrimSpace(view.Filter) != "" {
		out.Linef("filter: %s", view.Filter)
		out.Linef("matched_links: %d", len(inspection.Links))
	}
	for _, link := range inspection.Links {
		if link.Missing {
			writeDebugMissingLink(out, link)
			continue
		}
		writeDebugLinkInstance(out, link)
	}
	out.Linef("actions: %d", len(inspection.Actions))
	if len(inspection.Actions) > 0 {
		rows := [][]string{{"ACTION", "INSTANCE", "GROUP", "PEER", "SA_ID", "REASON"}}
		for _, action := range inspection.Actions {
			rows = append(rows, []string{action.Action, dash(action.InstanceID), dash(action.GroupID), action.PeerZone.String(), formatUint64OrDash(action.SAUniqueID), dash(action.Reason)})
		}
		writeDebugTable(out, rows)
	}
	out.Linef("skipped: %d", len(inspection.Skipped))
	if len(inspection.Skipped) > 0 {
		rows := [][]string{{"GROUP", "PEER", "REASON", "DETAIL"}}
		for _, skip := range inspection.Skipped {
			rows = append(rows, []string{dash(skip.GroupID), skip.Peer.String(), dash(skip.Reason), dash(skip.Detail)})
		}
		writeDebugTable(out, rows)
	}
	return out.Err()
}

func writeDebugLinkInstance(out *lineWriter, link inspect.LinkView) {
	desired := inspect.DesiredLink{}
	if link.Desired != nil {
		desired = *link.Desired
	}
	sa := inspect.LinkSA{}
	if link.ActualSA != nil {
		sa = *link.ActualSA
	}
	out.Blank()
	out.Linef("link %s", escapeTableCell(link.ID))
	rows := [][]string{
		{"SECTION", "FIELD", "VALUE"},
		{"link", "peer", link.PeerZone},
		{"link", "group", dash(link.GroupID)},
		{"link", "state", dash(link.ActualState)},
		{"planner", "link_id", dash(firstNonEmpty(link.LinkID, desired.LinkID))},
		{"planner", "path_key", dash(firstNonEmpty(link.PathKey, desired.PathKey))},
		{"planner", "runtime_id", dash(firstNonEmpty(link.IKEName, link.TransportID, desired.TransportID))},
		{"planner", "desired_hash", dash(shortTextHash(desired.DesiredSpecHash))},
		{"planner", "actual_hash", dash(shortTextHash(link.DesiredSpecHash))},
		{"planner", "endpoint", dash(link.Endpoint)},
		{"planner", "local_tunnel", dash(link.LocalTunnelAddr)},
		{"planner", "peer_tunnel", dash(link.PeerTunnelAddr)},
		{"xfrm", "interface", formatInterfaceWithIfID(link.InterfaceName, link.XFRMIfID)},
		{"strongswan", "child_sa", dash(firstNonEmpty(sa.ChildSA, link.ChildSAName))},
		{"strongswan", "sa_state", formatSAState(sa)},
		{"strongswan", "local_endpoint", dash(sa.LocalEndpoint)},
		{"strongswan", "remote_endpoint", dash(firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint))},
		{"strongswan", "local_identity", dash(sa.LocalIdentity)},
		{"strongswan", "remote_identity", dash(sa.RemoteIdentity)},
		{"strongswan", "reqid", formatUint32OrDash(sa.ReqID)},
		{"strongswan", "observed_interface", formatDerivedInterfaceWithIfID(sa.XFRMIfID)},
		{"rotation", "phase", dash(link.Rotation.Phase)},
		{"rotation", "port_generation select/runtime/staged", inspect.DebugPortGenerationSummary(link.Rotation)},
		{"rotation", "port local/remote/runtime/staged", inspect.DebugPortSummary(link.Endpoint, firstNonEmpty(sa.RemoteEndpoint, sa.Endpoint), "")},
		{"rotation", "staged_ike", dash(link.Rotation.StagedIKEName)},
		{"rotation", "staged_interface", formatInterfaceWithIfID(link.Rotation.StagedInterfaceName, link.Rotation.StagedXFRMIfID)},
		{"rotation", "deadline", formatUnixTime(link.Rotation.RotateDeadline)},
		{"takeover", "initiator_role", dash(link.Takeover.InitiatorRole)},
		{"takeover", "phase", dash(link.Takeover.Phase)},
		{"takeover", "until", formatUnixTime(link.Takeover.Until)},
		{"takeover", "observed_initiator", dash(link.Takeover.ObservedInitiator)},
		{"lifecycle", "owner", dash(link.OwnerManager)},
		{"lifecycle", "failures", fmt.Sprintf("%d", link.FailureCount)},
		{"lifecycle", "backoff_until", formatUnixTime(link.BackoffUntil)},
		{"lifecycle", "last_failure", failureDisplay(link.LastFailure)},
		{"lifecycle", "takeover_failure", failureDisplay(link.Takeover.LastFailure)},
	}
	if link.Health == nil {
		rows = append(rows, []string{"health", "state", "unavailable"})
	} else {
		health := link.Health
		rows = append(rows, []string{"health", "state", dash(health.State)})
		rows = append(rows, []string{"health", "probe_id", dash(firstNonEmpty(health.ProbeID, health.InstanceID))})
		rows = append(rows, []string{"health", "role", dash(firstNonEmpty(health.ProbeRole, "active"))})
		rows = append(rows, []string{"health", "probe_type", dash(health.ProbeType)})
		rows = append(rows, []string{"health", "sent/received/lost", fmt.Sprintf("%d/%d/%d", health.Sent, health.Received, health.Lost)})
		rows = append(rows, []string{"health", "loss", fmt.Sprintf("%d%%", health.LossRatio)})
		rows = append(rows, []string{"health", "rtt last/ewma", fmt.Sprintf("%dms/%dms", health.LastRTTMs, health.EWMARTTMs)})
		rows = append(rows, []string{"health", "consecutive_fail", fmt.Sprintf("%d", health.ConsecutiveFail)})
		rows = append(rows, []string{"health", "last_failure", failureDisplay(health.LastFailure)})
		rows = append(rows, []string{"health", "next_probe", formatUnixTime(health.NextProbeUnix)})
		rows = append(rows, []string{"health", "cutover_blocking", fmt.Sprintf("%t", health.CutoverBlocking)})
	}
	rows = append(rows, []string{"routing", "bird_state", link.Routing.BirdState})
	writeDebugTable(out, rows)
}

func writeDebugMissingLink(out *lineWriter, link inspect.LinkView) {
	desired := inspect.DesiredLink{}
	if link.Desired != nil {
		desired = *link.Desired
	}
	out.Blank()
	out.Linef("link %s", escapeTableCell(link.ID))
	rows := [][]string{
		{"SECTION", "FIELD", "VALUE"},
		{"link", "peer", link.PeerZone},
		{"link", "group", dash(link.GroupID)},
		{"link", "state", "missing"},
		{"planner", "desired_hash", dash(shortTextHash(desired.DesiredSpecHash))},
		{"planner", "actual_hash", "-"},
		{"planner", "endpoint", dash(desired.Endpoint)},
		{"planner", "local_tunnel", dash(desired.LocalTunnelAddr)},
		{"planner", "peer_tunnel", dash(desired.PeerTunnelAddr)},
		{"xfrm", "interface", formatInterfaceWithIfID(link.InterfaceName, link.XFRMIfID)},
		{"strongswan", "child_sa", "-"},
		{"strongswan", "sa_state", "-"},
		{"health", "owner", "-"},
		{"health", "failures", "0"},
		{"health", "backoff_until", "-"},
		{"health", "last_failure", "-"},
		{"routing", "bird_state", link.Routing.BirdState},
	}
	writeDebugTable(out, rows)
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
