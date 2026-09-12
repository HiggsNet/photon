package text

import (
	"io"
	"sort"
	"strings"
	"text/tabwriter"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteBirdDump(w io.Writer, dump *inspect.BirdDumpResponse) error {
	out := newLineWriter(w)
	if dump == nil || len(dump.Instances) == 0 {
		out.Linef("bird_dump: no instances")
		return out.Err()
	}
	netnsNames := make([]string, 0, len(dump.Instances))
	for netnsName := range dump.Instances {
		netnsNames = append(netnsNames, netnsName)
	}
	sort.Strings(netnsNames)
	for _, netnsName := range netnsNames {
		inst := dump.Instances[netnsName]
		out.Linef("netns %s", inst.NetNS)
		out.Linef("  instance_id: %s", dash(inst.InstanceID))
		out.Linef("  control_socket: %s", dash(inst.ControlSocket))
		out.LineIf(inst.ConfigPath != "", "  config_path: %s", inst.ConfigPath)
		out.LineIf(inst.FilterFailure != nil, "  filter_failure: %s", failureDisplay(inst.FilterFailure))
		if inst.FilterDefinitions != "" {
			out.Linef("  filter_definitions:")
			for line := range strings.SplitSeq(inst.FilterDefinitions, "\n") {
				out.Linef("    %s", line)
			}
		}
		out.LineIf(inst.Failure != nil, "  failure: %s", failureDisplay(inst.Failure))
		commands := make([]string, 0, len(inst.Raw))
		for cmd := range inst.Raw {
			commands = append(commands, cmd)
		}
		sort.Strings(commands)
		for _, cmd := range commands {
			if isStructuredBirdCommand(cmd) {
				continue
			}
			out.Linef("  command: %s", cmd)
			raw := strings.TrimRight(inst.Raw[cmd], "\n")
			if raw == "" {
				out.Linef("    -")
				continue
			}
			for line := range strings.SplitSeq(raw, "\n") {
				out.Linef("    %s", line)
			}
		}
		if err := out.Err(); err != nil {
			return err
		}
		if err := writeBirdInterfaceContexts(w, inst.Interfaces); err != nil {
			return err
		}
		if err := writeBirdNeighbors(w, inst.Neighbors); err != nil {
			return err
		}
		if err := writeBirdBabelRoutes(w, inst.BabelRoutes); err != nil {
			return err
		}
		if err := writeBirdBabelEntries(w, inst.BabelEntries); err != nil {
			return err
		}
	}
	return out.Err()
}

func isStructuredBirdCommand(command string) bool {
	switch command {
	case "show babel neighbors", "show babel routes", "show babel entries":
		return true
	default:
		return false
	}
}

func writeBirdInterfaceContexts(w io.Writer, rows []inspect.BirdInterfaceContext) error {
	if len(rows) == 0 {
		return nil
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	out.Println("  Photon interface mapping:")
	tableRows := [][]string{{"  INTERFACE", "ZONE", "FAMILY", "LINK", "ROLE"}}
	for _, row := range rows {
		tableRows = append(tableRows, []string{"  " + row.Name, dash(row.Zone), dash(row.Family), dash(row.LinkID), dash(row.RuntimeRole)})
	}
	writeAlignedRows(out, tableRows, 1)
	if err := out.Err(); err != nil {
		return err
	}
	return table.Flush()
}

func writeBirdNeighbors(w io.Writer, rows []inspect.BirdBabelNeighbor) error {
	if len(rows) == 0 {
		return nil
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	out.Linef("  Babel neighbors (%d):", len(rows))
	tableRows := [][]string{{"  ADDRESS", "INTERFACE", "ZONE", "FAMILY", "METRIC", "ROUTES", "HELLOS", "EXPIRES", "AUTH", "RTT(ms)", "PROTOCOL"}}
	for _, row := range rows {
		tableRows = append(tableRows, []string{
			"  " + row.Address, row.Interface, dash(row.Zone), dash(row.Family), row.Metric, row.Routes, row.Hellos,
			row.Expires, row.Auth, row.RTT, dash(row.Protocol)})
	}
	writeAlignedRows(out, tableRows, 2)
	if err := out.Err(); err != nil {
		return err
	}
	return table.Flush()
}

func writeBirdBabelRoutes(w io.Writer, rows []inspect.BirdBabelRoute) error {
	if len(rows) == 0 {
		return nil
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	out.Linef("  Babel routes (%d):", len(rows))
	tableRows := [][]string{{"  PREFIX", "NEXTHOP", "INTERFACE", "ZONE", "FAMILY", "METRIC", "FLAG", "SEQNO", "EXPIRES", "PROTOCOL"}}
	for _, row := range rows {
		tableRows = append(tableRows, []string{
			"  " + row.Prefix, row.Nexthop, row.Interface, dash(row.Zone), dash(row.Family), row.Metric,
			dash(row.Flag), row.Seqno, row.Expires, dash(row.Protocol)})
	}
	writeAlignedRows(out, tableRows, 3)
	if err := out.Err(); err != nil {
		return err
	}
	return table.Flush()
}

func writeBirdBabelEntries(w io.Writer, rows []inspect.BirdBabelEntry) error {
	if len(rows) == 0 {
		return nil
	}
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	out := newLineWriter(table)
	out.Linef("  Babel entries (%d):", len(rows))
	tableRows := [][]string{{"  PREFIX", "ROUTER ID", "METRIC", "SEQNO", "ROUTES", "SOURCES", "SELECTED INTERFACE", "ZONE", "FAMILY", "PROTOCOL"}}
	for _, row := range rows {
		tableRows = append(tableRows, []string{
			"  " + row.Prefix, row.RouterID, row.Metric, row.Seqno, row.Routes, row.Sources,
			dash(row.Interface), dash(row.Zone), dash(row.Family), dash(row.Protocol)})
	}
	writeAlignedRows(out, tableRows, 7)
	if err := out.Err(); err != nil {
		return err
	}
	return table.Flush()
}

func WriteBabelDebug(w io.Writer, view inspect.BabelDebugView) error {
	out := newLineWriter(w)
	if len(view.Instances) == 0 {
		out.Linef("routing: not configured")
		return out.Err()
	}
	if failure := view.LastReconcileFailure; failure != nil {
		out.Linef("last_reconcile_failure: %s", failureDisplay(failure))
	}
	for _, inst := range view.Instances {
		out.Linef("netns %s", inst.NetNS)
		out.Linef("  instance_id: %s", inst.InstanceID)
		out.Linef("  mode: %s", inst.Mode)
		out.LineIf(inst.ShutdownPolicy != "", "  shutdown_policy: %s", inst.ShutdownPolicy)
		if !inst.Enabled {
			out.Linef("  state: disabled")
			continue
		}
		if inst.HasState {
			out.Linef("  router_id: %d", inst.RouterID)
			out.Linef("  control_socket: %s", dash(inst.ControlSocket))
			out.Linef("  config_path: %s", dash(inst.ConfigPath))
			out.Linef("  pid_file: %s", dash(inst.PIDFile))
			out.Linef("  last_config_hash: %s", dash(shortTextHash(inst.LastConfigHash)))
			out.LineIf(len(inst.Overlays) > 0, "  overlays: %s", strings.Join(inst.Overlays, ", "))
			out.Linef("  state: %s", defaultText(inst.State, "pending"))
			out.Linef("  last_failure: %s", failureDisplay(inst.LastFailure))
			continue
		}
		out.Linef("  router_id: -")
		out.Linef("  control_socket: -")
		out.Linef("  config_path: -")
		out.Linef("  pid_file: -")
		out.Linef("  last_config_hash: -")
		out.Linef("  state: pending")
		out.Linef("  last_failure: -")
	}
	return out.Err()
}

func shortTextHash(hash string) string {
	if len(hash) <= 12 {
		return hash
	}
	return hash[:12]
}
