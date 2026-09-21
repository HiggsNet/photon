package main

import (
	"cmp"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/urfave/cli/v3"
)

type ipamMutationRequest struct {
	Operation string        `json:"operation"`
	Zone      zone.ZonePath `json:"zone"`
	Prefix    string        `json:"prefix"`
	Target    zone.ZonePath `json:"target,omitempty"`
	Shared    bool          `json:"shared,omitempty"`
	Tag       string        `json:"tag,omitempty"`
	DryRun    bool          `json:"dry_run,omitempty"`
}

const (
	ipamOperationPoolCreate       = "pool_create"
	ipamOperationPoolRevoke       = "pool_revoke"
	ipamOperationAssignmentCreate = "assignment_create"
	ipamOperationAssignmentRevoke = "assignment_revoke"
)

// commonIPAMIntent is the thin control-adapter boundary. It translates the
// wire request into one explicit public Store intent and performs no state
// reads or semantic validation of its own.
func commonIPAMIntent(request ipamMutationRequest) (corestate.LocalIntent, error) {
	switch request.Operation {
	case ipamOperationPoolCreate:
		return corestate.PutIPAMPoolIntent{
			Zone: request.Zone, Prefix: request.Prefix, DelegatedTo: request.Target,
		}, nil
	case ipamOperationPoolRevoke:
		return corestate.RevokeIPAMPoolIntent{Zone: request.Zone, Prefix: request.Prefix}, nil
	case ipamOperationAssignmentCreate:
		return corestate.PutIPAMAssignmentIntent{
			Zone: request.Zone, Prefix: request.Prefix, AssignedTo: request.Target, Shared: request.Shared, Tag: request.Tag,
		}, nil
	case ipamOperationAssignmentRevoke:
		return corestate.RevokeIPAMAssignmentIntent{
			Zone: request.Zone, Prefix: request.Prefix, AssignedTo: request.Target,
		}, nil
	default:
		return nil, fmt.Errorf("unsupported IPAM operation %q", request.Operation)
	}
}

func cmdIPAM() *cli.Command {
	return &cli.Command{
		Name:  "ipam",
		Usage: "IPAM pool and assignment management",
		Commands: []*cli.Command{
			{
				Name:  "pool",
				Usage: "IPAM pool management commands",
				Commands: []*cli.Command{
					{
						Name:      "create",
						Usage:     "Create or update an IPAM pool delegation",
						UsageText: "photon route ipam pool create [--direct] <zone> <prefix> --delegated-to <zone>",
						Description: "Delegate authority to assign prefixes from a pool to a sub-zone.\n" +
							"The prefix is canonicalized before storage.",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "delegated-to", Usage: "Zone that receives the pool delegation", Required: true},
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: photon route ipam pool create <zone> <prefix> --delegated-to <zone>", 1)
							}
							return createIPAMPool(
								zone.ZonePath(cmd.Args().Get(0)),
								cmd.Args().Get(1),
								zone.ZonePath(cmd.String("delegated-to")),
								cmd.Bool("direct"),
							)
						},
					},
					{
						Name:        "revoke",
						Usage:       "Revoke an IPAM pool delegation",
						UsageText:   "photon route ipam pool revoke [--direct] <zone> <prefix>",
						Description: "Withdraw a previously created IPAM pool delegation by publishing a higher-version record with active=false.",
						Flags: []cli.Flag{
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: photon route ipam revoke pool <zone> <prefix>", 1)
							}
							return revokeIPAMPool(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Bool("direct"))
						},
					},
				},
			},
			{
				Name:      "assign",
				Usage:     "Assign a prefix to a zone",
				UsageText: "photon route ipam assign [--direct] <zone> <prefix> --to <zone> [--shared] [--tag <tag>]",
				Description: "Assign a CIDR prefix to a zone so it may announce routes within it.\n" +
					"The prefix is canonicalized before storage.\n" +
					"--shared marks this as an anycast assignment, allowing multiple zones to hold the same prefix.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "to", Usage: "Zone that receives the assignment", Required: true},
					&cli.BoolFlag{Name: "shared", Usage: "Mark as anycast/shared assignment (allows prefix overlap with other shared assignments)", Value: false},
					&cli.StringFlag{Name: "tag", Usage: "Stable selector for a shared assignment group"},
					&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 2 {
						return cli.Exit("usage: photon route ipam assign <zone> <prefix> --to <zone> [--shared] [--tag <tag>]", 1)
					}
					return assignIPAM(
						zone.ZonePath(cmd.Args().Get(0)),
						cmd.Args().Get(1),
						zone.ZonePath(cmd.String("to")),
						cmd.Bool("shared"),
						cmd.String("tag"),
						cmd.Bool("direct"),
					)
				},
			},
			{
				Name:      "revoke",
				Usage:     "Revoke an IPAM record",
				UsageText: "photon route ipam revoke assignment|pool <zone> <prefix>",
				Commands: []*cli.Command{
					{
						Name:        "assignment",
						Usage:       "Revoke an IPAM assignment",
						UsageText:   "photon route ipam revoke assignment [--direct] [--to <zone>] <zone> <prefix>",
						Description: "Withdraw a previously created IPAM assignment by publishing a higher-version record with active=false.",
						Flags: []cli.Flag{
							&cli.StringFlag{Name: "to", Usage: "Assigned member Zone; required when a shared prefix has multiple members"},
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: photon route ipam revoke assignment [--to <zone>] <zone> <prefix>", 1)
							}
							return revokeIPAMAssignmentTo(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), zone.ZonePath(cmd.String("to")), cmd.Bool("direct"))
						},
					},
					{
						Name:        "pool",
						Usage:       "Revoke an IPAM pool delegation",
						UsageText:   "photon route ipam revoke pool [--direct] <zone> <prefix>",
						Description: "Withdraw a previously created IPAM pool delegation by publishing a higher-version record with active=false.",
						Flags: []cli.Flag{
							&cli.BoolFlag{Name: "direct", Usage: "Write the local DB directly without daemon reconcile"},
						},
						Action: func(ctx context.Context, cmd *cli.Command) error {
							if cmd.Args().Len() != 2 {
								return cli.Exit("usage: photon route ipam revoke pool <zone> <prefix>", 1)
							}
							return revokeIPAMPool(zone.ZonePath(cmd.Args().Get(0)), cmd.Args().Get(1), cmd.Bool("direct"))
						},
					},
				},
			},
			{
				Name:      "assigned",
				Usage:     "List authorized IPAM assignments",
				UsageText: "photon route ipam assigned [--zone <zone>]",
				Description: "Print authorized IPAM assignments as a table.\n" +
					"If --zone is given, only assignments whose source or assigned_to matches are shown.",
				Flags: []cli.Flag{
					&cli.StringFlag{Name: "zone", Usage: "Filter by source or assigned zone"},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon route ipam assigned [--zone <zone>]", 1)
					}
					return listIPAMAssignments(zone.ZonePath(cmd.String("zone")))
				},
			},
			{
				Name:        "mine",
				Usage:       "Show IPAM prefixes and pools for the local managed zone",
				UsageText:   "photon route ipam mine [--json]",
				Description: "Print the local managed zone's authorized IPAM assignments and owned pools as tables.",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "json", Usage: "Print structured JSON output", Value: false},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 0 {
						return cli.Exit("usage: photon route ipam mine [--json]", 1)
					}
					return showLocalIPAM(cmd.Bool("json"))
				},
			},
			{
				Name:      "get",
				Usage:     "Explain IPAM ownership and assignment for an address or prefix",
				UsageText: "photon route ipam get <addr-or-prefix> [--json]",
				Flags: []cli.Flag{
					&cli.BoolFlag{Name: "json", Usage: "Print structured JSON output", Value: false},
				},
				Action: func(ctx context.Context, cmd *cli.Command) error {
					if cmd.Args().Len() != 1 {
						return cli.Exit("usage: photon route ipam get <addr-or-prefix> [--json]", 1)
					}
					return getIPAM(cmd.Args().First(), cmd.Bool("json"))
				},
			},
		},
	}
}

func createIPAMPool(path zone.ZonePath, prefix string, delegatedTo zone.ZonePath, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	return createIPAMPoolWithConfig(config, path, prefix, delegatedTo, time.Now(), direct)
}

func createIPAMPoolWithConfig(config *appConfig, path zone.ZonePath, prefix string, delegatedTo zone.ZonePath, now time.Time, direct bool) error {
	return submitIPAMMutation(config, ipamMutationRequest{
		Operation: ipamOperationPoolCreate,
		Zone:      path, Prefix: prefix, Target: delegatedTo,
	}, "created", now, direct)
}

func assignIPAM(path zone.ZonePath, prefix string, assignedTo zone.ZonePath, shared bool, tag string, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	return assignIPAMWithConfigTag(config, path, prefix, assignedTo, shared, tag, time.Now(), direct)
}

func assignIPAMWithConfigTag(config *appConfig, path zone.ZonePath, prefix string, assignedTo zone.ZonePath, shared bool, tag string, now time.Time, direct bool) error {
	return submitIPAMMutation(config, ipamMutationRequest{
		Operation: ipamOperationAssignmentCreate,
		Zone:      path, Prefix: prefix, Target: assignedTo, Shared: shared, Tag: tag,
	}, "assigned", now, direct)
}

func revokeIPAMPool(path zone.ZonePath, prefix string, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	return revokeIPAMPoolWithConfig(config, path, prefix, time.Now(), direct)
}

func revokeIPAMPoolWithConfig(config *appConfig, path zone.ZonePath, prefix string, now time.Time, direct bool) error {
	return submitIPAMMutation(config, ipamMutationRequest{
		Operation: ipamOperationPoolRevoke,
		Zone:      path, Prefix: prefix,
	}, "revoked", now, direct)
}

func revokeIPAMAssignmentTo(path zone.ZonePath, prefix string, assignedTo zone.ZonePath, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	return revokeIPAMAssignmentWithConfigTo(config, path, prefix, assignedTo, time.Now(), direct)
}

func revokeIPAMAssignmentWithConfigTo(config *appConfig, path zone.ZonePath, prefix string, target zone.ZonePath, now time.Time, direct bool) error {
	return submitIPAMMutation(config, ipamMutationRequest{
		Operation: ipamOperationAssignmentRevoke,
		Zone:      path, Prefix: prefix, Target: target,
	}, "revoked", now, direct)
}

func submitIPAMMutation(config *appConfig, request ipamMutationRequest, operation string, now time.Time, direct bool) error {
	if version, ok, err := sendVersionedMutationViaControl(config, controlRequest{Method: "ipam_mutate", IPAM: &request}, direct); ok {
		if err != nil {
			return err
		}
		fmt.Printf("%s IPAM %s version %d via daemon\n", operation, request.Prefix, version)
		return nil
	}
	intent, err := commonIPAMIntent(request)
	if err != nil {
		return err
	}
	result, err := applyOfflineCommonIntent(config, intent, request.DryRun, now)
	if err != nil {
		return err
	}
	if result.Record == nil {
		return errors.New("IPAM mutation did not return a record")
	}
	fmt.Printf("%s %s/%s version %d\n", operation, result.Record.Zone, result.Record.Key, result.Record.Version)
	return nil
}

func listIPAMAssignments(filterZone zone.ZonePath) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	return listIPAMAssignmentsWithConfig(config, filterZone, time.Now(), false)
}

func listIPAMAssignmentsWithConfig(config *appConfig, filterZone zone.ZonePath, now time.Time, direct bool) error {
	return listIPAMAssignmentsWithConfigTo(os.Stdout, config, filterZone, now, direct)
}

func listIPAMAssignmentsWithConfigTo(w io.Writer, config *appConfig, filterZone zone.ZonePath, now time.Time, direct bool) error {
	if rows, ok, err := readCanonicalViewViaControl[[]inspect.IPAMAssignmentRow](config, controlRequest{Method: "ipam_assignments_view", Zone: filterZone.String()}, direct); err != nil {
		return err
	} else if ok {
		return writeIPAMAssignments(w, rows)
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return err
	}
	if common.State == nil {
		return fmt.Errorf("common state is not initialized")
	}
	rows, err := buildIPAMAssignmentRows(common.State, now, filterZone)
	if err != nil {
		return err
	}
	return writeIPAMAssignments(w, rows)
}

func buildIPAMAssignmentRows(state *corestate.VerifiedState, now time.Time, filterZone zone.ZonePath) ([]inspect.IPAMAssignmentRow, error) {
	if state == nil {
		return nil, fmt.Errorf("common state is not initialized")
	}
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, now)
	if err != nil {
		return nil, err
	}
	rows := make([]inspect.IPAMAssignmentRow, 0, len(ars.AllAssignments))
	filter := string(filterZone)
	for _, entry := range ars.AllAssignments {
		if filter != "" && string(entry.Source) != filter && string(entry.AssignedTo) != filter {
			continue
		}
		rows = append(rows, inspect.IPAMAssignmentRow{
			Prefix:     entry.Prefix.String(),
			Source:     string(entry.Source),
			AssignedTo: string(entry.AssignedTo),
			Shared:     entry.Shared,
			Tag:        entry.Tag,
		})
	}
	sortIPAMAssignmentRows(rows)
	return rows, nil
}

func sortIPAMAssignmentRows(rows []inspect.IPAMAssignmentRow) {
	sort.Slice(rows, func(i, j int) bool {
		if cmp := inspect.ComparePrefixStrings(rows[i].Prefix, rows[j].Prefix); cmp != 0 {
			return cmp < 0
		}
		if rows[i].AssignedTo != rows[j].AssignedTo {
			return inspect.ZonePathLess(rows[i].AssignedTo, rows[j].AssignedTo)
		}
		if rows[i].Source != rows[j].Source {
			return inspect.ZonePathLess(rows[i].Source, rows[j].Source)
		}
		return rows[i].Tag < rows[j].Tag
	})
}

func writeIPAMAssignments(w io.Writer, rows []inspect.IPAMAssignmentRow) error {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "assignments: %d\n", len(rows))
	tableRows := [][]string{{"PREFIX", "SOURCE", "ASSIGNED_TO", "MODE", "TAG"}}
	for _, row := range rows {
		tableRows = append(tableRows, []string{
			row.Prefix,
			row.Source,
			row.AssignedTo,
			ipamAssignmentMode(row.Shared),
			dash(row.Tag),
		})
	}
	if err := inspecttext.WriteAlignedRows(table, tableRows, 1, 2); err != nil {
		return err
	}
	return table.Flush()
}

func showLocalIPAM(jsonOut bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	return showLocalIPAMWithConfig(config, jsonOut, time.Now(), false)
}

func showLocalIPAMWithConfig(config *appConfig, jsonOut bool, now time.Time, direct bool) error {
	report, err := buildIPAMMineReport(config, now, direct)
	if err != nil {
		return err
	}
	if jsonOut {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}
	return writeIPAMMineReport(os.Stdout, report)
}

func writeIPAMMineReport(w io.Writer, report *inspect.IPAMMineReport) error {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "managed_zone: %s\n", report.ManagedZone)
	fmt.Fprintf(table, "assignments: %d\n", len(report.Assignments))
	assignmentRows := [][]string{{"PREFIX", "SOURCE", "MODE", "TAG"}}
	for _, row := range report.Assignments {
		assignmentRows = append(assignmentRows, []string{
			row.Prefix,
			row.Source,
			ipamAssignmentMode(row.Shared),
			dash(row.Tag),
		})
	}
	if err := inspecttext.WriteAlignedRows(table, assignmentRows, 1); err != nil {
		return err
	}
	fmt.Fprintln(table)
	fmt.Fprintf(table, "pools: %d\n", len(report.Pools))
	poolRows := [][]string{{"PREFIX", "SOURCE", "DELEGATED_TO", "RELATION"}}
	for _, row := range report.Pools {
		poolRows = append(poolRows, []string{
			row.Prefix,
			row.Source,
			row.DelegatedTo,
			dash(strings.Join(row.Relation, ",")),
		})
	}
	if err := inspecttext.WriteAlignedRows(table, poolRows, 1, 2); err != nil {
		return err
	}
	return table.Flush()
}

func buildIPAMMineReport(config *appConfig, now time.Time, direct bool) (*inspect.IPAMMineReport, error) {
	if report, ok, err := readCanonicalViewViaControl[inspect.IPAMMineReport](config, controlRequest{Method: "ipam_mine_view"}, direct); err != nil {
		return nil, err
	} else if ok {
		return &report, nil
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return nil, err
	}
	if common.State == nil {
		return nil, fmt.Errorf("common state is not initialized")
	}
	return buildIPAMMineReportFromState(common.State, now)
}

func buildIPAMMineReportFromState(state *corestate.VerifiedState, now time.Time) (*inspect.IPAMMineReport, error) {
	if state == nil {
		return nil, fmt.Errorf("common state is not initialized")
	}
	if state.ManagedZone == "" || !state.ManagedZone.Valid() {
		return nil, fmt.Errorf("managed_zone is not set")
	}
	if state.Network == nil {
		return nil, fmt.Errorf("network state is nil")
	}
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, now)
	if err != nil {
		return nil, err
	}

	managed := state.ManagedZone
	report := &inspect.IPAMMineReport{
		ManagedZone: string(managed),
		Assignments: []inspect.IPAMMineAssignmentRow{},
		Pools:       []inspect.IPAMMinePoolRow{},
	}
	for _, entry := range ars.AllAssignments {
		if entry.AssignedTo != managed {
			continue
		}
		report.Assignments = append(report.Assignments, inspect.IPAMMineAssignmentRow{
			Prefix: entry.Prefix.String(),
			Source: string(entry.Source),
			Shared: entry.Shared,
			Tag:    entry.Tag,
		})
	}
	for _, entry := range ars.AllPools {
		relation := localIPAMPoolRelation(entry, managed)
		if len(relation) == 0 {
			continue
		}
		report.Pools = append(report.Pools, inspect.IPAMMinePoolRow{
			Prefix:      entry.Prefix.String(),
			Source:      string(entry.Source),
			DelegatedTo: string(entry.DelegatedTo),
			Relation:    relation,
		})
	}
	sort.Slice(report.Assignments, func(i, j int) bool {
		return inspect.ComparePrefixStrings(report.Assignments[i].Prefix, report.Assignments[j].Prefix) < 0
	})
	sort.Slice(report.Pools, func(i, j int) bool {
		if cmp := inspect.ComparePrefixStrings(report.Pools[i].Prefix, report.Pools[j].Prefix); cmp != 0 {
			return cmp < 0
		}
		if report.Pools[i].Source != report.Pools[j].Source {
			return report.Pools[i].Source < report.Pools[j].Source
		}
		return report.Pools[i].DelegatedTo < report.Pools[j].DelegatedTo
	})
	return report, nil
}

func localIPAMPoolRelation(entry *routing.PoolEntry, managed zone.ZonePath) []string {
	if entry == nil {
		return nil
	}
	var relation []string
	if entry.Source == managed {
		relation = append(relation, "published_by_managed_zone")
	}
	if entry.DelegatedTo == managed {
		relation = append(relation, "delegated_to_managed_zone")
	}
	return relation
}

func getIPAM(query string, jsonOut bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	report, err := buildIPAMGetReport(config, query, time.Now(), false)
	if err != nil {
		return err
	}
	if jsonOut {
		out, err := json.MarshalIndent(report, "", "  ")
		if err != nil {
			return err
		}
		fmt.Println(string(out))
		return nil
	}
	return writeIPAMGetReport(os.Stdout, report)
}

func buildIPAMGetReport(config *appConfig, query string, now time.Time, direct bool) (*inspect.IPAMGetReport, error) {
	if report, ok, err := readCanonicalViewViaControl[inspect.IPAMGetReport](config, controlRequest{Method: "ipam_get_view", ValueText: query}, direct); err != nil {
		return nil, err
	} else if ok {
		return &report, nil
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return nil, err
	}
	if common.State == nil {
		return nil, fmt.Errorf("common state is not initialized")
	}
	return buildIPAMGetReportFromState(common.State, now, query)
}

func buildIPAMGetReportFromState(state *corestate.VerifiedState, now time.Time, query string) (*inspect.IPAMGetReport, error) {
	if state == nil {
		return nil, fmt.Errorf("common state is not initialized")
	}
	prefix, err := normalizeIPAMGetQuery(query)
	if err != nil {
		return nil, err
	}
	ars, err := routing.BuildAuthorizedRouteSet(state.Network, now)
	if err != nil {
		return nil, err
	}
	report := &inspect.IPAMGetReport{
		Query:       prefix.String(),
		PoolChain:   []inspect.IPAMGetPoolRow{},
		Assignments: []inspect.IPAMGetAssignmentRow{},
		Routes:      []inspect.IPAMGetRouteRow{},
		Diagnostics: []inspect.IPAMGetDiagnosticRow{},
	}
	var pools []*routing.PoolEntry
	for _, pool := range ars.AllPools {
		if pool.Prefix.Bits() <= prefix.Bits() && pool.Prefix.Overlaps(prefix) {
			pools = append(pools, pool)
		}
	}
	slices.SortFunc(pools, func(a, b *routing.PoolEntry) int {
		return cmp.Or(
			cmp.Compare(a.Prefix.Bits(), b.Prefix.Bits()),
			cmp.Compare(a.Source, b.Source),
			cmp.Compare(a.DelegatedTo, b.DelegatedTo),
		)
	})
	for _, pool := range pools {
		report.PoolChain = append(report.PoolChain, inspect.IPAMGetPoolRow{
			Prefix:      pool.Prefix.String(),
			Source:      string(pool.Source),
			DelegatedTo: string(pool.DelegatedTo),
			Relation:    ipamGetPoolRelation(pool),
		})
	}
	if len(report.PoolChain) > 0 {
		best := report.PoolChain[len(report.PoolChain)-1]
		report.BestPool = &best
	}
	for _, assignment := range ars.AllAssignments {
		if !prefix.Overlaps(assignment.Prefix) {
			continue
		}
		report.Assignments = append(report.Assignments, inspect.IPAMGetAssignmentRow{
			Prefix:     assignment.Prefix.String(),
			Source:     string(assignment.Source),
			AssignedTo: string(assignment.AssignedTo),
			Shared:     assignment.Shared,
			Tag:        assignment.Tag,
		})
	}
	sort.Slice(report.Assignments, func(i, j int) bool {
		return inspect.ComparePrefixStrings(report.Assignments[i].Prefix, report.Assignments[j].Prefix) < 0
	})
	if len(report.Assignments) == 1 && !report.Assignments[0].Shared {
		assignedTo := report.Assignments[0].AssignedTo
		report.AssignedTo = &assignedTo
	}
	for source, routes := range ars.Announced {
		for p := range routes {
			if !prefix.Overlaps(p) {
				continue
			}
			report.Routes = append(report.Routes, inspect.IPAMGetRouteRow{Prefix: p.String(), Source: string(source)})
		}
	}
	sort.Slice(report.Routes, func(i, j int) bool {
		if cmp := inspect.ComparePrefixStrings(report.Routes[i].Prefix, report.Routes[j].Prefix); cmp != 0 {
			return cmp < 0
		}
		return report.Routes[i].Source < report.Routes[j].Source
	})
	for _, authErr := range ars.Errors {
		if !strings.HasPrefix(authErr.Code, "ipam_") {
			continue
		}
		if authErr.Prefix.IsValid() && !prefix.Overlaps(authErr.Prefix) {
			continue
		}
		report.Diagnostics = append(report.Diagnostics, inspect.IPAMGetDiagnosticRow{Code: authErr.Code, Detail: authErr.Detail})
	}
	if report.BestPool == nil {
		report.Diagnostics = append(report.Diagnostics, inspect.IPAMGetDiagnosticRow{Code: "ipam_no_pool", Detail: fmt.Sprintf("no valid pool covers %s", prefix)})
	} else if len(report.Assignments) == 0 {
		report.Diagnostics = append(report.Diagnostics, inspect.IPAMGetDiagnosticRow{Code: "ipam_unassigned", Detail: fmt.Sprintf("no assignment covers %s", prefix)})
	}
	return report, nil
}

func normalizeIPAMGetQuery(query string) (netip.Prefix, error) {
	if strings.Contains(query, "/") {
		p, err := netip.ParsePrefix(query)
		if err != nil {
			return netip.Prefix{}, fmt.Errorf("invalid prefix %q: %w", query, err)
		}
		return p.Masked(), nil
	}
	addr, err := netip.ParseAddr(query)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("invalid address or prefix %q: %w", query, err)
	}
	return netip.PrefixFrom(addr, addr.BitLen()), nil
}

func ipamGetPoolRelation(pool *routing.PoolEntry) string {
	if pool.Source == pool.DelegatedTo {
		return "owner"
	}
	return "delegated"
}

func writeIPAMGetReport(w io.Writer, report *inspect.IPAMGetReport) error {
	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "query: %s\n", report.Query)

	fmt.Fprintf(table, "pools: %d\n", len(report.PoolChain))
	poolRows := [][]string{{"PREFIX", "SOURCE", "DELEGATED_TO", "RELATION", "BEST"}}
	for i, pool := range report.PoolChain {
		best := "-"
		if i == len(report.PoolChain)-1 {
			best = "yes"
		}
		poolRows = append(poolRows, []string{
			pool.Prefix,
			pool.Source,
			pool.DelegatedTo,
			dash(pool.Relation),
			best,
		})
	}
	if err := inspecttext.WriteAlignedRows(table, poolRows, 1, 2); err != nil {
		return err
	}

	fmt.Fprintln(table)
	fmt.Fprintf(table, "assignments: %d\n", len(report.Assignments))
	assignmentRows := [][]string{{"PREFIX", "SOURCE", "ASSIGNED_TO", "MODE", "TAG"}}
	for _, assignment := range report.Assignments {
		assignmentRows = append(assignmentRows, []string{
			assignment.Prefix,
			assignment.Source,
			assignment.AssignedTo,
			ipamAssignmentMode(assignment.Shared),
			dash(assignment.Tag),
		})
	}
	if err := inspecttext.WriteAlignedRows(table, assignmentRows, 1, 2); err != nil {
		return err
	}

	fmt.Fprintln(table)
	fmt.Fprintf(table, "routes: %d\n", len(report.Routes))
	routeRows := [][]string{{"PREFIX", "SOURCE"}}
	for _, route := range report.Routes {
		routeRows = append(routeRows, []string{route.Prefix, route.Source})
	}
	if err := inspecttext.WriteAlignedRows(table, routeRows, 1); err != nil {
		return err
	}

	fmt.Fprintln(table)
	fmt.Fprintf(table, "diagnostics: %d\n", len(report.Diagnostics))
	fmt.Fprintln(table, "CODE\tDETAIL")
	for _, diag := range report.Diagnostics {
		fmt.Fprintf(table, "%s\t%s\n", diag.Code, strings.ReplaceAll(diag.Detail, "\n", "\\n"))
	}
	return table.Flush()
}

func ipamAssignmentMode(shared bool) string {
	if shared {
		return "shared"
	}
	return "exclusive"
}
