package main

import (
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"sort"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/HiggsNet/photon/internal/inspect"
	inspecttext "github.com/HiggsNet/photon/internal/inspect/text"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
)

type routeMutationRequest struct {
	Zone   zone.ZonePath `json:"zone"`
	Prefix string        `json:"prefix"`
	Active bool          `json:"active"`
	DryRun bool          `json:"dry_run,omitempty"`
}

func commonRouteIntent(request routeMutationRequest) corestate.LocalIntent {
	if request.Active {
		return corestate.AnnounceRouteIntent{Zone: request.Zone, Prefix: request.Prefix}
	}
	return corestate.WithdrawRouteIntent{Zone: request.Zone, Prefix: request.Prefix}
}

func announceRoute(path zone.ZonePath, prefix string, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	return mutateRouteWithConfig(config, path, prefix, true, time.Now(), direct)
}

func withdrawRoute(path zone.ZonePath, prefix string, direct bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}

	return mutateRouteWithConfig(config, path, prefix, false, time.Now(), direct)
}

func showRoutes(filter string, includeAll bool, verbose bool) error {
	config, err := loadAppConfig()
	if err != nil {
		return err
	}
	report, err := buildRouteShowReport(config, "", includeAll, time.Now(), false)
	if err != nil {
		return err
	}
	return printRouteShowReport(os.Stdout, report, includeAll, filter, verbose)
}

func mutateRouteWithConfig(config *appConfig, path zone.ZonePath, prefix string, active bool, now time.Time, direct bool) error {
	request := routeMutationRequest{Zone: path, Prefix: prefix, Active: active}
	if version, ok, err := sendVersionedMutationViaControl(config, controlRequest{Method: "route_mutate", Route: &request}, direct); ok {
		if err != nil {
			return err
		}
		fmt.Printf("%s route %s version %d via daemon\n", routeOpVerb(request.Active), request.Prefix, version)
		return nil
	}
	result, err := applyOfflineCommonIntent(config, commonRouteIntent(request), request.DryRun, now)
	if err != nil {
		return err
	}
	if result.Record == nil {
		return errors.New("route mutation did not return a record")
	}
	fmt.Printf("%s route %s/%s version %d\n", routeOpVerb(request.Active), result.Record.Zone, result.Record.Key, result.Record.Version)
	return nil
}

func buildRouteShowReport(config *appConfig, filterZone zone.ZonePath, includeAll bool, now time.Time, direct bool) (*inspect.RouteShowReport, error) {
	if report, ok, err := readCanonicalViewViaControl[inspect.RouteShowReport](config, controlRequest{Method: "route_view", Zone: filterZone.String(), IncludeAll: includeAll}, direct); err != nil {
		return nil, err
	} else if ok {
		return &report, nil
	}
	common, _, err := loadOfflineOwnerViews(config)
	if err != nil {
		return nil, err
	}
	if common.State == nil {
		return nil, errors.New("common state is not initialized")
	}
	return buildRouteShowReportFromState(common.State, now, filterZone, includeAll)
}

func buildRouteShowReportFromState(verified *corestate.VerifiedState, now time.Time, filterZone zone.ZonePath, includeAll bool) (*inspect.RouteShowReport, error) {
	report := &inspect.RouteShowReport{
		ManagedZone:   string(verified.ManagedZone),
		Announcements: []inspect.RouteShowRow{},
	}
	if verified.Network == nil {
		return report, nil
	}
	authorized := map[string]map[string]struct{}{}
	sharedRoutes := map[string]map[string]struct{}{}
	routeTags := map[string]map[string]string{}
	ars, arsErr := routing.BuildAuthorizedRouteSet(verified.Network, now)
	if arsErr == nil && ars != nil {
		for z, prefixes := range ars.Announced {
			key := string(z)
			if authorized[key] == nil {
				authorized[key] = map[string]struct{}{}
			}
			if sharedRoutes[key] == nil {
				sharedRoutes[key] = map[string]struct{}{}
			}
			if routeTags[key] == nil {
				routeTags[key] = map[string]string{}
			}
			for prefix, entry := range prefixes {
				authorized[key][prefix.String()] = struct{}{}
				if entry != nil {
					routeTags[key][prefix.String()] = entry.AssignmentTag
					if entry.SharedAssignment {
						sharedRoutes[key][prefix.String()] = struct{}{}
					}
				}
			}
		}
	}

	zones := make([]zone.ZonePath, 0, len(verified.Network.Zones))
	for path := range verified.Network.Zones {
		if filterZone != "" && path != filterZone {
			continue
		}
		zones = append(zones, path)
	}
	inspect.SortZonePaths(zones)

	for _, path := range zones {
		zs := verified.Network.Zones[path]
		if zs == nil {
			continue
		}
		keys := make([]string, 0, len(zs.Records))
		for key := range zs.Records {
			if strings.HasPrefix(key, routing.RecordKeyPrefixRoutes) {
				keys = append(keys, key)
			}
		}
		sort.Strings(keys)
		for _, key := range keys {
			rec := zs.Records[key]
			ann, err := routing.ParseRouteAnnouncementRecord(rec)
			if err != nil {
				continue
			}
			if !includeAll && !ann.Active {
				continue
			}
			prefix := ann.Prefix
			if p, err := netip.ParsePrefix(prefix); err == nil {
				prefix = p.Masked().String()
			}
			_, isAuthorized := authorized[string(path)][prefix]
			_, isShared := sharedRoutes[string(path)][prefix]
			if !isShared {
				isShared = routeUsesSharedAssignment(ars, path, prefix)
			}
			report.Announcements = append(report.Announcements, inspect.RouteShowRow{
				Zone:       string(path),
				Prefix:     prefix,
				Tag:        routeTags[string(path)][prefix],
				Shared:     isShared,
				Active:     ann.Active,
				Controller: ann.Controller,
				Authorized: isAuthorized,
				Version:    rec.Version,
				Key:        key,
			})
		}
	}
	sortRouteShowRows(report.Announcements)
	return report, nil
}

func sortRouteShowRows(rows []inspect.RouteShowRow) {
	sort.Slice(rows, func(i, j int) bool {
		a := rows[i]
		b := rows[j]
		if cmp := inspect.ComparePrefixStrings(a.Prefix, b.Prefix); cmp != 0 {
			return cmp < 0
		}
		if a.Zone != b.Zone {
			return inspect.ZonePathLess(a.Zone, b.Zone)
		}
		return a.Key < b.Key
	})
}

func printRouteShowReport(w io.Writer, report *inspect.RouteShowReport, includeAll bool, filter string, verbose bool) error {
	if report == nil {
		report = &inspect.RouteShowReport{}
	}
	filter = strings.ToLower(strings.TrimSpace(filter))
	rows := make([]inspect.RouteShowRow, 0, len(report.Announcements))
	for _, row := range report.Announcements {
		state := "active"
		if !row.Active {
			state = "withdrawn"
		}
		authorization := "unauthorized"
		if row.Authorized {
			authorization = "authorized"
		}
		mode := "non-shared"
		if row.Shared {
			mode = "shared"
		}
		searchable := strings.Join([]string{
			row.Prefix,
			row.Zone,
			row.Tag,
			state,
			row.Controller,
			authorization,
			mode,
			row.Key,
		}, " ")
		if filter == "" || strings.Contains(strings.ToLower(searchable), filter) {
			rows = append(rows, row)
		}
	}

	table := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	fmt.Fprintf(table, "managed_zone: %s\n", report.ManagedZone)
	if filter == "" {
		fmt.Fprintf(table, "announcements: %d\n", len(rows))
	} else {
		fmt.Fprintf(table, "announcements: %d/%d\n", len(rows), len(report.Announcements))
	}
	nonSharedRows := make([]inspect.RouteShowRow, 0, len(rows))
	sharedRows := make([]inspect.RouteShowRow, 0, len(rows))
	for _, row := range rows {
		if row.Shared {
			sharedRows = append(sharedRows, row)
		} else {
			nonSharedRows = append(nonSharedRows, row)
		}
	}

	fmt.Fprintf(table, "non_shared_announcements: %d\n", len(nonSharedRows))
	if err := printRouteShowRows(table, nonSharedRows, verbose, false); err != nil {
		return err
	}

	sort.SliceStable(sharedRows, func(i, j int) bool {
		if cmp := inspect.ComparePrefixStrings(sharedRows[i].Prefix, sharedRows[j].Prefix); cmp != 0 {
			return cmp < 0
		}
		if sharedRows[i].Zone != sharedRows[j].Zone {
			return inspect.ZonePathLess(sharedRows[i].Zone, sharedRows[j].Zone)
		}
		return sharedRows[i].Key < sharedRows[j].Key
	})
	sharedPrefixes := 0
	lastPrefix := ""
	for _, row := range sharedRows {
		if row.Prefix != lastPrefix {
			sharedPrefixes++
			lastPrefix = row.Prefix
		}
	}
	fmt.Fprintf(table, "shared_announcements: %d (%d prefixes)\n", len(sharedRows), sharedPrefixes)
	if err := printRouteShowRows(table, sharedRows, verbose, true); err != nil {
		return err
	}
	if len(rows) == 0 && !includeAll {
		fmt.Fprintln(table, "hint: use --all to include withdrawn announcements")
	}
	return table.Flush()
}

func routeShowHeader(verbose bool) []string {
	if verbose {
		return []string{"PREFIX", "ZONE", "TAG", "STATE", "AUTHORIZATION", "CONTROLLER", "VERSION", "RECORD"}
	}
	return []string{"PREFIX", "ZONE", "TAG", "STATE", "AUTHORIZATION"}
}

func routeShowCells(prefix string, row inspect.RouteShowRow, verbose bool) []string {
	state := "active"
	if !row.Active {
		state = "withdrawn"
	}
	authorized := "unauthorized"
	if row.Authorized {
		authorized = "authorized"
	}
	controller := "explicit"
	if row.Controller != "" {
		controller = row.Controller
	}
	if verbose {
		return []string{prefix, row.Zone, dash(row.Tag), state, authorized, controller, fmt.Sprint(row.Version), row.Key}
	}
	return []string{prefix, row.Zone, dash(row.Tag), state, authorized}
}

func printRouteShowRows(w io.Writer, routeRows []inspect.RouteShowRow, verbose, groupPrefix bool) error {
	rows := [][]string{routeShowHeader(verbose)}
	lastPrefix := ""
	for _, row := range routeRows {
		prefix := row.Prefix
		if groupPrefix {
			if prefix == lastPrefix {
				prefix = ""
			} else {
				lastPrefix = prefix
			}
		}
		rows = append(rows, routeShowCells(prefix, row, verbose))
	}
	return inspecttext.WriteAlignedRows(w, rows, 1)
}

func routeUsesSharedAssignment(ars *routing.AuthorizedRouteSet, path zone.ZonePath, prefix string) bool {
	if ars == nil {
		return false
	}
	routePrefix, err := netip.ParsePrefix(prefix)
	if err != nil {
		return false
	}
	for _, ancestor := range path.Ancestors() {
		for _, entry := range ars.AllAssignments {
			if entry == nil || entry.Source != ancestor || entry.Prefix.Bits() > routePrefix.Bits() || !entry.Prefix.Contains(routePrefix.Masked().Addr()) {
				continue
			}
			usable := routing.IsZoneAncestor(entry.AssignedTo, path) ||
				(routing.IsZoneAncestor(path, entry.AssignedTo) && entry.Source == path)
			if usable {
				return entry.Shared
			}
		}
	}
	return false
}

func routeOpVerb(active bool) string {
	if active {
		return "announced"
	}
	return "withdrew"
}
