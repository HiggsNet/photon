package text

import (
	"io"
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/HiggsNet/photon/internal/inspect"
)

func WriteRoutesDebug(w io.Writer, dump *inspect.RoutesResponse) error {
	if dump == nil {
		dump = &inspect.RoutesResponse{}
	}
	out := newLineWriter(w)
	out.Linef("route_source: gossip_announcements_and_ipam_authorization")
	out.Linef("local_zone: %s", dump.LocalZone)
	out.Linef("export_prefixes: %d", len(dump.ExportSet))
	for _, p := range dump.ExportSet {
		out.Linef("  %s", p)
	}
	zones := make([]string, 0, len(dump.Authorized))
	for z := range dump.Authorized {
		zones = append(zones, z)
	}
	inspect.SortZoneStrings(zones)
	out.Linef("authorized_prefixes: %d zones", len(zones))
	for _, z := range zones {
		out.Linef("zone %s", z)
		for _, p := range dump.Authorized[z] {
			out.Linef("  %s", p)
		}
	}
	out.Linef("authorization_errors: %d", len(dump.Errors))
	for _, e := range dump.Errors {
		out.Linef("  zone=%s prefix=%s code=%s detail=%s", e.Zone, dash(e.Prefix), e.Code, e.Detail)
	}
	out.Linef("bird_cross_view: %d instances", len(dump.BIRD))
	for _, inst := range dump.BIRD {
		out.Linef("netns %s", inst.NetNS)
		out.Linef("  instance_id: %s", dash(inst.InstanceID))
		out.LineIf(inst.State != "", "  state: %s", inst.State)
		out.LineIf(inst.Failure != nil, "  failure: %s", failureDisplay(inst.Failure))
		out.Linef("  routes: %d", len(inst.Routes))
		for _, route := range inst.Routes {
			out.Printf("    %s selected=%t authorized=%t import_allowed=%t",
				route.Prefix, route.Selected, route.Authorized, route.ImportAllowed)
			out.PrintIf(len(route.Zones) > 0, " zones=%s", strings.Join(route.Zones, ","))
			out.PrintIf(route.Protocol != "", " protocol=%s", route.Protocol)
			out.PrintIf(route.Source != "", " source=%s", route.Source)
			out.PrintIf(route.Iface != "", " iface=%s", route.Iface)
			out.PrintIf(route.Via != "", " via=%s", route.Via)
			out.PrintIf(route.From != "", " from=%s", route.From)
			out.PrintIf(route.Metric > 0, " metric=%d", route.Metric)
			out.Blank()
		}
	}
	return out.Err()
}

func WriteRouteDebug(w io.Writer, prefix netip.Prefix, dump *inspect.RoutesResponse) error {
	if dump == nil {
		dump = &inspect.RoutesResponse{}
	}
	prefixStr := prefix.String()
	out := newLineWriter(w)
	out.Linef("route_source: gossip_announcements_and_ipam_authorization")
	out.Linef("prefix: %s", prefixStr)

	localExport := slices.Contains(dump.ExportSet, prefixStr)
	out.Linef("local_export: %t", localExport)

	authorized := false
	zones := make([]string, 0)
	for z, prefixes := range dump.Authorized {
		if slices.Contains(prefixes, prefixStr) {
			authorized = true
			zones = append(zones, z)
		}
	}
	inspect.SortZoneStrings(zones)
	out.Linef("authorized: %t", authorized)
	if len(zones) == 0 {
		out.Println("announcing_zones: -")
	} else {
		out.Linef("announcing_zones: %s", strings.Join(zones, ", "))
	}

	matchedAssignment := inspect.RouteAssignment{}
	matchedBits := -1
	for assignPrefixStr, assignment := range dump.Assignments {
		assignPrefix, err := netip.ParsePrefix(assignPrefixStr)
		if err != nil {
			continue
		}
		if assignPrefix.Bits() > prefix.Bits() {
			continue
		}
		if assignPrefix.Contains(prefix.Masked().Addr()) {
			if matchedBits == -1 || assignPrefix.Bits() > matchedBits {
				matchedAssignment = assignment
				matchedBits = assignPrefix.Bits()
			}
		}
	}
	if matchedBits != -1 {
		out.Linef("assignment_source: %s", matchedAssignment.Source)
		out.Linef("assignment_assigned_to: %s", matchedAssignment.AssignedTo)
	} else {
		out.Println("assignment_source: -")
		out.Println("assignment_assigned_to: -")
	}

	prefixErrors := make([]inspect.RouteAuthorizationError, 0)
	for _, e := range dump.Errors {
		if e.Prefix == prefixStr {
			prefixErrors = append(prefixErrors, e)
		}
	}
	out.Linef("authorization_errors: %d", len(prefixErrors))
	for _, e := range prefixErrors {
		out.Linef("  zone=%s code=%s detail=%s", e.Zone, e.Code, e.Detail)
	}
	matches := BirdRoutesMatchingPrefix(dump, prefixStr)
	out.Linef("bird_cross_view: %d", len(matches))
	for _, match := range matches {
		out.Printf("  netns=%s instance=%s selected=%t authorized=%t import_allowed=%t",
			match.NetNS, dash(match.InstanceID), match.Route.Selected, match.Route.Authorized, match.Route.ImportAllowed)
		out.PrintIf(match.Route.Protocol != "", " protocol=%s", match.Route.Protocol)
		out.PrintIf(match.Route.Iface != "", " iface=%s", match.Route.Iface)
		out.PrintIf(match.Route.Metric > 0, " metric=%d", match.Route.Metric)
		out.Blank()
	}
	return out.Err()
}

type BirdRoutePrefixMatch struct {
	NetNS      string
	InstanceID string
	Route      inspect.BirdRouteView
}

func BirdRoutesMatchingPrefix(dump *inspect.RoutesResponse, prefix string) []BirdRoutePrefixMatch {
	if dump == nil {
		return nil
	}
	matches := make([]BirdRoutePrefixMatch, 0)
	for _, inst := range dump.BIRD {
		for _, route := range inst.Routes {
			if route.Prefix != prefix {
				continue
			}
			matches = append(matches, BirdRoutePrefixMatch{
				NetNS:      inst.NetNS,
				InstanceID: inst.InstanceID,
				Route:      route,
			})
		}
	}
	sort.Slice(matches, func(i, j int) bool {
		if matches[i].NetNS != matches[j].NetNS {
			return matches[i].NetNS < matches[j].NetNS
		}
		if matches[i].InstanceID != matches[j].InstanceID {
			return matches[i].InstanceID < matches[j].InstanceID
		}
		return matches[i].Route.Iface < matches[j].Route.Iface
	})
	return matches
}
