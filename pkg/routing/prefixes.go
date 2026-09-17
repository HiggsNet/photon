package routing

import (
	"net/netip"
	"slices"
	"sort"
	"strings"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// AuthorizedPrefixes returns announced prefixes authorized for the selected zones, or all zones when empty.
func AuthorizedPrefixes(ars *AuthorizedRouteSet, zones []zone.ZonePath) []netip.Prefix {
	if ars == nil {
		return nil
	}
	var out []netip.Prefix
	for source, prefixes := range ars.Announced {
		if len(zones) > 0 {
			found := slices.Contains(zones, source)
			if !found {
				continue
			}
		}
		for prefix := range prefixes {
			out = append(out, prefix)
		}
	}
	return out
}

// AutoAnnounceAssignedPrefixes selects local assignments eligible for automatic announcement.
func AutoAnnounceAssignedPrefixes(ars *AuthorizedRouteSet, managedZone zone.ZonePath, announceAll bool, selectors []string) []netip.Prefix {
	if ars == nil || !managedZone.Valid() || (!announceAll && len(selectors) == 0) {
		return nil
	}
	entries := ars.AllAssignments
	if len(entries) == 0 {
		entries = make([]*AssignmentEntry, 0, len(ars.Assignments))
		for _, entry := range ars.Assignments {
			entries = append(entries, entry)
		}
	}
	selected := make(map[netip.Prefix]struct{})
	for _, entry := range entries {
		if entry == nil || entry.AssignedTo != managedZone {
			continue
		}
		if announceAll || assignmentMatchesAnnounceSelectors(entry, selectors) {
			selected[entry.Prefix] = struct{}{}
		}
	}
	out := make([]netip.Prefix, 0, len(selected))
	for prefix := range selected {
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Addr() != out[j].Addr() {
			return out[i].Addr().Less(out[j].Addr())
		}
		return out[i].Bits() < out[j].Bits()
	})
	return out
}

func assignmentMatchesAnnounceSelectors(entry *AssignmentEntry, selectors []string) bool {
	for _, selector := range selectors {
		switch {
		case selector == "all":
			return true
		case selector == "non-shared" && !entry.Shared:
			return true
		case selector == "shared" && entry.Shared:
			return true
		case strings.HasPrefix(selector, "tag:") && entry.Tag == strings.TrimPrefix(selector, "tag:"):
			return true
		case strings.HasPrefix(selector, "assignment:") && entry.Prefix.String() == strings.TrimPrefix(selector, "assignment:"):
			return true
		}
	}
	return false
}
