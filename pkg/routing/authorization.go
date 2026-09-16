package routing

import (
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// RouteEntry represents an active, authorized route announcement.
type RouteEntry struct {
	Record           *zone.Record
	Source           zone.ZonePath
	Prefix           netip.Prefix
	Announcement     *RouteAnnouncementRecord
	SharedAssignment bool   // backed by an anycast/shared IPAM assignment
	AssignmentTag    string // tag of the assignment that authorized this route
}

// AssignmentEntry represents an active IPAM assignment record.
type AssignmentEntry struct {
	Prefix     netip.Prefix
	AssignedTo zone.ZonePath
	Source     zone.ZonePath
	Record     *zone.Record
	Assignment *IPAMAssignmentRecord
	Shared     bool // anycast assignment: overlaps with other shared assignments are allowed
	Tag        string
}

// PoolEntry represents an active IPAM pool record.
type PoolEntry struct {
	Prefix      netip.Prefix
	DelegatedTo zone.ZonePath
	Source      zone.ZonePath
	Record      *zone.Record
	Pool        *IPAMPoolRecord
}

// RouteAuthorizationError captures a non-fatal validation problem.
type RouteAuthorizationError struct {
	Zone   zone.ZonePath
	Prefix netip.Prefix
	Code   string
	Detail string
}

// AuthorizedRouteSet is the result of reconciling announcements with IPAM state.
type AuthorizedRouteSet struct {
	Announced   map[zone.ZonePath]map[netip.Prefix]*RouteEntry
	Assignments map[netip.Prefix]*AssignmentEntry // one representative entry per prefix (for quick lookup)
	// AllAssignments contains every valid assignment including anycast/shared
	// duplicates that share the same prefix. Consumers that must enumerate all
	// assignments (CLI listing, auto-announce, BIRD static routes) should
	// iterate this slice instead of the Assignments map.
	AllAssignments []*AssignmentEntry
	Pools          map[netip.Prefix]*PoolEntry // one representative valid pool per prefix
	// AllPools contains every valid pool, including entries with identical or
	// overlapping prefixes that would otherwise be hidden by the Pools map.
	AllPools []*PoolEntry
	Errors   []RouteAuthorizationError
}

// BuildAuthorizedRouteSet builds an authorized route set from verified active state.
func BuildAuthorizedRouteSet(ns *zone.NetworkState, now time.Time) (*AuthorizedRouteSet, error) {
	if ns == nil {
		return nil, errors.New("network state is nil")
	}

	ars := &AuthorizedRouteSet{
		Announced:   make(map[zone.ZonePath]map[netip.Prefix]*RouteEntry),
		Assignments: make(map[netip.Prefix]*AssignmentEntry),
		Pools:       make(map[netip.Prefix]*PoolEntry),
	}

	var pendingRoutes []*RouteEntry
	var pendingAssignments []*AssignmentEntry
	var pendingPools []*PoolEntry

	for path, zs := range ns.Zones {
		revoked := ns.IsZoneRevoked(path, now)

		for key, rec := range zs.Records {
			switch {
			case strings.HasPrefix(key, RecordKeyPrefixIPAMPools):
				if revoked {
					continue
				}
				pool, err := ParseIPAMPoolRecord(rec)
				if err != nil {
					ars.addError(path, netip.Prefix{}, "ipam_pool_invalid", err.Error())
					continue
				}
				if !pool.Active {
					continue
				}
				p := mustParsePrefix(pool.Prefix)
				pendingPools = append(pendingPools, &PoolEntry{
					Prefix:      p,
					DelegatedTo: pool.DelegatedTo,
					Source:      path,
					Record:      rec,
					Pool:        pool,
				})

			case strings.HasPrefix(key, RecordKeyPrefixIPAMAssignments):
				if revoked {
					continue
				}
				assignment, err := ParseIPAMAssignmentRecord(rec)
				if err != nil {
					ars.addError(path, netip.Prefix{}, "ipam_assignment_invalid", err.Error())
					continue
				}
				if !assignment.Active {
					continue
				}
				p := mustParsePrefix(assignment.Prefix)
				pendingAssignments = append(pendingAssignments, &AssignmentEntry{
					Prefix:     p,
					AssignedTo: assignment.AssignedTo,
					Source:     path,
					Record:     rec,
					Assignment: assignment,
					Shared:     assignment.Shared,
					Tag:        assignment.Tag,
				})

			case strings.HasPrefix(key, RecordKeyPrefixRoutes):
				ann, err := ParseRouteAnnouncementRecord(rec)
				if err != nil {
					ars.addError(path, netip.Prefix{}, "route_announcement_invalid", err.Error())
					continue
				}
				if !ann.Active {
					continue
				}
				if revoked {
					ars.addError(path, mustParsePrefix(ann.Prefix), "route_zone_revoked", "zone is revoked")
					continue
				}
				p := mustParsePrefix(ann.Prefix)
				pendingRoutes = append(pendingRoutes, &RouteEntry{
					Record:       rec,
					Source:       path,
					Prefix:       p,
					Announcement: ann,
				})
			}
		}
	}

	validPools := validatePools(pendingPools, ars)
	ars.AllPools = validPools
	for _, pool := range validPools {
		if ars.Pools[pool.Prefix] == nil {
			ars.Pools[pool.Prefix] = pool
		}
	}

	// Validate assignments against pools and detect overlaps before authorizing
	// announcements.
	validAssignments := validateAssignmentPools(pendingAssignments, ars)
	validAssignments, badTags := validateAssignmentTags(validAssignments)
	for entry := range badTags {
		ars.addError(entry.Source, entry.Prefix, "ipam_assignment_tag_conflict",
			fmt.Sprintf("shared assignment tag %q resolves to more than one prefix", entry.Tag))
	}
	validAssignments, badAssignments := validateAssignmentOverlaps(validAssignments, ns)
	for entry := range badAssignments {
		ars.addError(entry.Source, entry.Prefix, "ipam_assignment_overlap",
			fmt.Sprintf("assignment %s overlaps with another assignment outside the delegation chain", entry.Prefix))
	}

	// Store all valid assignments (including anycast duplicates sharing the
	// same prefix) and a representative in the prefix-keyed map for quick
	// lookups.
	ars.AllAssignments = validAssignments
	for _, entry := range validAssignments {
		if existing := ars.Assignments[entry.Prefix]; existing == nil || (existing.Shared && !entry.Shared) {
			ars.Assignments[entry.Prefix] = entry
		}
	}

	// Authorize pending announcements against assignments.
	var authorized []*RouteEntry
	for _, entry := range pendingRoutes {
		if assignment := findAssignmentForPrefix(ars, entry.Source, entry.Prefix); assignment != nil {
			entry.SharedAssignment = assignment.Shared
			entry.AssignmentTag = assignment.Tag
			authorized = append(authorized, entry)
		} else {
			ars.addError(entry.Source, entry.Prefix, "route_unauthorized_no_assignment", "no matching assignment")
		}
	}

	// Resolve overlapping prefixes.
	keep := resolveOverlaps(authorized, ars, ns)

	for _, entry := range keep {
		if ars.Announced[entry.Source] == nil {
			ars.Announced[entry.Source] = make(map[netip.Prefix]*RouteEntry)
		}
		ars.Announced[entry.Source][entry.Prefix] = entry
	}

	// Stable ordering for easier test assertions and debugging.
	sort.Slice(ars.Errors, func(i, j int) bool {
		if ars.Errors[i].Zone != ars.Errors[j].Zone {
			return ars.Errors[i].Zone < ars.Errors[j].Zone
		}
		if ars.Errors[i].Prefix.String() != ars.Errors[j].Prefix.String() {
			return ars.Errors[i].Prefix.String() < ars.Errors[j].Prefix.String()
		}
		return ars.Errors[i].Code < ars.Errors[j].Code
	})

	return ars, nil
}

func validateAssignmentTags(assignments []*AssignmentEntry) (kept []*AssignmentEntry, bad map[*AssignmentEntry]bool) {
	bad = make(map[*AssignmentEntry]bool)
	byTag := make(map[string]netip.Prefix)
	conflicted := make(map[string]bool)
	for _, entry := range assignments {
		if entry == nil || entry.Tag == "" {
			continue
		}
		key := assignmentTagFamilyKey(entry)
		if prefix, ok := byTag[key]; ok && prefix != entry.Prefix {
			conflicted[key] = true
		} else {
			byTag[key] = entry.Prefix
		}
	}
	for _, entry := range assignments {
		if entry != nil && conflicted[assignmentTagFamilyKey(entry)] {
			bad[entry] = true
			continue
		}
		kept = append(kept, entry)
	}
	return kept, bad
}

func assignmentTagFamilyKey(entry *AssignmentEntry) string {
	if entry == nil {
		return ""
	}
	family := "6"
	if entry.Prefix.Addr().Is4() {
		family = "4"
	}
	return entry.Tag + "/" + family
}

// IsZoneAncestor reports whether ancestor is the same zone as child or one of
// its parent zones.
func IsZoneAncestor(ancestor, child zone.ZonePath) bool {
	if ancestor == child {
		return true
	}
	return slices.Contains(child.Ancestors(), ancestor)
}

// IsInDelegationChain reports whether candidate is equal to target or is a
// descendant of target that has been delegated through the network state.
// It checks parent zone Delegations first, then falls back to the child's
// ParentProof cache.
func IsInDelegationChain(ns *zone.NetworkState, candidate, target zone.ZonePath) bool {
	if ns == nil {
		return false
	}
	if candidate == target {
		return true
	}
	if !IsZoneAncestor(target, candidate) {
		return false
	}

	current := candidate
	for current != target {
		parent := current.Parent()
		if parent == current {
			return false
		}

		parentState := ns.Zones[parent]
		if parentState != nil && parentState.Delegations[current] != nil {
			current = parent
			continue
		}

		childState := ns.Zones[current]
		if childState != nil && len(childState.ParentProof) > 0 {
			// ParentProof[0] is the direct parent->current delegation.
			if childState.ParentProof[0].ZoneName == current {
				current = parent
				continue
			}
		}

		return false
	}
	return true
}

func validatePools(pools []*PoolEntry, ars *AuthorizedRouteSet) []*PoolEntry {
	ownerValid := validatePoolOwnership(pools, ars)
	valid, bad := validatePoolOverlaps(ownerValid)
	for entry := range bad {
		ars.addError(entry.Source, entry.Prefix, "ipam_pool_overlap",
			fmt.Sprintf("pool %s overlaps with another pool outside the ownership chain", entry.Prefix))
	}
	return valid
}

func validatePoolOwnership(pools []*PoolEntry, ars *AuthorizedRouteSet) []*PoolEntry {
	valid := make(map[*PoolEntry]bool)
	for changed := true; changed; {
		changed = false
		for _, entry := range pools {
			if valid[entry] {
				continue
			}
			if isRootBootstrapPool(entry) || hasValidCoveringOwnerPool(valid, entry) {
				valid[entry] = true
				changed = true
			}
		}
	}

	out := make([]*PoolEntry, 0, len(valid))
	for _, entry := range pools {
		if valid[entry] {
			out = append(out, entry)
			continue
		}
		ars.addError(entry.Source, entry.Prefix, "ipam_pool_owner_mismatch",
			fmt.Sprintf("pool %s is not covered by a pool owned by %s", entry.Prefix, entry.Source))
	}
	return out
}

func isRootBootstrapPool(pool *PoolEntry) bool {
	return pool.Source == zone.RootZone && pool.DelegatedTo == zone.RootZone
}

func hasValidCoveringOwnerPool(valid map[*PoolEntry]bool, pool *PoolEntry) bool {
	for cover := range valid {
		if cover == pool {
			continue
		}
		if cover.DelegatedTo != pool.Source {
			continue
		}
		if containsPrefix(cover.Prefix, pool.Prefix) {
			return true
		}
	}
	return false
}

func validatePoolOverlaps(pools []*PoolEntry) (kept []*PoolEntry, bad map[*PoolEntry]bool) {
	bad = make(map[*PoolEntry]bool)
	for i := range pools {
		for j := i + 1; j < len(pools); j++ {
			a, b := pools[i], pools[j]
			if !a.Prefix.Overlaps(b.Prefix) {
				continue
			}
			if isPoolOverlapAllowed(pools, a, b) {
				continue
			}
			if containsPrefix(a.Prefix, b.Prefix) && !containsPrefix(b.Prefix, a.Prefix) {
				bad[b] = true
				continue
			}
			if containsPrefix(b.Prefix, a.Prefix) && !containsPrefix(a.Prefix, b.Prefix) {
				bad[a] = true
				continue
			}
			bad[a] = true
			bad[b] = true
		}
	}
	if len(bad) == 0 {
		return pools, bad
	}
	kept = make([]*PoolEntry, 0, len(pools)-len(bad))
	for _, entry := range pools {
		if bad[entry] {
			continue
		}
		kept = append(kept, entry)
	}
	return kept, bad
}

func isPoolOverlapAllowed(pools []*PoolEntry, a, b *PoolEntry) bool {
	if containsPrefix(a.Prefix, b.Prefix) && isContainedPoolOverlapAllowed(pools, a, b) {
		return true
	}
	if containsPrefix(b.Prefix, a.Prefix) && isContainedPoolOverlapAllowed(pools, b, a) {
		return true
	}
	return false
}

func isContainedPoolOverlapAllowed(pools []*PoolEntry, outer, inner *PoolEntry) bool {
	if outer.DelegatedTo == inner.Source {
		return true
	}
	for _, bridge := range pools {
		if bridge == inner || bridge == outer {
			continue
		}
		if bridge.DelegatedTo != inner.Source {
			continue
		}
		if containsPrefix(outer.Prefix, bridge.Prefix) && containsPrefix(bridge.Prefix, inner.Prefix) {
			return true
		}
	}
	return false
}

// validateAssignmentPools removes assignments that are not covered by a valid
// pool ownership. An assignment in zone Z is valid only if there exists a valid
// pool that covers the assignment prefix and is delegated exactly to Z.
func validateAssignmentPools(assignments []*AssignmentEntry, ars *AuthorizedRouteSet) []*AssignmentEntry {
	valid := make([]*AssignmentEntry, 0, len(assignments))
	for _, entry := range assignments {
		if isAssignmentPoolValid(ars, entry) {
			valid = append(valid, entry)
			continue
		}
		ars.addError(entry.Source, entry.Prefix, "ipam_assignment_pool_mismatch",
			fmt.Sprintf("assignment %s has no covering pool delegation", entry.Prefix))
	}
	return valid
}

func isAssignmentPoolValid(ars *AuthorizedRouteSet, assignment *AssignmentEntry) bool {
	for _, pool := range ars.AllPools {
		if pool.DelegatedTo != assignment.Source {
			continue
		}
		if containsPrefix(pool.Prefix, assignment.Prefix) {
			return true
		}
	}
	return false
}

// validateAssignmentOverlaps rejects assignments whose prefixes overlap unless
// the overlap is authorized by the delegation chain. It returns the kept
// assignments and a set of rejected assignments for error reporting.
func validateAssignmentOverlaps(assignments []*AssignmentEntry, ns *zone.NetworkState) (kept []*AssignmentEntry, bad map[*AssignmentEntry]bool) {
	bad = make(map[*AssignmentEntry]bool)
	for i := range assignments {
		for j := i + 1; j < len(assignments); j++ {
			a, b := assignments[i], assignments[j]
			if !a.Prefix.Overlaps(b.Prefix) {
				continue
			}
			if isAssignmentOverlapAllowed(ns, a, b) {
				continue
			}
			bad[a] = true
			bad[b] = true
		}
	}

	if len(bad) == 0 {
		return assignments, bad
	}

	kept = make([]*AssignmentEntry, 0, len(assignments)-len(bad))
	for _, entry := range assignments {
		if bad[entry] {
			continue
		}
		kept = append(kept, entry)
	}
	return kept, bad
}

func isAssignmentOverlapAllowed(ns *zone.NetworkState, a, b *AssignmentEntry) bool {
	// Anycast/shared assignments: allow overlap when both sides are marked
	// shared. This enables multiple zones to legitimately hold the same
	// prefix (e.g. anycast service IPs). A single shared assignment does not
	// exempt the other side from normal overlap rules if the other is not
	// also shared.
	if a.Shared && b.Shared {
		return true
	}

	// Same zone: allow hierarchical assignments where one assigned_to is a
	// strict ancestor of the other.
	if a.Source == b.Source {
		if a.AssignedTo != b.AssignedTo && (IsZoneAncestor(a.AssignedTo, b.AssignedTo) || IsZoneAncestor(b.AssignedTo, a.AssignedTo)) {
			return true
		}
		return false
	}

	// Different zones: require containment and delegation-chain relationship.
	contained := containsPrefix(a.Prefix, b.Prefix) || containsPrefix(b.Prefix, a.Prefix)
	inChain := IsInDelegationChain(ns, a.Source, b.Source) || IsInDelegationChain(ns, b.Source, a.Source)
	return contained && inChain
}

// findAssignmentForPrefix finds an assignment that authorizes prefix within
// zone z or one of its ancestor zones. It searches AllAssignments (including
// anycast/shared duplicates) so that multiple zones holding the same prefix
// are all checked.
func findAssignmentForPrefix(ars *AuthorizedRouteSet, z zone.ZonePath, prefix netip.Prefix) *AssignmentEntry {
	for _, ancestor := range z.Ancestors() {
		for _, entry := range ars.AllAssignments {
			if entry.Source != ancestor {
				continue
			}
			if !containsPrefix(entry.Prefix, prefix) {
				continue
			}
			// The assignment must be usable by the announcing zone.
			// Valid cases:
			//   1. AssignedTo == z (self-announcement)
			//   2. AssignedTo is an ancestor of z (z announces a sub-prefix
			//      assigned to an ancestor)
			//   3. AssignedTo is a descendant of z AND the assignment record
			//      itself lives in z (parent aggregate of a child-assigned prefix)
			assignedToUsable := IsZoneAncestor(entry.AssignedTo, z) ||
				(IsZoneAncestor(z, entry.AssignedTo) && entry.Source == z)
			if assignedToUsable {
				return entry
			}
		}
	}
	return nil
}

func containsPrefix(outer, inner netip.Prefix) bool {
	if outer.Bits() > inner.Bits() {
		return false
	}
	return outer.Contains(inner.Masked().Addr())
}

func (ars *AuthorizedRouteSet) addError(z zone.ZonePath, p netip.Prefix, code, detail string) {
	ars.Errors = append(ars.Errors, RouteAuthorizationError{
		Zone:   z,
		Prefix: p,
		Code:   code,
		Detail: detail,
	})
}

func resolveOverlaps(entries []*RouteEntry, ars *AuthorizedRouteSet, ns *zone.NetworkState) []*RouteEntry {
	bad := make(map[*RouteEntry]bool)

	for i := range entries {
		for j := i + 1; j < len(entries); j++ {
			a, b := entries[i], entries[j]
			if !a.Prefix.Overlaps(b.Prefix) {
				continue
			}

			// Anycast/shared announcements: allow overlap when both sides are
			// backed by shared assignments. Babel ECMP handles multipath to
			// the same prefix from multiple zones.
			if a.SharedAssignment && b.SharedAssignment {
				continue
			}

			contained := containsPrefix(a.Prefix, b.Prefix) || containsPrefix(b.Prefix, a.Prefix)
			inChain := IsInDelegationChain(ns, a.Source, b.Source) || IsInDelegationChain(ns, b.Source, a.Source)

			if !contained || !inChain {
				bad[a] = true
				bad[b] = true
			}
		}
	}

	if len(bad) == 0 {
		return entries
	}

	for entry := range bad {
		ars.addError(entry.Source, entry.Prefix, "route_overlap_unauthorized",
			fmt.Sprintf("overlapping prefix %s with another zone not in the same delegation chain", entry.Prefix))
	}

	keep := make([]*RouteEntry, 0, len(entries)-len(bad))
	for _, entry := range entries {
		if !bad[entry] {
			keep = append(keep, entry)
		}
	}
	return keep
}

func mustParsePrefix(s string) netip.Prefix {
	p, err := netip.ParsePrefix(s)
	if err != nil {
		panic(fmt.Sprintf("invalid prefix %q: %v", s, err))
	}
	return p.Masked()
}

// LocalAssignedPrefixes returns this zone's assigned prefixes, optionally including shared assignments.
func LocalAssignedPrefixes(ars *AuthorizedRouteSet, managedZone zone.ZonePath, includeShared bool) []netip.Prefix {
	if ars == nil || !managedZone.Valid() {
		return nil
	}
	outSet := make(map[netip.Prefix]struct{})
	if len(ars.AllAssignments) > 0 {
		for _, entry := range ars.AllAssignments {
			if entry == nil || entry.AssignedTo != managedZone || (!includeShared && entry.Shared) {
				continue
			}
			outSet[entry.Prefix] = struct{}{}
		}
	} else {
		for prefix, entry := range ars.Assignments {
			if entry == nil || entry.AssignedTo != managedZone || (!includeShared && entry.Shared) {
				continue
			}
			outSet[prefix] = struct{}{}
		}
	}
	out := make([]netip.Prefix, 0, len(outSet))
	for prefix := range outSet {
		out = append(out, prefix)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].Addr().Less(out[j].Addr()) || (out[i].Addr() == out[j].Addr() && out[i].Bits() < out[j].Bits())
	})
	return out
}
