package state

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/routing"
)

var ErrReservedRecordIntent = errors.New("record key or type is owned by a typed state API")

func validateGenericRecordIntent(intent PutRecordIntent) error {
	reservedPrefixes := []string{
		routing.RecordKeyPrefixIPAMPools,
		routing.RecordKeyPrefixIPAMAssignments,
		routing.RecordKeyPrefixRoutes,
		"services/",
		"routing/",
		"ipsec/",
		"sync/endpoint/",
	}
	for _, prefix := range reservedPrefixes {
		if strings.HasPrefix(intent.Key, prefix) {
			return fmt.Errorf("%w: key %q", ErrReservedRecordIntent, intent.Key)
		}
	}
	reservedTypes := []string{
		routing.RecordTypeIPAMPool,
		routing.RecordTypeIPAMAssignment,
		routing.RecordTypeRouteAnnouncement,
		routing.RecordTypeRoutingNetns,
		"service.socks5.v1",
		"ipsec.profile.v1",
		"ipsec.addresses.v1",
		"ipsec.ports.v1",
		"ipsec.transport_key.v1",
		"ipsec.overlay_intent.v1",
		"sync.endpoint",
	}
	if slices.Contains(reservedTypes, intent.Type) {
		return fmt.Errorf("%w: type %q", ErrReservedRecordIntent, intent.Type)
	}
	return nil
}

func applyPutIPAMPoolIntent(state *VerifiedState, intent PutIPAMPoolIntent, now time.Time) (*zone.Record, zone.ZonePath, error) {
	if !intent.Zone.Valid() || !intent.DelegatedTo.Valid() {
		return nil, "", zone.ErrInvalidZonePath
	}
	canonical, key, err := canonicalIPAMKey(intent.Prefix, routing.NormalizeIPAMPoolKey)
	if err != nil {
		return nil, "", err
	}
	value, err := json.Marshal(routing.IPAMPoolRecord{Version: 1, Prefix: canonical, DelegatedTo: intent.DelegatedTo, Active: true})
	if err != nil {
		return nil, "", err
	}
	if err := checkIPAMWriteCapability(state, intent.Zone, key); err != nil {
		return nil, "", err
	}
	if err := validateIPAMCandidate(state.Network, intent.Zone, key, value, routing.RecordTypeIPAMPool, canonical,
		now, "ipam_pool_owner_mismatch", "ipam_pool_overlap"); err != nil {
		return nil, "", err
	}
	return applyPutRecordIntent(state, PutRecordIntent{Zone: intent.Zone, Key: key, Type: routing.RecordTypeIPAMPool, Value: value}, now)
}

func applyRevokeIPAMPoolIntent(state *VerifiedState, intent RevokeIPAMPoolIntent, now time.Time) (*zone.Record, zone.ZonePath, error) {
	canonical, key, err := canonicalIPAMKey(intent.Prefix, routing.NormalizeIPAMPoolKey)
	if err != nil {
		return nil, "", err
	}
	current := recordAt(state, intent.Zone, key)
	pool, err := routing.ParseIPAMPoolRecord(current)
	if err != nil {
		if current == nil {
			return nil, "", fmt.Errorf("no active ipam.pool for %s in %s", canonical, intent.Zone)
		}
		return nil, "", fmt.Errorf("current pool record for %s is invalid: %w", canonical, err)
	}
	if !pool.Active {
		return nil, "", fmt.Errorf("pool %s in %s is already revoked", canonical, intent.Zone)
	}
	if err := checkIPAMWriteCapability(state, intent.Zone, key); err != nil {
		return nil, "", err
	}
	pool.Active = false
	value, err := json.Marshal(pool)
	if err != nil {
		return nil, "", err
	}
	return applyPutRecordIntent(state, PutRecordIntent{Zone: intent.Zone, Key: key, Type: routing.RecordTypeIPAMPool, Value: value}, now)
}

func applyPutIPAMAssignmentIntent(state *VerifiedState, intent PutIPAMAssignmentIntent, now time.Time) (*zone.Record, zone.ZonePath, error) {
	if !intent.Zone.Valid() || !intent.AssignedTo.Valid() {
		return nil, "", zone.ErrInvalidZonePath
	}
	canonical, key, err := canonicalIPAMKey(intent.Prefix, routing.NormalizeIPAMAssignmentKey)
	if err != nil {
		return nil, "", err
	}
	if intent.Shared {
		key += "#" + strings.TrimSuffix(intent.AssignedTo.String(), ".")
	}
	record := routing.IPAMAssignmentRecord{
		Version: 1, Prefix: canonical, AssignedTo: intent.AssignedTo, Active: true, Shared: intent.Shared, Tag: intent.Tag,
	}
	if err := record.Validate(intent.Zone); err != nil {
		return nil, "", err
	}
	value, err := json.Marshal(record)
	if err != nil {
		return nil, "", err
	}
	if err := checkIPAMWriteCapability(state, intent.Zone, key); err != nil {
		return nil, "", err
	}
	if err := validateIPAMCandidate(state.Network, intent.Zone, key, value, routing.RecordTypeIPAMAssignment, canonical,
		now, "ipam_assignment_pool_mismatch", "ipam_assignment_overlap", "ipam_assignment_tag_conflict"); err != nil {
		return nil, "", err
	}
	return applyPutRecordIntent(state, PutRecordIntent{Zone: intent.Zone, Key: key, Type: routing.RecordTypeIPAMAssignment, Value: value}, now)
}

func applyRevokeIPAMAssignmentIntent(state *VerifiedState, intent RevokeIPAMAssignmentIntent, now time.Time) (*zone.Record, zone.ZonePath, error) {
	canonical, baseKey, err := canonicalIPAMKey(intent.Prefix, routing.NormalizeIPAMAssignmentKey)
	if err != nil {
		return nil, "", err
	}
	key, assignment, err := findActiveAssignment(state, intent.Zone, baseKey, canonical, intent.AssignedTo)
	if err != nil {
		return nil, "", err
	}
	if err := checkIPAMWriteCapability(state, intent.Zone, key); err != nil {
		return nil, "", err
	}
	assignment.Active = false
	value, err := json.Marshal(assignment)
	if err != nil {
		return nil, "", err
	}
	return applyPutRecordIntent(state, PutRecordIntent{Zone: intent.Zone, Key: key, Type: routing.RecordTypeIPAMAssignment, Value: value}, now)
}

func applyRouteIntent(state *VerifiedState, path zone.ZonePath, prefix, controller string, active bool, now time.Time) (*zone.Record, zone.ZonePath, error) {
	if !path.Valid() {
		return nil, "", zone.ErrInvalidZonePath
	}
	canonical, key, err := canonicalIPAMKey(prefix, routing.NormalizeRouteAnnouncementKey)
	if err != nil {
		return nil, "", err
	}
	if !active {
		current := recordAt(state, path, key)
		announcement, parseErr := routing.ParseRouteAnnouncementRecord(current)
		if parseErr != nil {
			if current == nil {
				return nil, "", fmt.Errorf("no active route announcement for %s in %s", canonical, path)
			}
			return nil, "", fmt.Errorf("current route record for %s is invalid: %w", canonical, parseErr)
		}
		if !announcement.Active {
			return nil, "", fmt.Errorf("route %s in %s is already withdrawn", canonical, path)
		}
	}
	if controller != "" && controller != routing.RouteControllerAuto {
		return nil, "", fmt.Errorf("unknown route controller: %s", controller)
	}
	value, err := json.Marshal(routing.RouteAnnouncementRecord{Version: 1, Prefix: canonical, Active: active, Controller: controller})
	if err != nil {
		return nil, "", err
	}
	if active {
		candidate := zone.CloneNetworkStateForZone(state.Network, path)
		zs := candidate.Zones[path]
		if zs == nil {
			return nil, "", fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
		}
		ensureZoneCollections(zs)
		zs.Records[key] = &zone.Record{Zone: path, Key: key, Type: routing.RecordTypeRouteAnnouncement, Value: value}
		authorized, err := routing.BuildAuthorizedRouteSet(candidate, now)
		if err != nil {
			return nil, "", err
		}
		found := false
		for announced := range authorized.Announced[path] {
			if announced.String() == canonical {
				found = true
				break
			}
		}
		if !found {
			for _, authErr := range authorized.Errors {
				if authErr.Zone == path && authErr.Prefix.String() == canonical {
					return nil, "", fmt.Errorf("%s: %s", authErr.Code, authErr.Detail)
				}
			}
			return nil, "", fmt.Errorf("route_unauthorized_no_assignment: no matching assignment for %s in %s", canonical, path)
		}
	}
	return applyPutRecordIntent(state, PutRecordIntent{Zone: path, Key: key, Type: routing.RecordTypeRouteAnnouncement, Value: value}, now)
}

func canonicalIPAMKey(prefix string, normalize func(string) (string, error)) (string, string, error) {
	canonical, err := routing.CanonicalizePrefix(prefix)
	if err != nil {
		return "", "", fmt.Errorf("invalid prefix %q: %w", prefix, err)
	}
	key, err := normalize(canonical)
	if err != nil {
		return "", "", err
	}
	return canonical, key, nil
}

func checkIPAMWriteCapability(state *VerifiedState, path zone.ZonePath, key string) error {
	if state == nil || state.Network == nil {
		return ErrInvalidStateRoot
	}
	zs := state.Network.Zones[path]
	if zs == nil || zs.Authority == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	if path == zone.RootZone {
		return nil
	}
	for _, authorizedKey := range zs.Authority.Keys {
		for _, capability := range authorizedKey.Capabilities {
			if capability.KeyPrefix != "" && !strings.HasPrefix(key, capability.KeyPrefix) {
				continue
			}
			if slices.Contains(capability.Permissions, zone.PermAllocateIP) {
				return nil
			}
		}
	}
	return fmt.Errorf("zone %s authority lacks allocate-ip capability for key %s", path, key)
}

func validateIPAMCandidate(network *zone.NetworkState, path zone.ZonePath, key string, value []byte, recordType, canonical string,
	now time.Time, rejectCodes ...string,
) error {
	candidate := zone.CloneNetworkStateForZone(network, path)
	zs := candidate.Zones[path]
	if zs == nil {
		return fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	ensureZoneCollections(zs)
	zs.Records[key] = &zone.Record{Zone: path, Key: key, Type: recordType, Value: append([]byte(nil), value...)}
	authorized, err := routing.BuildAuthorizedRouteSet(candidate, now)
	if err != nil {
		return err
	}
	reject := make(map[string]bool, len(rejectCodes))
	for _, code := range rejectCodes {
		reject[code] = true
	}
	for _, authErr := range authorized.Errors {
		if authErr.Zone == path && authErr.Prefix.String() == canonical && reject[authErr.Code] {
			return fmt.Errorf("%s: %s", authErr.Code, authErr.Detail)
		}
	}
	return nil
}

func findActiveAssignment(state *VerifiedState, path zone.ZonePath, baseKey, canonical string, target zone.ZonePath) (string, *routing.IPAMAssignmentRecord, error) {
	if state == nil || state.Network == nil || state.Network.Zones[path] == nil {
		return "", nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	type match struct {
		key        string
		assignment *routing.IPAMAssignmentRecord
	}
	var matches []match
	foundInactive := false
	for key, record := range state.Network.Zones[path].Records {
		if key != baseKey && !strings.HasPrefix(key, baseKey+"#") {
			continue
		}
		assignment, err := routing.ParseIPAMAssignmentRecord(record)
		if err != nil || assignment.Prefix != canonical || (target.Valid() && assignment.AssignedTo != target) {
			continue
		}
		if !assignment.Active {
			foundInactive = true
			continue
		}
		matches = append(matches, match{key: key, assignment: assignment})
	}
	if len(matches) == 0 {
		if foundInactive {
			return "", nil, fmt.Errorf("assignment %s in %s is already revoked", canonical, path)
		}
		return "", nil, fmt.Errorf("no active ipam.assignment for %s in %s", canonical, path)
	}
	if len(matches) > 1 {
		return "", nil, fmt.Errorf("multiple shared assignments exist for %s in %s; specify assigned zone", canonical, path)
	}
	return matches[0].key, matches[0].assignment, nil
}

func recordAt(state *VerifiedState, path zone.ZonePath, key string) *zone.Record {
	if state == nil || state.Network == nil || state.Network.Zones[path] == nil {
		return nil
	}
	return state.Network.Zones[path].Records[key]
}
