package zone

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

var (
	ErrInvalidZonePath    = errors.New("invalid zone path")
	ErrInvalidFQKey       = errors.New("invalid fully-qualified key")
	ErrZoneNotFound       = errors.New("zone not found")
	ErrRecordNotFound     = errors.New("record not found")
	ErrStaleRecord        = errors.New("stale record version")
	ErrRecordConflict     = errors.New("record version conflict")
	ErrInvalidRecordChain = errors.New("invalid record version chain")
	ErrZoneRevoked        = errors.New("zone revoked")
)

const MaxRecordHistoryPerKey = 16

func ParseFQKey(fqkey string) (ZonePath, string, error) {
	zonePart, key, ok := strings.Cut(fqkey, "/")
	if !ok || key == "" {
		return "", "", ErrInvalidFQKey
	}

	zp := ZonePath(zonePart)
	if !zp.Valid() {
		return "", "", ErrInvalidZonePath
	}

	return zp, key, nil
}

func (ns *NetworkState) Get(fqkey string) (*Record, error) {
	zp, key, err := ParseFQKey(fqkey)
	if err != nil {
		return nil, err
	}

	for _, current := range zp.Ancestors() {
		if ns.IsZoneRevoked(current, time.Now()) {
			continue
		}
		zs := ns.Zones[current]
		if zs == nil {
			continue
		}
		if r := zs.Records[key]; r != nil {
			return r, nil
		}
	}

	return nil, fmt.Errorf("%w: %s", ErrRecordNotFound, fqkey)
}

func (ns *NetworkState) Put(record *Record) error {
	return ns.PutAt(record, time.Now())
}

func (ns *NetworkState) PutAt(record *Record, now time.Time) error {
	if ns.RecordVerifier == nil && ns.RecordHasher == nil {
		return ns.PutTrusted(record)
	}

	if record == nil {
		return errors.New("record is nil")
	}
	if !record.Zone.Valid() {
		return ErrInvalidZonePath
	}
	if record.Key == "" {
		return ErrInvalidFQKey
	}
	if record.Version == 0 {
		return ErrInvalidRecordChain
	}
	if ns.IsZoneRevoked(record.Zone, now) {
		return fmt.Errorf("%w: %s", ErrZoneRevoked, record.Zone)
	}

	zs := ns.Zones[record.Zone]
	if zs == nil {
		return fmt.Errorf("%w: %s", ErrZoneNotFound, record.Zone)
	}

	if ns.RecordVerifier != nil {
		if err := ns.RecordVerifier(record, zs.Authority, now); err != nil {
			return err
		}
	}

	current := zs.Records[record.Key]
	if current == nil {
		zs.Records[record.Key] = record
		return nil
	}

	if record.Version < current.Version {
		return ErrStaleRecord
	}
	if record.Version == current.Version {
		if ns.sameRecord(record, current) {
			return nil
		}
		return ErrRecordConflict
	}
	if record.Version == current.Version+1 && ns.RecordHasher != nil && len(record.PrevHash) > 0 && !equalBytes(record.PrevHash, ns.RecordHasher(current)) {
		return ErrRecordConflict
	}

	zs.RecordHistory[record.Key] = appendBoundedHistory(zs.RecordHistory[record.Key], current)
	zs.Records[record.Key] = record
	return nil
}

func (ns *NetworkState) IsZoneRevoked(path ZonePath, now time.Time) bool {
	return ns.ActiveRevocation(path, now) != nil
}

func (ns *NetworkState) ActiveRevocation(path ZonePath, now time.Time) *DelegationRevocation {
	if ns == nil || !path.Valid() || path == RootZone {
		return nil
	}
	for current := path; current != RootZone; current = current.Parent() {
		parent := current.Parent()
		parentState := ns.Zones[parent]
		if parentState == nil {
			continue
		}
		revocation := parentState.Revocations[current]
		if revocation == nil || revocation.ChildZone != current || revocation.ParentZone != parent {
			continue
		}
		if revocation.RevokedAt > 0 && now.Unix() < revocation.RevokedAt {
			continue
		}
		if delegation := parentState.Delegations[current]; delegation != nil {
			hashMatches := equalBytes(revocation.RevokedAuthorityHash, delegation.AuthorityHash)
			epochCovers := revocation.RevokedAuthorityEpoch >= delegation.AuthorityEpoch
			if !hashMatches && !epochCovers {
				continue
			}
		}
		return revocation
	}
	return nil
}

func (ns *NetworkState) sameRecord(a, b *Record) bool {
	if ns.RecordHasher != nil {
		return equalBytes(ns.RecordHasher(a), ns.RecordHasher(b))
	}
	return a == b
}

func equalBytes(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var out byte
	for i := range a {
		out |= a[i] ^ b[i]
	}
	return out == 0
}

func (ns *NetworkState) PutTrusted(record *Record) error {
	if record == nil {
		return errors.New("record is nil")
	}
	if !record.Zone.Valid() {
		return ErrInvalidZonePath
	}
	if record.Key == "" {
		return ErrInvalidFQKey
	}
	if ns.IsZoneRevoked(record.Zone, time.Now()) {
		return fmt.Errorf("%w: %s", ErrZoneRevoked, record.Zone)
	}

	zs := ns.Zones[record.Zone]
	if zs == nil {
		return fmt.Errorf("%w: %s", ErrZoneNotFound, record.Zone)
	}

	current := zs.Records[record.Key]
	if current != nil {
		zs.RecordHistory[record.Key] = appendBoundedHistory(zs.RecordHistory[record.Key], current)
	}
	zs.Records[record.Key] = record
	return nil
}

func appendBoundedHistory(history []*Record, record *Record) []*Record {
	if record == nil {
		return history
	}
	return boundRecordHistory(append(history, record))
}

func boundRecordHistory(history []*Record) []*Record {
	if len(history) <= MaxRecordHistoryPerKey {
		return history
	}
	return append([]*Record(nil), history[len(history)-MaxRecordHistoryPerKey:]...)
}

// RevokedZones projects active revocations, including purged tombstones and descendants.
func (network *NetworkState) RevokedZones(now time.Time) map[ZonePath]bool {
	out := make(map[ZonePath]bool)
	if network == nil {
		return out
	}
	for z := range network.Zones {
		if z.IsRoot() {
			continue
		}
		if network.IsZoneRevoked(z, now) {
			out[z] = true
		}
	}
	// A purge may remove the revoked ZoneState while retaining its signed
	// revocation in the parent. Include those direct tombstone paths too.
	for _, parent := range network.Zones {
		if parent == nil {
			continue
		}
		for path := range parent.Revocations {
			if network.IsZoneRevoked(path, now) {
				out[path] = true
			}
		}
	}
	return out
}
