// Package state owns Photon verified-state DTOs and pure verification/COW
// operations shared by Linux and Windows runtimes.
package state

import (
	"bytes"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/vmihailenco/msgpack/v5"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

var (
	ErrZoneSnapshotTooLarge = errors.New("zone snapshot exceeds quota")
	ErrUntrustedZone        = errors.New("zone is not under a trusted root")
	ErrStaleAuthority       = errors.New("stale zone authority epoch")
	ErrAuthorityConflict    = errors.New("zone authority conflicts at the same epoch")
	ErrRootAuthorityChange  = errors.New("root authority is immutable")
	ErrStaleDelegation      = errors.New("stale delegation authority epoch")
	ErrDelegationConflict   = errors.New("delegation conflicts at the same authority epoch")
)

const DefaultSnapshotMaxBytes = 1200

type RecordSnapshot struct {
	Zone   zone.ZonePath `json:"zone" msgpack:"z"`
	Record *zone.Record  `json:"record" msgpack:"r"`
}

type ZoneSnapshot struct {
	Zone          zone.ZonePath                                `json:"zone" msgpack:"z"`
	Authority     *zone.ZoneAuthority                          `json:"authority" msgpack:"a"`
	ParentProof   []*zone.Delegation                           `json:"parent_proof,omitempty" msgpack:"pp,omitempty"`
	Delegations   map[zone.ZonePath]*zone.Delegation           `json:"delegations,omitempty" msgpack:"d,omitempty"`
	Revocations   map[zone.ZonePath]*zone.DelegationRevocation `json:"revocations,omitempty" msgpack:"rv,omitempty"`
	Records       map[string]*zone.Record                      `json:"records,omitempty" msgpack:"rc,omitempty"`
	RecordHistory map[string][]*zone.Record                    `json:"record_history,omitempty" msgpack:"rh,omitempty"`
}

type SyncLimits struct {
	MaxZones   int
	MaxRecords int
	MaxBytes   int
}

type ApplyResult struct {
	Zone             zone.ZonePath
	Records          int
	Delegation       int
	ZoneRootChanged  bool
	AuthorityChanged bool
	NetworkChanged   bool
}

func DefaultSyncLimits() SyncLimits {
	return SyncLimits{
		MaxZones:   16,
		MaxRecords: 1024,
		MaxBytes:   DefaultSnapshotMaxBytes,
	}
}

func Snapshot(ns *zone.NetworkState, path zone.ZonePath) (*ZoneSnapshot, error) {
	if ns == nil {
		return nil, errors.New("network state is nil")
	}
	zs := ns.Zones[path]
	if zs == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	return &ZoneSnapshot{
		Zone:        path,
		Authority:   cloneAuthority(zs.Authority),
		ParentProof: snapshotParentProof(ns, path, zs),
		Delegations: cloneDelegationMap(zs.Delegations),
		Revocations: cloneRevocationMap(zs.Revocations),
		Records:     cloneRecordMap(zs.Records),
	}, nil
}

func RecordSnapshotFor(ns *zone.NetworkState, path zone.ZonePath, key string, version uint64) (*RecordSnapshot, error) {
	if ns == nil {
		return nil, errors.New("network state is nil")
	}
	if !path.Valid() || key == "" {
		return nil, zone.ErrInvalidFQKey
	}
	zs := ns.Zones[path]
	if zs == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	for _, record := range append([]*zone.Record(nil), zs.RecordHistory[key]...) {
		if record != nil && (version == 0 || record.Version == version) {
			return &RecordSnapshot{Zone: path, Record: cloneRecord(record)}, nil
		}
	}
	if record := zs.Records[key]; record != nil && (version == 0 || record.Version == version) {
		return &RecordSnapshot{Zone: path, Record: cloneRecord(record)}, nil
	}
	return nil, fmt.Errorf("%w: %s/%s", zone.ErrRecordNotFound, path, key)
}

// ApplySnapshot validates and applies snapshot to a detached target-zone COW
// candidate. It never mutates ns. On success the caller owns the returned
// NetworkState and may publish it atomically; on failure no candidate is
// returned.
func ApplySnapshot(ns *zone.NetworkState, snapshot *ZoneSnapshot, now time.Time, limits SyncLimits) (*zone.NetworkState, *ApplyResult, error) {
	return applySnapshot(ns, snapshot, now, limits, false)
}

// ApplyRecoverySnapshot applies an explicitly selected recovery snapshot after
// normal cryptographic verification, but permits it to replace a conflicting
// non-root authority/delegation version. The root authority remains immutable.
func ApplyRecoverySnapshot(ns *zone.NetworkState, snapshot *ZoneSnapshot, now time.Time, limits SyncLimits) (*zone.NetworkState, *ApplyResult, error) {
	return applySnapshot(ns, snapshot, now, limits, true)
}

func applySnapshot(ns *zone.NetworkState, snapshot *ZoneSnapshot, now time.Time, limits SyncLimits, allowAuthorityReset bool) (*zone.NetworkState, *ApplyResult, error) {
	if ns == nil {
		return nil, nil, errors.New("network state is nil")
	}
	if snapshot == nil {
		return nil, nil, errors.New("zone snapshot is nil")
	}
	if !snapshot.Zone.Valid() {
		return nil, nil, zone.ErrInvalidZonePath
	}
	if ns.IsZoneRevoked(snapshot.Zone, now) {
		return nil, nil, fmt.Errorf("%w: %s", zone.ErrZoneRevoked, snapshot.Zone)
	}
	if limits == (SyncLimits{}) {
		limits = DefaultSyncLimits()
	}
	if err := checkSnapshotLimits(snapshot, limits); err != nil {
		return nil, nil, err
	}

	beforeZone := ns.Zones[snapshot.Zone]
	beforeRoot := ZoneRoot(beforeZone)
	var beforeAuthority []byte
	if beforeZone != nil {
		beforeAuthority = photoncrypto.AuthorityHash(beforeZone.Authority)
	}

	candidate := zone.CloneNetworkStateForZone(ns, snapshot.Zone)
	candidate.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	active := candidate.Zones[snapshot.Zone]
	candidate.Zones[snapshot.Zone] = ZoneStateFromSnapshot(snapshot)
	if err := photoncrypto.VerifyChain(candidate, snapshot.Zone, now); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrUntrustedZone, err)
	}
	if beforeZone != nil && (snapshot.Zone == zone.RootZone || !allowAuthorityReset) {
		if err := validateAuthorityTransition(snapshot.Zone, beforeZone.Authority, snapshot.Authority); err != nil {
			return nil, nil, err
		}
	}

	zs := candidate.Zones[snapshot.Zone]
	for child, delegation := range zs.Delegations {
		if err := photoncrypto.VerifyDelegation(delegation, zs.Authority, snapshot.Zone, now); err != nil {
			return nil, nil, fmt.Errorf("verify delegation %s: %w", child, err)
		}
		if beforeZone != nil && !allowAuthorityReset {
			if err := validateDelegationTransition(child, beforeZone.Delegations[child], delegation); err != nil {
				return nil, nil, err
			}
		}
	}
	for child, revocation := range zs.Revocations {
		if err := photoncrypto.VerifyDelegationRevocation(revocation, zs.Authority, snapshot.Zone, now); err != nil {
			return nil, nil, fmt.Errorf("verify revocation %s: %w", child, err)
		}
	}

	if active == nil {
		active = zone.NewZoneState(snapshot.Zone, cloneAuthority(snapshot.Authority))
	} else {
		active.Authority = cloneAuthority(snapshot.Authority)
	}
	candidate.Zones[snapshot.Zone] = active
	active.ParentProof = cloneDelegationSlice(snapshot.ParentProof)
	if active.Delegations == nil {
		active.Delegations = make(map[zone.ZonePath]*zone.Delegation)
	}
	if active.Revocations == nil {
		active.Revocations = make(map[zone.ZonePath]*zone.DelegationRevocation)
	}
	if active.Records == nil {
		active.Records = make(map[string]*zone.Record)
	}
	if active.RecordHistory == nil {
		active.RecordHistory = make(map[string][]*zone.Record)
	}
	for child, delegation := range snapshot.Delegations {
		active.Delegations[child] = cloneDelegation(delegation)
	}
	for child, revocation := range snapshot.Revocations {
		active.Revocations[child] = cloneRevocation(revocation)
		if activeRevocationApplies(active.Delegations[child], revocation) {
			delete(active.Delegations, child)
		}
	}

	var applied int
	for _, record := range orderedSnapshotRecords(snapshot) {
		err := candidate.PutAt(record, now)
		switch {
		case err == nil:
			applied++
		case errors.Is(err, zone.ErrStaleRecord), errors.Is(err, zone.ErrRecordConflict):
			continue
		default:
			return nil, nil, err
		}
	}

	afterRoot := ZoneRoot(active)
	afterAuthority := photoncrypto.AuthorityHash(active.Authority)
	rootChanged := !bytes.Equal(beforeRoot, afterRoot)
	authorityChanged := !bytes.Equal(beforeAuthority, afterAuthority)
	result := &ApplyResult{
		Zone:             snapshot.Zone,
		Records:          applied,
		Delegation:       len(active.Delegations),
		ZoneRootChanged:  rootChanged,
		AuthorityChanged: authorityChanged,
		NetworkChanged:   rootChanged || authorityChanged,
	}
	return candidate, result, nil
}

func validateAuthorityTransition(path zone.ZonePath, current, incoming *zone.ZoneAuthority) error {
	if current == nil || incoming == nil {
		return nil
	}
	if incoming.Epoch < current.Epoch {
		return fmt.Errorf("%w for %s: current=%d incoming=%d", ErrStaleAuthority, path, current.Epoch, incoming.Epoch)
	}
	currentHash := photoncrypto.AuthorityHash(current)
	incomingHash := photoncrypto.AuthorityHash(incoming)
	if path == zone.RootZone && !bytes.Equal(currentHash, incomingHash) {
		return fmt.Errorf("%w: current_epoch=%d incoming_epoch=%d current=%x incoming=%x", ErrRootAuthorityChange, current.Epoch, incoming.Epoch, currentHash, incomingHash)
	}
	if incoming.Epoch == current.Epoch {
		if !bytes.Equal(currentHash, incomingHash) {
			return fmt.Errorf("%w for %s: epoch=%d current=%x incoming=%x", ErrAuthorityConflict, path, current.Epoch, currentHash, incomingHash)
		}
		return nil
	}
	return nil
}

func validateDelegationTransition(child zone.ZonePath, current, incoming *zone.Delegation) error {
	if current == nil || incoming == nil {
		return nil
	}
	if incoming.AuthorityEpoch < current.AuthorityEpoch {
		return fmt.Errorf("%w for %s: current=%d incoming=%d", ErrStaleDelegation, child, current.AuthorityEpoch, incoming.AuthorityEpoch)
	}
	if incoming.AuthorityEpoch == current.AuthorityEpoch &&
		(!bytes.Equal(current.AuthorityHash, incoming.AuthorityHash) || !bytes.Equal(current.Signature, incoming.Signature)) {
		return fmt.Errorf("%w for %s: epoch=%d", ErrDelegationConflict, child, current.AuthorityEpoch)
	}
	return nil
}

func checkSnapshotLimits(snapshot *ZoneSnapshot, limits SyncLimits) error {
	records := countRecords(snapshot.RecordHistory) + len(snapshot.Records)
	if limits.MaxRecords > 0 && records > limits.MaxRecords {
		return ErrZoneSnapshotTooLarge
	}
	if limits.MaxBytes > 0 {
		// Use msgpack for size check because it is the default wire codec.
		data, err := msgpack.Marshal(snapshot)
		if err != nil {
			return err
		}
		if len(data) > limits.MaxBytes {
			return ErrZoneSnapshotTooLarge
		}
	}
	return nil
}

func orderedSnapshotRecords(snapshot *ZoneSnapshot) []*zone.Record {
	byKey := make(map[string][]*zone.Record)
	for key, record := range snapshot.Records {
		if record != nil {
			byKey[key] = append(byKey[key], cloneRecord(record))
		}
	}

	keys := make([]string, 0, len(byKey))
	for key := range byKey {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	var out []*zone.Record
	for _, key := range keys {
		records := byKey[key]
		sort.SliceStable(records, func(i, j int) bool {
			if records[i].Version == records[j].Version {
				return bytes.Compare(photoncrypto.RecordHash(records[i]), photoncrypto.RecordHash(records[j])) < 0
			}
			return records[i].Version < records[j].Version
		})
		out = append(out, records...)
	}
	return out
}

// ZoneStateFromSnapshot returns a detached zone projection for hashing and
// protocol encoding. It does not verify or publish the snapshot.
func ZoneStateFromSnapshot(snapshot *ZoneSnapshot) *zone.ZoneState {
	return &zone.ZoneState{
		Path:          snapshot.Zone,
		Authority:     cloneAuthority(snapshot.Authority),
		ParentProof:   cloneDelegationSlice(snapshot.ParentProof),
		Delegations:   cloneDelegationMap(snapshot.Delegations),
		Revocations:   cloneRevocationMap(snapshot.Revocations),
		Records:       cloneRecordMap(snapshot.Records),
		RecordHistory: cloneRecordHistory(snapshot.RecordHistory),
	}
}

func snapshotParentProof(ns *zone.NetworkState, path zone.ZonePath, zs *zone.ZoneState) []*zone.Delegation {
	proof := cloneDelegationSlice(zs.ParentProof)
	if path == zone.RootZone || ns == nil {
		return proof
	}
	parent := path.Parent()
	if parent == zone.RootZone {
		return proof
	}
	parentState := ns.Zones[parent]
	if parentState == nil {
		return proof
	}
	delegation := parentState.Delegations[path]
	if delegation == nil {
		return proof
	}
	for _, existing := range proof {
		if existing != nil && existing.ZoneName == path {
			return proof
		}
	}
	return append([]*zone.Delegation{cloneDelegation(delegation)}, proof...)
}

func countRecords(records map[string][]*zone.Record) int {
	var out int
	for _, list := range records {
		out += len(list)
	}
	return out
}

func cloneRecordMap(records map[string]*zone.Record) map[string]*zone.Record {
	if records == nil {
		return nil
	}
	out := make(map[string]*zone.Record, len(records))
	for key, record := range records {
		out[key] = cloneRecord(record)
	}
	return out
}

func cloneRecordHistory(records map[string][]*zone.Record) map[string][]*zone.Record {
	if records == nil {
		return nil
	}
	out := make(map[string][]*zone.Record, len(records))
	for key, list := range records {
		if list == nil {
			out[key] = nil
			continue
		}
		out[key] = make([]*zone.Record, 0, len(list))
		for _, record := range list {
			out[key] = append(out[key], cloneRecord(record))
		}
	}
	return out
}

func cloneDelegationMap(delegations map[zone.ZonePath]*zone.Delegation) map[zone.ZonePath]*zone.Delegation {
	if delegations == nil {
		return nil
	}
	out := make(map[zone.ZonePath]*zone.Delegation, len(delegations))
	for path, delegation := range delegations {
		out[path] = cloneDelegation(delegation)
	}
	return out
}

func cloneRevocationMap(revocations map[zone.ZonePath]*zone.DelegationRevocation) map[zone.ZonePath]*zone.DelegationRevocation {
	if revocations == nil {
		return nil
	}
	out := make(map[zone.ZonePath]*zone.DelegationRevocation, len(revocations))
	for path, revocation := range revocations {
		out[path] = cloneRevocation(revocation)
	}
	return out
}

func cloneDelegationSlice(delegations []*zone.Delegation) []*zone.Delegation {
	if delegations == nil {
		return nil
	}
	out := make([]*zone.Delegation, 0, len(delegations))
	for _, delegation := range delegations {
		out = append(out, cloneDelegation(delegation))
	}
	return out
}

func cloneAuthority(authority *zone.ZoneAuthority) *zone.ZoneAuthority {
	if authority == nil {
		return nil
	}
	out := *authority
	out.Keys = make([]zone.AuthorizedKey, len(authority.Keys))
	for i, key := range authority.Keys {
		out.Keys[i] = key
		out.Keys[i].Key = cloneBytes(key.Key)
		out.Keys[i].Capabilities = append([]zone.Capability(nil), key.Capabilities...)
		for j := range out.Keys[i].Capabilities {
			out.Keys[i].Capabilities[j].Permissions = append([]zone.Permission(nil), key.Capabilities[j].Permissions...)
		}
	}
	return &out
}

func cloneDelegation(delegation *zone.Delegation) *zone.Delegation {
	if delegation == nil {
		return nil
	}
	out := *delegation
	out.Authority = *cloneAuthority(&delegation.Authority)
	out.AuthorityHash = cloneBytes(delegation.AuthorityHash)
	out.SignedBy = cloneBytes(delegation.SignedBy)
	out.Signature = cloneBytes(delegation.Signature)
	if delegation.ExpiresAt != nil {
		expires := *delegation.ExpiresAt
		out.ExpiresAt = &expires
	}
	return &out
}

func cloneRevocation(revocation *zone.DelegationRevocation) *zone.DelegationRevocation {
	if revocation == nil {
		return nil
	}
	out := *revocation
	out.RevokedAuthorityHash = cloneBytes(revocation.RevokedAuthorityHash)
	out.SignedBy = cloneBytes(revocation.SignedBy)
	out.Signature = cloneBytes(revocation.Signature)
	return &out
}

func activeRevocationApplies(delegation *zone.Delegation, revocation *zone.DelegationRevocation) bool {
	if revocation == nil {
		return false
	}
	if delegation == nil {
		return true
	}
	return bytes.Equal(revocation.RevokedAuthorityHash, delegation.AuthorityHash) || revocation.RevokedAuthorityEpoch >= delegation.AuthorityEpoch
}

func cloneRecord(record *zone.Record) *zone.Record {
	if record == nil {
		return nil
	}
	out := *record
	out.Value = cloneBytes(record.Value)
	out.ValueHash = cloneBytes(record.ValueHash)
	out.PrevHash = cloneBytes(record.PrevHash)
	out.SignedBy = cloneBytes(record.SignedBy)
	out.Signature = cloneBytes(record.Signature)
	return &out
}

func cloneBytes(in []byte) []byte {
	if in == nil {
		return nil
	}
	return append([]byte(nil), in...)
}
