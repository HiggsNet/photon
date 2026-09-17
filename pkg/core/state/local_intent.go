package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/routing"
	photonservice "github.com/HiggsNet/photon/pkg/service"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

var (
	ErrAuthorityEpochStale    = errors.New("authority epoch is stale")
	ErrAuthorityEpochConflict = errors.New("authority conflicts at the same epoch")
)

type LocalIntent interface {
	isLocalIntent()
}

type PutRecordIntent struct {
	Zone  zone.ZonePath
	Key   string
	Type  string
	Value []byte
}

func (PutRecordIntent) isLocalIntent() {}

type ProtocolRecordKind string

const (
	ProtocolRecordGossipEndpoint ProtocolRecordKind = "gossip_endpoint"
	ProtocolRecordIPsec          ProtocolRecordKind = "ipsec"
	ProtocolRecordRoutingNetns   ProtocolRecordKind = "routing_netns"
)

// PutProtocolRecordIntent is the narrow publisher path for reserved protocol
// records. Kind, key and type must be a known tuple; generic record writers
// remain unable to enter these namespaces.
type PutProtocolRecordIntent struct {
	Kind  ProtocolRecordKind
	Zone  zone.ZonePath
	Key   string
	Type  string
	Value []byte
}

func (PutProtocolRecordIntent) isLocalIntent() {}

type PutIPAMPoolIntent struct {
	Zone        zone.ZonePath
	Prefix      string
	DelegatedTo zone.ZonePath
}

func (PutIPAMPoolIntent) isLocalIntent() {}

type RevokeIPAMPoolIntent struct {
	Zone   zone.ZonePath
	Prefix string
}

func (RevokeIPAMPoolIntent) isLocalIntent() {}

type PutIPAMAssignmentIntent struct {
	Zone       zone.ZonePath
	Prefix     string
	AssignedTo zone.ZonePath
	Shared     bool
	Tag        string
}

func (PutIPAMAssignmentIntent) isLocalIntent() {}

type RevokeIPAMAssignmentIntent struct {
	Zone       zone.ZonePath
	Prefix     string
	AssignedTo zone.ZonePath
}

func (RevokeIPAMAssignmentIntent) isLocalIntent() {}

type AnnounceRouteIntent struct {
	Zone       zone.ZonePath
	Prefix     string
	Controller string
}

func (AnnounceRouteIntent) isLocalIntent() {}

type WithdrawRouteIntent struct {
	Zone       zone.ZonePath
	Prefix     string
	Controller string
}

func (WithdrawRouteIntent) isLocalIntent() {}

type PublishSOCKS5Intent struct {
	Endpoints []photonservice.SOCKS5Endpoint
}

func (PublishSOCKS5Intent) isLocalIntent() {}

type WithdrawSOCKS5Intent struct{}

func (WithdrawSOCKS5Intent) isLocalIntent() {}

type PutDelegationIntent struct {
	Parent    zone.ZonePath
	Authority *zone.ZoneAuthority
	ExpiresAt *time.Time
}

func (PutDelegationIntent) isLocalIntent() {}

type RevokeDelegationIntent struct {
	Parent zone.ZonePath
	Child  zone.ZonePath
	Reason string
}

func (RevokeDelegationIntent) isLocalIntent() {}

// UpdateRootAuthorityIntent is retained for callers to receive ErrRootAuthorityChange.
// Root authority changes are no longer supported.
type UpdateRootAuthorityIntent struct {
	Authority *zone.ZoneAuthority
}

func (UpdateRootAuthorityIntent) isLocalIntent() {}

type LocalIntentResult struct {
	CommitResult
	Record     *zone.Record
	Delegation *zone.Delegation
	Revocation *zone.DelegationRevocation
	Authority  *zone.ZoneAuthority
}

// LocalIntentBatchResult is one atomic local-authority transaction. All
// intents are evaluated against the same candidate in order and the verified
// revision advances at most once.
type LocalIntentBatchResult struct {
	CommitResult
	Results []LocalIntentResult
}

// PreviewLocalIntent runs the same validation, normalization and signing path
// as ApplyLocalIntent against a detached snapshot, without persisting or
// publishing the candidate. VerifiedRevision remains the currently committed
// revision because a preview is not a commit.
func (store *Store) PreviewLocalIntent(intent LocalIntent, now time.Time) (LocalIntentResult, error) {
	var out LocalIntentResult
	if store == nil {
		return out, ErrVerifiedStoreClosed
	}
	if intent == nil {
		return out, errors.New("local intent is nil")
	}
	store.mu.RLock()
	if store.closed {
		store.mu.RUnlock()
		return out, ErrVerifiedStoreClosed
	}
	baseRevision := store.revision
	candidate := cloneVerifiedState(store.state)
	checkpoint := cloneGossipCheckpoint(store.gossip)
	store.mu.RUnlock()

	preview := NewStoreWithCheckpoint(candidate, checkpoint, nil)
	out, err := preview.ApplyLocalIntent(context.Background(), intent, now)
	if err != nil {
		return LocalIntentResult{}, err
	}
	out.Committed = false
	out.Changes.VerifiedRevision = baseRevision
	return cloneLocalIntentResult(out), nil
}

// ApplyLocalIntent validates, signs and commits one authority-owned mutation.
// Private keys are ordinary persisted Store state under the administrator's
// filesystem/host security policy. Publication occurs only after persistence.
func (store *Store) ApplyLocalIntent(ctx context.Context, intent LocalIntent, now time.Time) (LocalIntentResult, error) {
	batch, err := store.ApplyLocalIntents(ctx, []LocalIntent{intent}, now)
	if err != nil {
		return LocalIntentResult{}, err
	}
	if len(batch.Results) != 1 {
		return LocalIntentResult{}, errors.New("local intent transaction produced no result")
	}
	out := batch.Results[0]
	out.CommitResult = batch.CommitResult
	return out, nil
}

// ApplyLocalIntents validates, signs and commits an ordered set of
// authority-owned mutations as one candidate. A later failure discards all
// earlier mutations in the batch.
func (store *Store) ApplyLocalIntents(ctx context.Context, intents []LocalIntent, now time.Time) (LocalIntentBatchResult, error) {
	return store.applyLocalIntents(ctx, intents, now, nil)
}

// ApplyLocalIntentsAtRevision publishes a plan only while the common verified
// state is still at the revision from which the caller derived it. This is
// used when platform-private state must be persisted before its public records
// become visible.
func (store *Store) ApplyLocalIntentsAtRevision(ctx context.Context, intents []LocalIntent, now time.Time, expected VerifiedRevision) (LocalIntentBatchResult, error) {
	return store.applyLocalIntents(ctx, intents, now, &expected)
}

func (store *Store) applyLocalIntents(ctx context.Context, intents []LocalIntent, now time.Time, expected *VerifiedRevision) (LocalIntentBatchResult, error) {
	var out LocalIntentBatchResult
	if store == nil {
		return out, ErrVerifiedStoreClosed
	}
	if len(intents) == 0 {
		return out, errors.New("local intent batch is empty")
	}
	for _, intent := range intents {
		if intent == nil {
			return LocalIntentBatchResult{}, errors.New("local intent is nil")
		}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	store.writeMu.Lock()
	defer store.writeMu.Unlock()

	store.mu.RLock()
	if store.closed {
		store.mu.RUnlock()
		return out, ErrVerifiedStoreClosed
	}
	baseRevision := store.revision
	candidate := cloneVerifiedState(store.state)
	gossipCandidate := cloneGossipCheckpoint(store.gossip)
	store.mu.RUnlock()
	if expected != nil && baseRevision != *expected {
		return out, ErrVerifiedRevisionStale
	}
	changedZones := make([]zone.ZonePath, 0, len(intents))
	var securityPriority bool
	var metadataChanged bool
	out.Results = make([]LocalIntentResult, 0, len(intents))
	for _, intent := range intents {
		result, changed, additional, secure, checkpointChanged, err := applyLocalIntentCandidate(candidate, gossipCandidate, intent, now)
		if err != nil {
			return LocalIntentBatchResult{}, err
		}
		if changed != "" {
			changedZones = appendZoneOnce(changedZones, changed)
		}
		for _, path := range additional {
			changedZones = appendZoneOnce(changedZones, path)
		}
		securityPriority = securityPriority || secure
		metadataChanged = metadataChanged || checkpointChanged
		out.Results = append(out.Results, result)
	}
	if len(changedZones) == 0 && !metadataChanged {
		out.Changes.VerifiedRevision = baseRevision
		return out, nil
	}
	nextRevision := baseRevision
	if len(changedZones) > 0 {
		nextRevision++
	}
	changes := ChangeSet{
		VerifiedRevision:        nextRevision,
		ChangedZones:            changedZones,
		NetworkChanged:          len(changedZones) > 0,
		GossipCheckpointChanged: metadataChanged,
		SecurityPriority:        securityPriority,
	}
	if store.commit != nil {
		if err := store.commit(ctx, cloneCommitCandidate(candidate, gossipCandidate), changes); err != nil {
			return LocalIntentBatchResult{}, err
		}
	}
	store.mu.Lock()
	store.state = candidate
	store.gossip = gossipCandidate
	store.revision = nextRevision
	store.mu.Unlock()
	out.Committed = true
	out.Changes = changes
	return cloneLocalIntentBatchResult(out), nil
}

func applyLocalIntentCandidate(candidate *VerifiedState, gossipCandidate *GossipCheckpoint, intent LocalIntent, now time.Time) (LocalIntentResult, zone.ZonePath, []zone.ZonePath, bool, bool, error) {
	var out LocalIntentResult
	var changed zone.ZonePath
	var additionallyChanged []zone.ZonePath
	var securityPriority bool
	var metadataChanged bool
	var err error
	switch typed := intent.(type) {
	case PutRecordIntent:
		if err = validateGenericRecordIntent(typed); err == nil {
			out.Record, changed, err = applyPutRecordIntent(candidate, typed, now)
		}
	case PutProtocolRecordIntent:
		if err = validateProtocolRecordIntent(typed); err == nil {
			out.Record, changed, err = applyPutProtocolRecordIntent(candidate, typed, now)
		}
	case PutIPAMPoolIntent:
		out.Record, changed, err = applyPutIPAMPoolIntent(candidate, typed, now)
	case RevokeIPAMPoolIntent:
		out.Record, changed, err = applyRevokeIPAMPoolIntent(candidate, typed, now)
	case PutIPAMAssignmentIntent:
		out.Record, changed, err = applyPutIPAMAssignmentIntent(candidate, typed, now)
	case RevokeIPAMAssignmentIntent:
		out.Record, changed, err = applyRevokeIPAMAssignmentIntent(candidate, typed, now)
	case AnnounceRouteIntent:
		out.Record, changed, err = applyRouteIntent(candidate, typed.Zone, typed.Prefix, typed.Controller, true, now)
	case WithdrawRouteIntent:
		out.Record, changed, err = applyRouteIntent(candidate, typed.Zone, typed.Prefix, typed.Controller, false, now)
	case PublishSOCKS5Intent:
		out.Record, changed, err = applyPublishSOCKS5Intent(candidate, typed, now)
	case WithdrawSOCKS5Intent:
		out.Record, changed, err = applyWithdrawSOCKS5Intent(candidate, now)
	case PutDelegationIntent:
		out.Delegation, changed, err = applyPutDelegationIntent(candidate, typed, now)
		if changed != "" {
			additionallyChanged = append(additionallyChanged, typed.Authority.Zone)
		}
	case RevokeDelegationIntent:
		out.Revocation, changed, err = applyRevokeDelegationIntent(candidate, typed, now)
		if err == nil {
			securityPriority = true
			metadataChanged = cleanupRevokedPeerCheckpoint(gossipCandidate, typed.Child)
		}
	case UpdateRootAuthorityIntent:
		err = ErrRootAuthorityChange
	default:
		err = fmt.Errorf("unsupported local intent %T", intent)
	}
	return out, changed, additionallyChanged, securityPriority, metadataChanged, err
}

func validateProtocolRecordIntent(intent PutProtocolRecordIntent) error {
	valid := false
	switch intent.Kind {
	case ProtocolRecordGossipEndpoint:
		valid = intent.Key == "sync/endpoint/udp" && intent.Type == "sync.endpoint"
	case ProtocolRecordRoutingNetns:
		valid = intent.Key == routing.RecordKeyRoutingNetns && intent.Type == routing.RecordTypeRoutingNetns
	case ProtocolRecordIPsec:
		switch intent.Key {
		case ipsec.RecordKeyProfile:
			valid = intent.Type == ipsec.RecordTypeProfile
		case ipsec.RecordKeyAddresses:
			valid = intent.Type == ipsec.RecordTypeAddresses
		case ipsec.RecordKeyPorts:
			valid = intent.Type == ipsec.RecordTypePorts
		case ipsec.RecordKeyTransportKey:
			valid = intent.Type == ipsec.RecordTypeTransportKey
		default:
			valid = strings.HasPrefix(intent.Key, ipsec.RecordKeyOverlayPrefix) &&
				len(strings.TrimPrefix(intent.Key, ipsec.RecordKeyOverlayPrefix)) > 0 && intent.Type == ipsec.RecordTypeOverlayIntent
		}
	}
	if !valid {
		return fmt.Errorf("invalid %s protocol record tuple %q/%q", intent.Kind, intent.Key, intent.Type)
	}
	return nil
}

func applyPutProtocolRecordIntent(state *VerifiedState, intent PutProtocolRecordIntent, now time.Time) (*zone.Record, zone.ZonePath, error) {
	if state != nil && state.Network != nil {
		if zs := state.Network.Zones[intent.Zone]; zs != nil {
			if current := zs.Records[intent.Key]; current != nil && current.Type == intent.Type && bytes.Equal(current.Value, intent.Value) {
				return cloneRecord(current), "", nil
			}
		}
	}
	return applyPutRecordIntent(state, PutRecordIntent{
		Zone: intent.Zone, Key: intent.Key, Type: intent.Type, Value: intent.Value,
	}, now)
}

func applyPutRecordIntent(state *VerifiedState, intent PutRecordIntent, now time.Time) (*zone.Record, zone.ZonePath, error) {
	if !intent.Zone.Valid() {
		return nil, "", zone.ErrInvalidZonePath
	}
	if intent.Key == "" {
		return nil, "", zone.ErrInvalidFQKey
	}
	if state.Network.Zones[intent.Zone] == nil {
		return nil, "", fmt.Errorf("%w: %s", zone.ErrZoneNotFound, intent.Zone)
	}
	state.Network = zone.CloneNetworkStateForZone(state.Network, intent.Zone)
	state.Network.ConfigureRecordValidation(photoncrypto.VerifyRecord, photoncrypto.RecordHash)
	zoneState := state.Network.Zones[intent.Zone]
	ensureZoneCollections(zoneState)
	current := zoneState.Records[intent.Key]
	record := &zone.Record{Zone: intent.Zone, Key: intent.Key, Type: intent.Type, Value: append([]byte(nil), intent.Value...), Version: 1, Timestamp: now.Unix()}
	if current != nil {
		record.Version = current.Version + 1
		record.PrevHash = photoncrypto.RecordHash(current)
	}
	privateKey, err := localSigningKey(state, intent.Zone)
	if err != nil {
		return nil, "", err
	}
	if err := photoncrypto.SignRecord(record, privateKey); err != nil {
		return nil, "", err
	}
	if err := state.Network.PutAt(record, now); err != nil {
		return nil, "", err
	}
	return cloneRecord(record), intent.Zone, nil
}

// applyPutDelegationIntent atomically updates the parent proof and the child
// authority. Existing child records/history remain owned by the child zone and
// survive an authority epoch refresh.
func applyPutDelegationIntent(state *VerifiedState, intent PutDelegationIntent, now time.Time) (*zone.Delegation, zone.ZonePath, error) {
	if !intent.Parent.Valid() || intent.Authority == nil || !intent.Authority.Zone.Valid() || intent.Authority.Zone.Parent() != intent.Parent {
		return nil, "", zone.ErrInvalidZonePath
	}
	parent := state.Network.Zones[intent.Parent]
	if parent == nil || parent.Authority == nil {
		return nil, "", fmt.Errorf("%w: %s", zone.ErrZoneNotFound, intent.Parent)
	}
	child := intent.Authority.Zone
	if existing := parent.Delegations[child]; existing != nil {
		nextHash := photoncrypto.AuthorityHash(intent.Authority)
		switch {
		case intent.Authority.Epoch < existing.AuthorityEpoch:
			return nil, "", ErrAuthorityEpochStale
		case intent.Authority.Epoch == existing.AuthorityEpoch && !bytes.Equal(nextHash, existing.AuthorityHash):
			return nil, "", ErrAuthorityEpochConflict
		case intent.Authority.Epoch == existing.AuthorityEpoch && bytes.Equal(nextHash, existing.AuthorityHash) &&
			sameExpiry(existing.ExpiresAt, intent.ExpiresAt) && zoneAuthorityEqual(state.Network.Zones[child], intent.Authority):
			return cloneDelegation(existing), "", nil
		}
	}
	state.Network = zone.CloneNetworkStateForZone(state.Network, intent.Parent)
	state.Network = zone.CloneNetworkStateForZone(state.Network, child)
	parent = state.Network.Zones[intent.Parent]
	ensureZoneCollections(parent)
	delegation := &zone.Delegation{ZoneName: child, Scope: zone.DelegationScopeDirectChild, Authority: *cloneAuthority(intent.Authority), ExpiresAt: cloneTime(intent.ExpiresAt)}
	privateKey, err := localSigningKey(state, intent.Parent)
	if err != nil {
		return nil, "", err
	}
	if err := photoncrypto.SignDelegation(delegation, intent.Parent, privateKey); err != nil {
		return nil, "", err
	}
	if err := photoncrypto.VerifyDelegation(delegation, parent.Authority, intent.Parent, now); err != nil {
		return nil, "", err
	}
	if revocation := parent.Revocations[child]; revocation != nil && (revocation.RevokedAuthorityEpoch >= delegation.AuthorityEpoch || bytes.Equal(revocation.RevokedAuthorityHash, delegation.AuthorityHash)) {
		return nil, "", fmt.Errorf("%w: %s", zone.ErrZoneRevoked, child)
	}
	parent.Delegations[child] = delegation
	childState := state.Network.Zones[child]
	if childState == nil {
		childState = zone.NewZoneState(child, cloneAuthority(intent.Authority))
		state.Network.Zones[child] = childState
	} else {
		childState.Authority = cloneAuthority(intent.Authority)
	}
	if err := photoncrypto.VerifyChain(state.Network, child, now); err != nil {
		return nil, "", err
	}
	return cloneDelegation(delegation), intent.Parent, nil
}

func zoneAuthorityEqual(state *zone.ZoneState, authority *zone.ZoneAuthority) bool {
	return state != nil && state.Authority != nil && bytes.Equal(
		photoncrypto.AuthorityHash(state.Authority),
		photoncrypto.AuthorityHash(authority),
	)
}

func applyRevokeDelegationIntent(state *VerifiedState, intent RevokeDelegationIntent, now time.Time) (*zone.DelegationRevocation, zone.ZonePath, error) {
	if !intent.Parent.Valid() || !intent.Child.Valid() || intent.Child.Parent() != intent.Parent {
		return nil, "", zone.ErrInvalidZonePath
	}
	parent := state.Network.Zones[intent.Parent]
	if parent == nil || parent.Authority == nil {
		return nil, "", fmt.Errorf("%w: %s", zone.ErrZoneNotFound, intent.Parent)
	}
	delegation := parent.Delegations[intent.Child]
	if delegation == nil {
		return nil, "", fmt.Errorf("delegation not found: %s", intent.Child)
	}
	state.Network = zone.CloneNetworkStateForZone(state.Network, intent.Parent)
	parent = state.Network.Zones[intent.Parent]
	ensureZoneCollections(parent)
	revocation := &zone.DelegationRevocation{
		ChildZone:             intent.Child,
		ParentZone:            intent.Parent,
		RevokedAuthorityEpoch: delegation.AuthorityEpoch,
		RevokedAuthorityHash:  append([]byte(nil), delegation.AuthorityHash...),
		Reason:                intent.Reason,
		RevokedAt:             now.Unix(),
	}
	privateKey, err := localSigningKey(state, intent.Parent)
	if err != nil {
		return nil, "", err
	}
	if err := photoncrypto.SignDelegationRevocation(revocation, intent.Parent, privateKey); err != nil {
		return nil, "", err
	}
	if err := photoncrypto.VerifyDelegationRevocation(revocation, parent.Authority, intent.Parent, now); err != nil {
		return nil, "", err
	}
	parent.Revocations[intent.Child] = revocation
	delete(parent.Delegations, intent.Child)
	return cloneRevocation(revocation), intent.Parent, nil
}

func sameExpiry(a, b *time.Time) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Equal(*b)
}

func localSigningKey(state *VerifiedState, path zone.ZonePath) (ed25519.PrivateKey, error) {
	if state == nil || state.Network == nil {
		return nil, errors.New("verified state is nil")
	}
	zoneState := state.Network.Zones[path]
	if zoneState == nil || zoneState.Authority == nil {
		return nil, fmt.Errorf("%w: %s", zone.ErrZoneNotFound, path)
	}
	for _, privateKey := range []ed25519.PrivateKey{state.RootPrivateKey, state.IdentityPrivateKey} {
		if len(privateKey) == ed25519.PrivateKeySize && authorityHasPublicKey(zoneState.Authority, privateKey.Public().(ed25519.PublicKey)) {
			return append(ed25519.PrivateKey(nil), privateKey...), nil
		}
	}
	return nil, fmt.Errorf("no local signing key for zone %s", path)
}

func cloneTime(value *time.Time) *time.Time {
	if value == nil {
		return nil
	}
	out := *value
	return &out
}

func cloneLocalIntentResult(value LocalIntentResult) LocalIntentResult {
	value.Changes.ChangedZones = append([]zone.ZonePath(nil), value.Changes.ChangedZones...)
	value.Record = cloneRecord(value.Record)
	value.Delegation = cloneDelegation(value.Delegation)
	value.Revocation = cloneRevocation(value.Revocation)
	value.Authority = cloneAuthority(value.Authority)
	return value
}

func cloneLocalIntentBatchResult(value LocalIntentBatchResult) LocalIntentBatchResult {
	value.Changes.ChangedZones = append([]zone.ZonePath(nil), value.Changes.ChangedZones...)
	value.Results = append([]LocalIntentResult(nil), value.Results...)
	for i := range value.Results {
		value.Results[i] = cloneLocalIntentResult(value.Results[i])
	}
	return value
}

func ensureZoneCollections(state *zone.ZoneState) {
	if state.Delegations == nil {
		state.Delegations = make(map[zone.ZonePath]*zone.Delegation)
	}
	if state.Revocations == nil {
		state.Revocations = make(map[zone.ZonePath]*zone.DelegationRevocation)
	}
	if state.Records == nil {
		state.Records = make(map[string]*zone.Record)
	}
	if state.RecordHistory == nil {
		state.RecordHistory = make(map[string][]*zone.Record)
	}
}

func cleanupRevokedPeerCheckpoint(state *GossipCheckpoint, revoked zone.ZonePath) bool {
	if state == nil || !revoked.Valid() {
		return false
	}
	changed := false
	for peerID := range state.Peers {
		path := zone.ZonePath(peerID)
		if path == revoked || zoneDescendsFrom(path, revoked) {
			delete(state.Peers, peerID)
			changed = true
		}
	}
	return changed
}

func zoneDescendsFrom(path, parent zone.ZonePath) bool {
	if !path.Valid() || !parent.Valid() || path == parent {
		return false
	}
	for current := path.Parent(); ; current = current.Parent() {
		if current == parent {
			return true
		}
		if current == zone.RootZone {
			return false
		}
	}
}
