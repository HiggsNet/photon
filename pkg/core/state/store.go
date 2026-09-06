package state

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
)

var (
	ErrSnapshotRootMismatch       = errors.New("snapshot root does not match advertised catalog digest")
	ErrTrustedRootAuthorityChange = errors.New("remote snapshot cannot replace the trusted root authority")
	ErrVerifiedStoreClosed        = errors.New("verified state store is closed")
	ErrVerifiedRevisionStale      = errors.New("verified state revision is stale")
)

// VerifiedState is the platform-neutral persisted root owned by Store. It
// deliberately excludes controller observations such as SAs, routes, firewall
// rules, BIRD processes and tunnel handles.
type VerifiedState struct {
	ManagedZone          zone.ZonePath
	Network              *zone.NetworkState
	TrustedRootPublicKey ed25519.PublicKey
	// Private keys are intentionally part of the persisted local root. API,
	// observer and gossip projections must use DTOs that omit these fields.
	RootPrivateKey     ed25519.PrivateKey
	IdentityPrivateKey ed25519.PrivateKey
}

// GossipCheckpoint is a loss-tolerant restart hint. None of its fields may be
// required for signature verification, authorization or eventual convergence.
// Live sessions, timers, cursors, chunk assembly and in-flight pulls belong to
// gossip.Engine/GossipDriver memory and are deliberately absent here.
type GossipCheckpoint struct {
	Peers map[string]PeerCheckpoint `json:"peers,omitempty"`
}

// PeerCheckpoint contains restart hints that affect retry/discovery efficiency
// plus the most recent loss-tolerant failure context. Pure protocol counters
// and explanatory source fields belong in observability stores.
type PeerCheckpoint struct {
	LastSyncUnix            int64                            `json:"last_sync_unix,omitempty"`
	LastAttemptUnix         int64                            `json:"last_attempt_unix,omitempty"`
	BackoffUntilUnix        int64                            `json:"backoff_until_unix,omitempty"`
	FailureCount            int                              `json:"failure_count,omitempty"`
	LastRelayUnix           int64                            `json:"last_relay_unix,omitempty"`
	LastRelayCatalogRootHex string                           `json:"last_relay_catalog_root_hex,omitempty"`
	DiscoveredEndpoint      string                           `json:"discovered_endpoint,omitempty"`
	DiscoveredAtUnix        int64                            `json:"discovered_at_unix,omitempty"`
	ObservedEndpoint        string                           `json:"observed_endpoint,omitempty"`
	ObservedFirstSeenUnix   int64                            `json:"observed_first_seen_unix,omitempty"`
	ObservedLastSeenUnix    int64                            `json:"observed_last_seen_unix,omitempty"`
	ObservedLastSyncUnix    int64                            `json:"observed_last_sync_unix,omitempty"`
	ObservedUntilUnix       int64                            `json:"observed_until_unix,omitempty"`
	ObservedFailureCount    int                              `json:"observed_failure_count,omitempty"`
	ObservedGraceEndpoints  []ObservedGraceEndpoint          `json:"observed_grace_endpoints,omitempty"`
	LastFailure             *PeerFailure                     `json:"last_failure,omitempty"`
	RejectedObjects         map[zone.ZonePath]RejectedObject `json:"rejected_objects,omitempty"`
}

type PeerFailureCode string

const (
	PeerFailureUnknown   PeerFailureCode = "unknown"
	PeerFailureTimeout   PeerFailureCode = "timeout"
	PeerFailureTransport PeerFailureCode = "transport"
	PeerFailureProtocol  PeerFailureCode = "protocol"
	PeerFailureLegacy    PeerFailureCode = "legacy"
)

// PeerFailure is a loss-tolerant, serializable error record. Scheduling must
// use stable fields such as FailureCount, BackoffUntilUnix or Code and must
// never compare Message text.
type PeerFailure struct {
	Code    PeerFailureCode `json:"code"`
	Message string          `json:"message,omitempty"`
	AtUnix  int64           `json:"at_unix,omitempty"`
}

func (failure PeerFailure) Error() string {
	if failure.Message != "" {
		return failure.Message
	}
	return string(failure.Code)
}

type ObservedGraceEndpoint struct {
	Endpoint  string `json:"endpoint"`
	UntilUnix int64  `json:"until_unix"`
}

type RejectedObject struct {
	RootHash    []byte `json:"root_hash"`
	Reason      string `json:"reason"`
	UpdatedUnix int64  `json:"updated_unix"`
	UntilUnix   int64  `json:"until_unix,omitempty"`
}

const RejectedObjectTTL = 10 * time.Minute

// CommitCandidate is the atomic common-state persistence candidate. Verified facts and the
// loss-tolerant gossip checkpoint remain distinct logical partitions.
type CommitCandidate struct {
	Verified *VerifiedState
	Gossip   *GossipCheckpoint
}

type VerifiedRevision uint64

// View is a detached read model. Callers may freely retain or mutate it.
type View struct {
	State    *VerifiedState
	Gossip   *GossipCheckpoint
	Revision VerifiedRevision
}

type ChangeSet struct {
	VerifiedRevision        VerifiedRevision
	ChangedZones            []zone.ZonePath
	NetworkChanged          bool
	GossipCheckpointChanged bool
	SecurityPriority        bool
}

type CommitResult struct {
	Committed bool
	Changes   ChangeSet
}

type RemoteSnapshot struct {
	Snapshot     *ZoneSnapshot
	ExpectedRoot []byte
	Limits       SyncLimits
}

type RemoteApplyOutcome struct {
	Zone               zone.ZonePath
	Result             *ApplyResult
	ManagedZoneAdopted bool
	AuthorityRefreshed bool
	RejectReason       string
	Err                error
}

type RemoteBatchResult struct {
	CommitResult
	Outcomes []RemoteApplyOutcome
}

// CommitFunc persists one complete detached candidate before Store publishes
// it in memory. Implementations must not retain mutable pointers.
type CommitFunc func(context.Context, *CommitCandidate, ChangeSet) error

// Store is an in-memory single-owner common-state aggregate. Verified facts
// and loss-tolerant gossip checkpoints are separate logical partitions. Its mutex protects
// readers and the publication boundary; verification and persistence I/O
// run without holding the read lock.
type Store struct {
	writeMu  sync.Mutex
	mu       sync.RWMutex
	state    *VerifiedState
	gossip   *GossipCheckpoint
	revision VerifiedRevision
	commit   CommitFunc
	closed   bool
}

func NewStore(initial *VerifiedState, commit CommitFunc) *Store {
	return NewStoreWithCheckpoint(initial, nil, commit)
}

func NewStoreWithCheckpoint(initial *VerifiedState, checkpoint *GossipCheckpoint, commit CommitFunc) *Store {
	return &Store{state: cloneVerifiedState(initial), gossip: cloneGossipCheckpoint(checkpoint), commit: commit}
}

// RestoreStore constructs the in-memory common state from a candidate already
// validated and loaded from persistent storage. It preserves the persisted
// VerifiedRevision so the next Network commit advances from the disk value.
func RestoreStore(candidate *CommitCandidate, revision VerifiedRevision, commit CommitFunc) (*Store, error) {
	if candidate == nil || candidate.Verified == nil {
		return nil, fmt.Errorf("%w: persisted candidate is missing", ErrInvalidStateRoot)
	}
	if err := ValidateStateRoot(candidate.Verified); err != nil {
		return nil, err
	}
	return &Store{
		state:    cloneVerifiedState(candidate.Verified),
		gossip:   cloneGossipCheckpoint(candidate.Gossip),
		revision: revision,
		commit:   commit,
	}, nil
}

func (store *Store) ReadView() View {
	if store == nil {
		return View{}
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return View{State: cloneVerifiedState(store.state), Gossip: cloneGossipCheckpoint(store.gossip), Revision: store.revision}
}

// VerifiedRevision returns the currently published verified-state revision
// without cloning the verified state or gossip checkpoint.
func (store *Store) VerifiedRevision() VerifiedRevision {
	if store == nil {
		return 0
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.revision
}

func (store *Store) ZoneDigests() ([]ZoneDigest, VerifiedRevision) {
	if store == nil {
		return nil, 0
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return ZoneDigests(store.state.Network), store.revision
}

// ApplyRemoteBatch applies every item with an independent savepoint. A
// rejected item records a bounded peer checkpoint and does not discard earlier or
// later successful items. Publication is one serialized commit for the batch.
func (store *Store) ApplyRemoteBatch(ctx context.Context, peerID string, batch []RemoteSnapshot, now time.Time) (RemoteBatchResult, error) {
	var out RemoteBatchResult
	if store == nil {
		return out, ErrVerifiedStoreClosed
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
	base := cloneVerifiedState(store.state)
	baseGossip := cloneGossipCheckpoint(store.gossip)
	store.mu.RUnlock()
	candidate := base
	gossipCandidate := baseGossip
	changedZones := make([]zone.ZonePath, 0, len(batch))
	metadataChanged := false
	for _, item := range batch {
		outcome := RemoteApplyOutcome{}
		if item.Snapshot != nil {
			outcome.Zone = item.Snapshot.Zone
		}
		if item.Snapshot == nil {
			outcome.Err = errors.New("zone snapshot is nil")
		} else if item.Snapshot.Zone == candidate.ManagedZone {
			// A remote peer never owns the managed Zone contents. Its parent
			// may update only the authority envelope through a delegation.
			out.Outcomes = append(out.Outcomes, outcome)
			continue
		} else if item.Snapshot.Zone == zone.RootZone && rootAuthorityChanged(candidate.Network, item.Snapshot.Authority) {
			outcome.Err = ErrTrustedRootAuthorityChange
		} else if len(item.ExpectedRoot) > 0 {
			actual := ZoneRoot(ZoneStateFromSnapshot(item.Snapshot))
			if !bytes.Equal(actual, item.ExpectedRoot) {
				outcome.Err = fmt.Errorf("%w for %s: expected %x, received %x", ErrSnapshotRootMismatch, item.Snapshot.Zone, item.ExpectedRoot, actual)
			}
		}
		if outcome.Err == nil {
			next, result, err := ApplySnapshot(candidate.Network, item.Snapshot, now, item.Limits)
			if err != nil {
				outcome.Err = err
			} else {
				reconciled, managedResult, reconcileErr := ReconcileManagedAuthority(next, candidate.ManagedZone, identityPublicKey(candidate.IdentityPrivateKey), now)
				if reconcileErr != nil {
					outcome.Err = fmt.Errorf("reconcile managed zone authority: %w", reconcileErr)
				} else {
					candidate.Network = reconciled
					outcome.Result = result
					outcome.ManagedZoneAdopted = managedResult.Adopted
					outcome.AuthorityRefreshed = managedResult.Refreshed
					if result.NetworkChanged {
						changedZones = appendZoneOnce(changedZones, result.Zone)
					}
					if managedResult.Adopted || managedResult.Refreshed {
						changedZones = appendZoneOnce(changedZones, candidate.ManagedZone)
					}
					if clearRejectedObject(gossipCandidate, peerID, item.Snapshot.Zone) {
						metadataChanged = true
					}
				}
			}
		}
		if outcome.Err != nil {
			outcome.RejectReason = remoteRejectReason(outcome.Err)
			if item.Snapshot != nil && recordRejectedObject(gossipCandidate, peerID, item.Snapshot.Zone, rejectedRoot(item), outcome.RejectReason, now) {
				metadataChanged = true
			}
		}
		out.Outcomes = append(out.Outcomes, outcome)
	}

	networkChanged := len(changedZones) > 0
	if !networkChanged && !metadataChanged {
		out.Changes.VerifiedRevision = baseRevision
		return out, nil
	}
	nextRevision := baseRevision
	if networkChanged {
		nextRevision++
	}
	changes := ChangeSet{
		VerifiedRevision:        nextRevision,
		ChangedZones:            append([]zone.ZonePath(nil), changedZones...),
		NetworkChanged:          networkChanged,
		GossipCheckpointChanged: metadataChanged,
	}

	if store.commit != nil {
		if err := store.commit(ctx, cloneCommitCandidate(candidate, gossipCandidate), changes); err != nil {
			return RemoteBatchResult{}, err
		}
	}
	store.mu.Lock()
	store.state = candidate
	store.gossip = gossipCandidate
	store.revision = nextRevision
	store.mu.Unlock()
	out.Committed = true
	out.Changes = changes
	return out, nil
}

func rootAuthorityChanged(network *zone.NetworkState, authority *zone.ZoneAuthority) bool {
	if network == nil || network.Zones[zone.RootZone] == nil || network.Zones[zone.RootZone].Authority == nil || authority == nil {
		return true
	}
	return !bytes.Equal(photoncrypto.AuthorityHash(network.Zones[zone.RootZone].Authority), photoncrypto.AuthorityHash(authority))
}

func (store *Store) Close() {
	if store == nil {
		return
	}
	store.writeMu.Lock()
	defer store.writeMu.Unlock()
	store.mu.Lock()
	store.closed = true
	store.mu.Unlock()
}

func cloneVerifiedState(value *VerifiedState) *VerifiedState {
	if value == nil {
		return &VerifiedState{Network: zone.NewNetworkState()}
	}
	out := &VerifiedState{
		ManagedZone:          value.ManagedZone,
		Network:              zone.CloneNetworkState(value.Network),
		TrustedRootPublicKey: append(ed25519.PublicKey(nil), value.TrustedRootPublicKey...),
		RootPrivateKey:       append(ed25519.PrivateKey(nil), value.RootPrivateKey...),
		IdentityPrivateKey:   append(ed25519.PrivateKey(nil), value.IdentityPrivateKey...),
	}
	if out.Network == nil {
		out.Network = zone.NewNetworkState()
	}
	return out
}

func cloneGossipCheckpoint(value *GossipCheckpoint) *GossipCheckpoint {
	out := &GossipCheckpoint{Peers: make(map[string]PeerCheckpoint)}
	if value == nil {
		return out
	}
	for peerID, metadata := range value.Peers {
		out.Peers[peerID] = clonePeerCheckpoint(metadata)
	}
	return out
}

func cloneCommitCandidate(verified *VerifiedState, gossip *GossipCheckpoint) *CommitCandidate {
	return &CommitCandidate{Verified: cloneVerifiedState(verified), Gossip: cloneGossipCheckpoint(gossip)}
}

func identityPublicKey(privateKey ed25519.PrivateKey) ed25519.PublicKey {
	if len(privateKey) != ed25519.PrivateKeySize {
		return nil
	}
	return append(ed25519.PublicKey(nil), privateKey.Public().(ed25519.PublicKey)...)
}

func appendZoneOnce(paths []zone.ZonePath, path zone.ZonePath) []zone.ZonePath {
	for _, existing := range paths {
		if existing == path {
			return paths
		}
	}
	return append(paths, path)
}

func rejectedRoot(item RemoteSnapshot) []byte {
	if len(item.ExpectedRoot) > 0 {
		return append([]byte(nil), item.ExpectedRoot...)
	}
	if item.Snapshot == nil {
		return nil
	}
	return ZoneRoot(ZoneStateFromSnapshot(item.Snapshot))
}

func remoteRejectReason(err error) string {
	if errors.Is(err, ErrTrustedRootAuthorityChange) {
		return "trusted_root_authority_change"
	}
	if errors.Is(err, ErrSnapshotRootMismatch) {
		return "root_mismatch"
	}
	if errors.Is(err, ErrZoneSnapshotTooLarge) {
		return "snapshot_too_large"
	}
	if errors.Is(err, ErrUntrustedZone) {
		return "untrusted_zone"
	}
	return "invalid_snapshot"
}

func recordRejectedObject(state *GossipCheckpoint, peerID string, path zone.ZonePath, root []byte, reason string, now time.Time) bool {
	if state == nil || peerID == "" || !path.Valid() {
		return false
	}
	metadata := state.Peers[peerID]
	if metadata.RejectedObjects == nil {
		metadata.RejectedObjects = make(map[zone.ZonePath]RejectedObject)
	}
	previous, ok := metadata.RejectedObjects[path]
	if ok && previous.Reason == reason && bytes.Equal(previous.RootHash, root) {
		return false
	}
	metadata.RejectedObjects[path] = RejectedObject{
		RootHash: append([]byte(nil), root...), Reason: reason, UpdatedUnix: now.Unix(), UntilUnix: now.Add(RejectedObjectTTL).Unix(),
	}
	state.Peers[peerID] = metadata
	return true
}

func clearRejectedObject(state *GossipCheckpoint, peerID string, path zone.ZonePath) bool {
	if state == nil || peerID == "" {
		return false
	}
	metadata, ok := state.Peers[peerID]
	if !ok || metadata.RejectedObjects == nil {
		return false
	}
	if _, ok := metadata.RejectedObjects[path]; !ok {
		return false
	}
	delete(metadata.RejectedObjects, path)
	state.Peers[peerID] = metadata
	return true
}
