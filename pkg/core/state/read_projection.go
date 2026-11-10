package state

import (
	"sort"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// DiscoveryView contains detached current records, authorization data and
// restart hints from one committed Revision. Discovery never needs record
// history or local private keys.
type DiscoveryView struct {
	ManagedZone zone.ZonePath
	Network     *zone.NetworkState
	Peers       map[string]PeerCheckpoint
	Revision    VerifiedRevision
}

// ReadPeerAuthorization reads one peer's authorization chain and committed
// checkpoint without copying endpoint records that observed-source handling
// does not use. The same signatures, revocations and time checks remain possible.
func (store *Store) ReadPeerAuthorization(peerID string) *DiscoveryView {
	if peerID == "" {
		return nil
	}
	return store.ReadDiscoveryRecords(peerID, "")
}

// ReadDiscoveryRecords reads discovery records matching prefix. An empty
// peerID selects all peers. A specific peer retains its authorization chain,
// with records only from the peer itself. An empty prefix omits records.
func (store *Store) ReadDiscoveryRecords(peerID, prefix string) *DiscoveryView {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.state == nil || store.state.Network == nil {
		return nil
	}
	network := store.state.Network
	out := &DiscoveryView{
		ManagedZone: store.state.ManagedZone,
		Revision:    store.VerifiedRevision(),
		Network: &zone.NetworkState{
			Zones:          make(map[zone.ZonePath]*zone.ZoneState),
			GlobalRoot:     append([]byte(nil), network.GlobalRoot...),
			RecordVerifier: network.RecordVerifier,
			RecordHasher:   network.RecordHasher,
		},
		Peers: make(map[string]PeerCheckpoint),
	}
	if peerID == "" {
		for path, zs := range network.Zones {
			out.Network.Zones[path] = cloneDiscoveryZone(zs, prefix)
		}
		for id, peer := range store.gossip.Peers {
			out.Peers[id] = clonePeerCheckpoint(peer)
		}
		return out
	}
	if peer, ok := store.gossip.Peers[peerID]; ok {
		out.Peers[peerID] = clonePeerCheckpoint(peer)
	}
	path := zone.ZonePath(peerID)
	if path.Valid() {
		for current := path; ; current = current.Parent() {
			if zs, ok := network.Zones[current]; ok {
				recordPrefix := ""
				if current == path {
					recordPrefix = prefix
				}
				out.Network.Zones[current] = cloneDiscoveryZone(zs, recordPrefix)
			}
			if current == zone.RootZone {
				break
			}
		}
	}
	return out
}

func cloneDiscoveryZone(zs *zone.ZoneState, prefix string) *zone.ZoneState {
	if zs == nil {
		return nil
	}
	out := &zone.ZoneState{
		Path: zs.Path, Authority: cloneAuthority(zs.Authority),
		ParentProof: cloneDelegationSlice(zs.ParentProof),
		Delegations: cloneDelegationMap(zs.Delegations),
		Revocations: cloneRevocationMap(zs.Revocations),
		MerkleRoot:  append([]byte(nil), zs.MerkleRoot...),
	}
	if prefix != "" {
		for key, record := range zs.Records {
			if strings.HasPrefix(key, prefix) {
				if out.Records == nil {
					out.Records = make(map[string]*zone.Record)
				}
				out.Records[key] = cloneRecord(record)
			}
		}
	}
	return out
}

// ReadZoneSnapshot copies only the requested zone's wire snapshot and parent
// proof. Revocation is evaluated with the same committed network and time.
func (store *Store) ReadZoneSnapshot(path zone.ZonePath, now time.Time) (*ZoneSnapshot, bool, error) {
	if store == nil {
		snapshot, err := Snapshot(nil, path)
		return snapshot, false, err
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	network := store.state.Network
	revoked := network.IsZoneRevoked(path, now)
	if network != nil && network.Zones[path] != nil && revoked {
		return nil, true, nil
	}
	snapshot, err := Snapshot(network, path)
	return snapshot, revoked, err
}

// CatalogView is the detached catalog data read together from one committed root.
// It excludes records, history, private keys and peer restart hints.
type CatalogView struct {
	ManagedZone zone.ZonePath
	Digests     []ZoneDigest
}

func (store *Store) ReadCatalog() *CatalogView {
	if store == nil {
		return nil
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	if store.state == nil || store.state.Network == nil {
		return nil
	}
	return &CatalogView{ManagedZone: store.state.ManagedZone, Digests: store.zoneDigestsLocked(time.Now())}
}

// catalogSnapshot contains only time-independent roots for one committed
// revision. Store.mu pins that revision while readers build or use the snapshot;
// concurrent first readers may publish equivalent immutable snapshots.
type catalogSnapshot struct {
	revision VerifiedRevision
	digests  []ZoneDigest
}

// zoneDigestsLocked requires Store.mu to be held. Only raw zone roots are
// reused: future revocations can become active without a verified commit, and
// clock rollback can make a previously hidden zone visible again.
func (store *Store) zoneDigestsLocked(now time.Time) []ZoneDigest {
	if store.state == nil || store.state.Network == nil {
		return nil
	}
	network := store.state.Network
	catalog := store.catalog.Load()
	if catalog == nil || catalog.revision != store.VerifiedRevision() {
		catalog = &catalogSnapshot{revision: store.VerifiedRevision(), digests: make([]ZoneDigest, 0, len(network.Zones))}
		for path, zs := range network.Zones {
			if zs != nil {
				catalog.digests = append(catalog.digests, ZoneDigest{Zone: path, RootHash: ZoneRoot(zs)})
			}
		}
		sort.Slice(catalog.digests, func(i, j int) bool { return catalog.digests[i].Zone < catalog.digests[j].Zone })
		store.catalog.Store(catalog)
	}
	out := make([]ZoneDigest, 0, len(catalog.digests))
	for _, digest := range catalog.digests {
		if !network.IsZoneRevoked(digest.Zone, now) {
			out = append(out, ZoneDigest{Zone: digest.Zone, RootHash: append([]byte(nil), digest.RootHash...)})
		}
	}
	return out
}
