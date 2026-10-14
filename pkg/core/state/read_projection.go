package state

import (
	"github.com/HiggsNet/photon/pkg/core/zone"
	"time"
)

// DiscoveryView contains detached current records, authorization data and
// restart hints. Discovery never needs record history or local private keys.
type DiscoveryView struct {
	ManagedZone zone.ZonePath
	Network     *zone.NetworkState
	Peers       map[string]PeerCheckpoint
}

// ReadDiscovery reads one coherent discovery input. An empty peerID selects
// all peers; a specific peer selects its current records and ancestor chain.
// Ancestors retain authority, parent proofs, delegations and revocations, so
// callers still verify signatures and time-dependent policy on every use.
func (store *Store) ReadDiscovery(peerID string) *DiscoveryView {
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
			out.Network.Zones[path] = cloneDiscoveryZone(zs, true)
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
				out.Network.Zones[current] = cloneDiscoveryZone(zs, current == path)
			}
			if current == zone.RootZone {
				break
			}
		}
	}
	return out
}

func cloneDiscoveryZone(zs *zone.ZoneState, records bool) *zone.ZoneState {
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
	if records {
		out.Records = cloneRecordMap(zs.Records)
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

// ReadRecordSnapshot preserves the object-pull record lookup policy and
// version order, but copies only the selected record, including history.
func (store *Store) ReadRecordSnapshot(path zone.ZonePath, key string, version uint64) (*RecordSnapshot, error) {
	if store == nil {
		return RecordSnapshotFor(nil, path, key, version)
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return RecordSnapshotFor(store.state.Network, path, key, version)
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
	return &CatalogView{ManagedZone: store.state.ManagedZone, Digests: ZoneDigests(store.state.Network)}
}

// PeerActivity contains only observation times, without applying lifecycle policy.
type PeerActivity struct {
	LastSyncUnix         int64
	ObservedLastSeenUnix int64
}

type PeerActivityView struct {
	RevokedZones map[zone.ZonePath]bool
	Peers        map[string]PeerActivity
}

// ReadPeerActivity evaluates time-dependent revocations on every read. Results
// are detached; the application retains ownership of lifecycle suppression policy.
func (store *Store) ReadPeerActivity(now time.Time) PeerActivityView {
	if store == nil {
		return PeerActivityView{}
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	out := PeerActivityView{Peers: make(map[string]PeerActivity, len(store.gossip.Peers))}
	if store.state != nil {
		out.RevokedZones = store.state.Network.RevokedZones(now)
	}
	for id, peer := range store.gossip.Peers {
		out.Peers[id] = PeerActivity{LastSyncUnix: peer.LastSyncUnix, ObservedLastSeenUnix: peer.ObservedLastSeenUnix}
	}
	return out
}
