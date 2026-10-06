package state

import (
	"github.com/HiggsNet/photon/pkg/core/zone"
	"time"
)

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
