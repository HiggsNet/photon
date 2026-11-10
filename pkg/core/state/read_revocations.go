package state

import (
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// IsZoneRevoked checks the committed network at the event's evaluation time.
func (store *Store) IsZoneRevoked(path zone.ZonePath, now time.Time) bool {
	if store == nil {
		return false
	}
	store.mu.RLock()
	defer store.mu.RUnlock()
	return store.state != nil && store.state.Network.IsZoneRevoked(path, now)
}
