package state

import (
	"maps"
	"math"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
)

// revocationSnapshot is immutable and valid only within one verified revision
// and one interval between scheduled revocations. The lower bound also makes
// clock rollback safe. Checkpoint writes do not change revocation policy.
type revocationSnapshot struct {
	revision  VerifiedRevision
	fromUnix  int64
	untilUnix int64 // zero means no future activation
	zones     map[zone.ZonePath]bool
}

// revokedZonesLocked requires Store.mu to pin the committed verified revision.
// Return a detached map, just like the uncached NetworkState projection.
func (store *Store) revokedZonesLocked(now time.Time) map[zone.ZonePath]bool {
	if store.state == nil || store.state.Network == nil {
		return make(map[zone.ZonePath]bool)
	}
	second := now.Unix()
	snapshot := store.revocations.Load()
	if snapshot == nil || snapshot.revision != store.revision || second < snapshot.fromUnix ||
		(snapshot.untilUnix != 0 && second >= snapshot.untilUnix) {
		network := store.state.Network
		snapshot = &revocationSnapshot{
			revision: store.revision, fromUnix: math.MinInt64,
			zones: network.RevokedZones(now),
		}
		// ActiveRevocation depends on time only through positive RevokedAt
		// values. Include even currently inapplicable tombstones: unnecessary
		// invalidation is harmless, while missing a boundary is not.
		for _, parent := range network.Zones {
			if parent == nil {
				continue
			}
			for _, revocation := range parent.Revocations {
				if revocation == nil || revocation.RevokedAt <= 0 {
					continue
				}
				at := revocation.RevokedAt
				if at <= second {
					snapshot.fromUnix = max(snapshot.fromUnix, at)
				} else if snapshot.untilUnix == 0 || at < snapshot.untilUnix {
					snapshot.untilUnix = at
				}
			}
		}
		store.revocations.Store(snapshot)
	}
	return maps.Clone(snapshot.zones)
}
