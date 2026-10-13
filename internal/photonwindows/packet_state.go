package photonwindows

import corestate "github.com/HiggsNet/photon/pkg/core/state"

// packetStateView belongs to the daemon's serial packet owner. Its consumers
// must treat the detached snapshot as read-only. Only verified publication
// changes it; authorization lifetimes still need checking at the event's now.
// IPC, gossip and asynchronous planners continue using their own detached views.
type packetStateView struct {
	store *corestate.Store
	view  corestate.View
}

func (r *packetStateView) read(store *corestate.Store) corestate.View {
	if r.store != store || r.view.State == nil || r.view.Revision != store.VerifiedRevision() {
		r.store, r.view = store, store.ReadView()
		// Checkpoints can change without a verified revision. Packet authorization
		// doesn't consume them; do not present retained hints as current gossip.
		r.view.Gossip = nil
	}
	return r.view
}
