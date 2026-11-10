package text

import (
	"io"

	"github.com/HiggsNet/photon/internal/gossipview"
)

func WriteSyncStatus(w io.Writer, view gossipview.View, verbose bool) error {
	out := newLineWriter(w)
	out.Linef("peer_id: %s", view.PeerID)
	out.Linef("listen_addr: %s", view.ListenAddr)
	out.Linef("known_peers: %d", len(view.Peers))
	out.Linef("known_zones: %d", view.ZoneCount)
	out.Linef("local_root: %s", view.CatalogRoot)
	out.Linef("limits: max_datagram_bytes=%d max_sync_records=%d wire_version=%d wire_codec=%s",
		view.MaxDatagramBytes, view.MaxSyncRecords, view.WireVersion, view.WireCodec)
	for _, peer := range view.Peers {
		out.Linef("peer %s addr=%s status=%s last_sync=%s",
			peer.PeerID, dash(peer.SelectedAddr), peer.SyncStatus, gossipview.FormatTime(peer.LastSyncUnix))
		if !verbose {
			continue
		}
		if peer.Source == "bootstrap" {
			out.Linef("bootstrap peer=%s configured_addr=%s", peer.PeerID, dash(peer.ConfiguredAddr))
		} else if peer.DiscoveredAddr != "" {
			out.Linef("discovered peer=%s addr=%s", peer.PeerID, peer.DiscoveredAddr)
		}
		if err := out.Err(); err != nil {
			return err
		}
		if err := WritePeerDebug(w, peer); err != nil {
			return err
		}
	}
	return out.Err()
}
