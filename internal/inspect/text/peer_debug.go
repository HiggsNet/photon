package text

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/HiggsNet/photon/internal/gossipview"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func WritePeerDebug(w io.Writer, peer gossipview.Peer) error {
	out := newLineWriter(w)
	out.Linef("peer_id: %s", peer.PeerID)
	out.Linef("authorization: %s", peer.Authorization)
	out.Linef("source: %s", peer.Source)
	out.Linef("status: %s", peer.SyncStatus)
	out.Linef("last_success: %s", gossipview.FormatTime(peer.LastSyncUnix))
	out.Linef("last_failure: %s", gossipFailure(peer.LastFailure))
	out.Linef("backoff_until: %s", gossipview.FormatTime(peer.BackoffUntilUnix))
	out.Linef("configured_addr: %s", dash(peer.ConfiguredAddr))
	out.Linef("selected_addr: %s", dash(peer.SelectedAddr))
	out.Linef("discovered_addr: %s", dash(peer.DiscoveredAddr))
	out.Linef("last_successful_endpoint: %s", dash(peer.LastSuccessfulAddr))
	out.Linef("observed_addr: %s", dash(peer.ObservedAddr))
	out.Linef("observed_since: %s", gossipview.FormatTime(peer.ObservedFirstSeenUnix))
	out.Linef("observed_last_seen: %s", gossipview.FormatTime(peer.ObservedLastSeenUnix))
	out.Linef("observed_until: %s", gossipview.FormatTime(peer.ObservedUntilUnix))
	out.Linef("last_attempt: %s", gossipview.FormatTime(peer.LastAttemptUnix))
	out.Linef("last_relay: %s", gossipview.FormatTime(peer.LastRelayUnix))
	for _, endpoint := range peer.Endpoints {
		out.Linef("endpoint %s source=%s protocol=%s selected=%t", endpoint.Addr, endpoint.Source, endpoint.Protocol, endpoint.Selected)
	}
	if err := out.Err(); err != nil {
		return err
	}
	for _, detail := range []struct {
		label string
		value any
	}{
		{"session_diagnostics", peer.PeerDiagnostics},
		{"rejected_digests", peer.RejectedDigests},
	} {
		data, err := json.Marshal(detail.value)
		if err != nil {
			return err
		}
		out.Linef("%s: %s", detail.label, data)
	}
	return out.Err()
}

func gossipFailure(failure *corestate.PeerFailure) string {
	if failure == nil {
		return "-"
	}
	return fmt.Sprintf("code=%s message=%s", failure.Code, failure.Message)
}
