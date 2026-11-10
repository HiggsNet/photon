package text

import (
	"io"

	"github.com/HiggsNet/photon/internal/gossipview"
	"github.com/HiggsNet/photon/pkg/core/gossip"
)

func WriteEndpointsDebug(w io.Writer, view gossipview.View) error {
	out := newLineWriter(w)
	published := 0
	if len(view.LocalEndpoints) > 0 {
		published++
	}
	publishedCounts := make([]int, len(view.Peers))
	// Bootstrap and observed addresses have no published address field.
	for i, peer := range view.Peers {
		for _, ep := range peer.Endpoints {
			if ep.Address != "" {
				publishedCounts[i]++
			}
		}
		if publishedCounts[i] > 0 {
			published++
		}
	}
	out.Linef("published_peers: %d", published)
	if len(view.LocalEndpoints) > 0 {
		out.Linef("peer %s endpoints=%d local=true", view.ManagedZone, len(view.LocalEndpoints))
		for _, ep := range view.LocalEndpoints {
			writePublishedEndpoint(out, ep)
		}
	}
	for i, peer := range view.Peers {
		if publishedCounts[i] == 0 {
			continue
		}
		out.Linef("peer %s endpoints=%d local=false", peer.PeerID, publishedCounts[i])
		for _, ep := range peer.Endpoints {
			if ep.Address != "" {
				writePublishedEndpoint(out, ep.EndpointEntry)
			}
		}
	}
	return out.Err()
}

func writePublishedEndpoint(out *lineWriter, ep gossip.EndpointEntry) {
	out.Linef("  endpoint addr=%s port=%d scope=%s priority=%d protocol=%s source=%s last_observed=%s",
		ep.Address, ep.Port, ep.Scope, ep.Priority, ep.Protocol, dash(ep.Source), formatUnixTime(ep.LastObserved))
}
