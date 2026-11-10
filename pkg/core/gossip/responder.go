package gossip

import (
	"bytes"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// CatalogRootsMatch reports whether two non-nil catalog summaries advertise
// the same root. ZoneCount is metadata and does not change root identity.
func CatalogRootsMatch(left, right *corestate.CatalogSummary) bool {
	return left != nil && right != nil && bytes.Equal(left.CatalogRoot, right.CatalogRoot)
}

// PlanPingResponse creates the ordered protocol responses for an inbound
// PING. The caller owns transport send, diagnostics and persistence.
func PlanPingResponse(ping *Ping, localSummary *corestate.CatalogSummary) []*Message {
	if ping == nil || localSummary == nil {
		return nil
	}
	messages := []*Message{{
		Type: MessagePong,
		Pong: &Pong{Summary: localSummary},
	}}
	if ping.Summary != nil && !CatalogRootsMatch(ping.Summary, localSummary) {
		messages = append(messages, &Message{
			Type:             MessageFetchCatalogPage,
			FetchCatalogPage: &FetchCatalogPage{},
		})
	}
	return messages
}
