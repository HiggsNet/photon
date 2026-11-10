package gossip

import (
	"testing"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestOutboundMessageForAction(t *testing.T) {
	summary := &corestate.CatalogSummary{CatalogRoot: []byte("root"), ZoneCount: 1}
	tests := []struct {
		name     string
		action   SyncAction
		wantType MessageType
		check    func(*testing.T, *Message)
	}{
		{
			name:     "ping",
			action:   SendPingAction{PeerID: "peer-a", Summary: summary},
			wantType: MessagePing,
			check: func(t *testing.T, message *Message) {
				if message.Ping == nil || message.Ping.Summary != summary {
					t.Fatalf("ping = %#v, want supplied summary", message.Ping)
				}
			},
		},
		{
			name:     "catalog_page_request",
			action:   SendFetchCatalogPageAction{PeerID: "peer-a", Cursor: "3"},
			wantType: MessageFetchCatalogPage,
			check: func(t *testing.T, message *Message) {
				if message.FetchCatalogPage == nil || message.FetchCatalogPage.Cursor != "3" {
					t.Fatalf("fetch catalog page = %#v, want cursor 3", message.FetchCatalogPage)
				}
			},
		},
		{
			name:     "chunk_fallback",
			action:   SendChunkFallbackAction{PeerID: "peer-a", Zone: "node-a.catofes."},
			wantType: MessageFetchZone,
			check: func(t *testing.T, message *Message) {
				if message.FetchZone == nil || message.FetchZone.Zone != "node-a.catofes." {
					t.Fatalf("fetch zone = %#v, want chunk fallback", message.FetchZone)
				}
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			outbound, ok := OutboundMessageForAction(test.action)
			if !ok || outbound.PeerID != "peer-a" || outbound.Message == nil || outbound.Message.Type != test.wantType {
				t.Fatalf("outbound = %#v ok=%t, want peer-a/%s", outbound, ok, test.wantType)
			}
			test.check(t, outbound.Message)
		})
	}
}

func TestOutboundMessageForActionRejectsHostAction(t *testing.T) {
	if outbound, ok := OutboundMessageForAction(RecordBackoffAction{}); ok || outbound.Message != nil {
		t.Fatalf("outbound = %#v ok=%t, want non-send action", outbound, ok)
	}
}
