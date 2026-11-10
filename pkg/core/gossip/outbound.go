package gossip

// OutboundMessage is the protocol-owned wire result of a send action. The
// host runtime/controller owns actual transport I/O and diagnostics.
type OutboundMessage struct {
	PeerID  string
	Message *Message
}

// OutboundMessageForAction converts the send subset of SyncAction into its
// wire message. Non-send actions return ok=false and remain host concerns.
func OutboundMessageForAction(action SyncAction) (outbound OutboundMessage, ok bool) {
	switch typed := action.(type) {
	case SendPingAction:
		return OutboundMessage{
			PeerID: typed.PeerID,
			Message: &Message{
				Type: MessagePing,
				Ping: &Ping{Summary: typed.Summary},
			},
		}, true
	case SendFetchCatalogPageAction:
		return OutboundMessage{
			PeerID: typed.PeerID,
			Message: &Message{
				Type:             MessageFetchCatalogPage,
				FetchCatalogPage: &FetchCatalogPage{Cursor: typed.Cursor},
			},
		}, true
	case SendChunkFallbackAction:
		return OutboundMessage{
			PeerID: typed.PeerID,
			Message: &Message{
				Type:      MessageFetchZone,
				FetchZone: &FetchZone{Zone: typed.Zone},
			},
		}, true
	default:
		return OutboundMessage{}, false
	}
}
