package gossip

// InboundActionKind identifies a platform-neutral action produced from a
// verified inbound gossip packet. Executors own all I/O and persistence.
type InboundActionKind string

const (
	InboundPostSessionEvent        InboundActionKind = "post_session_event"
	InboundRespondPing             InboundActionKind = "respond_ping"
	InboundRespondFetchZone        InboundActionKind = "respond_fetch_zone"
	InboundRespondFetchCatalogPage InboundActionKind = "respond_fetch_catalog_page"
	InboundHandleObjectChunk       InboundActionKind = "handle_object_chunk"
	InboundHandleObjectChunkNACK   InboundActionKind = "handle_object_chunk_nack"
)

// InboundAction is a pure routing decision. Message points at the verified
// wire message supplied by the caller. Event is set only for
// InboundPostSessionEvent.
type InboundAction struct {
	Kind          InboundActionKind
	ActiveSession bool
	Message       *Message
	Event         SyncEvent
}

// PlanInboundPacket classifies a verified packet against the active session
// set and returns the ordered actions both Linux and leaf clients must execute.
func PlanInboundPacket(packet *Packet, sessions map[string]*SyncSession) []InboundAction {
	routed := RoutePacket(packet, sessions)
	active := false
	switch event := routed.(type) {
	case *PacketEvent:
		active = true
		packet = event.Packet
	case *UnsolicitedPacketEvent:
		packet = event.Packet
	default:
		return nil
	}
	if packet == nil || packet.Message == nil {
		return nil
	}
	message := packet.Message
	action := func(kind InboundActionKind) InboundAction {
		return InboundAction{Kind: kind, ActiveSession: active, Message: message}
	}

	switch message.Type {
	case MessagePing:
		if message.Ping == nil {
			return nil
		}
		var actions []InboundAction
		if active && message.Ping.Summary != nil {
			actions = append(actions, InboundAction{
				Kind:          InboundPostSessionEvent,
				ActiveSession: true,
				Message:       message,
				Event: &CatalogSummaryReceivedEvent{
					PeerID:  message.PeerID,
					Summary: message.Ping.Summary,
				},
			})
		}
		return append(actions, action(InboundRespondPing))
	case MessagePong:
		if !active || message.Pong == nil {
			return nil
		}
		return []InboundAction{{
			Kind:          InboundPostSessionEvent,
			ActiveSession: true,
			Message:       message,
			Event:         &PongReceivedEvent{PeerID: message.PeerID, Pong: message.Pong},
		}}
	case MessageFetchZone:
		if message.FetchZone == nil {
			return nil
		}
		return []InboundAction{action(InboundRespondFetchZone)}
	case MessageFetchCatalogPage:
		if message.FetchCatalogPage == nil {
			return nil
		}
		return []InboundAction{action(InboundRespondFetchCatalogPage)}
	case MessageCatalogPage:
		if !active || message.CatalogPage == nil {
			return nil
		}
		return []InboundAction{{
			Kind:          InboundPostSessionEvent,
			ActiveSession: true,
			Message:       message,
			Event:         &CatalogPageReceivedEvent{PeerID: message.PeerID, Page: message.CatalogPage},
		}}
	case MessageObjectChunk:
		if !active {
			return nil
		}
		return []InboundAction{action(InboundHandleObjectChunk)}
	case MessageObjectChunkNACK:
		return []InboundAction{action(InboundHandleObjectChunkNACK)}
	default:
		return nil
	}
}
