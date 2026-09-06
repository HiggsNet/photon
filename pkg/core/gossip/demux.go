package gossip

// RoutePacket classifies an inbound packet as belonging to an active
// per-peer sync session or to the read-only/unsolicited responder path. It is
// stateless and does not interpret message type.
func RoutePacket(packet *Packet, sessions map[string]*SyncSession) SyncEvent {
	if packet == nil || packet.Message == nil {
		return &UnsolicitedPacketEvent{Packet: packet}
	}
	if session, ok := sessions[packet.Message.PeerID]; ok && session != nil {
		return &PacketEvent{Session: session, Packet: packet}
	}
	return &UnsolicitedPacketEvent{Packet: packet}
}

// PacketEvent identifies a packet matched to an active sync session. The
// GossipDriver packet dispatcher translates it into a protocol event/response.
type PacketEvent struct {
	Session *SyncSession
	Packet  *Packet
}

func (*PacketEvent) SyncEventMarker() {}

// UnsolicitedPacketEvent identifies a packet without an active session. The
// GossipDriver may service read-only requests or use announcements as a hint.
type UnsolicitedPacketEvent struct {
	Packet *Packet
}

func (*UnsolicitedPacketEvent) SyncEventMarker() {}
