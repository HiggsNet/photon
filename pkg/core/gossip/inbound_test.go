package gossip

import (
	"reflect"
	"testing"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestPlanInboundPacketActiveMessageActions(t *testing.T) {
	peerID := "peer-a"
	sessions := map[string]*SyncSession{peerID: NewSyncSession(peerID)}
	summary := &corestate.CatalogSummary{CatalogRoot: []byte("root"), ZoneCount: 1}
	tests := []struct {
		name    string
		message *Message
		kinds   []InboundActionKind
		event   any
	}{
		{"ping", &Message{Type: MessagePing, PeerID: peerID, Ping: &Ping{Summary: summary}}, []InboundActionKind{InboundPostSessionEvent, InboundRespondPing}, &CatalogSummaryReceivedEvent{}},
		{"pong", &Message{Type: MessagePong, PeerID: peerID, Pong: &Pong{Summary: summary}}, []InboundActionKind{InboundPostSessionEvent}, &PongReceivedEvent{}},
		{"fetch_zone", &Message{Type: MessageFetchZone, PeerID: peerID, FetchZone: &FetchZone{Zone: "catofes."}}, []InboundActionKind{InboundRespondFetchZone}, nil},
		{"fetch_catalog", &Message{Type: MessageFetchCatalogPage, PeerID: peerID, FetchCatalogPage: &FetchCatalogPage{}}, []InboundActionKind{InboundRespondFetchCatalogPage}, nil},
		{"catalog_page", &Message{Type: MessageCatalogPage, PeerID: peerID, CatalogPage: &corestate.CatalogPage{}}, []InboundActionKind{InboundPostSessionEvent}, &CatalogPageReceivedEvent{}},
		{"object_chunk", &Message{Type: MessageObjectChunk, PeerID: peerID}, []InboundActionKind{InboundHandleObjectChunk}, nil},
		{"object_chunk_nack", &Message{Type: MessageObjectChunkNACK, PeerID: peerID}, []InboundActionKind{InboundHandleObjectChunkNACK}, nil},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actions := PlanInboundPacket(&Packet{Message: test.message}, sessions)
			if got := inboundActionKinds(actions); !reflect.DeepEqual(got, test.kinds) {
				t.Fatalf("action kinds = %v, want %v", got, test.kinds)
			}
			for _, action := range actions {
				if !action.ActiveSession || action.Message != test.message {
					t.Fatalf("action = %#v, want active original message", action)
				}
			}
			if test.event != nil && (len(actions) == 0 || reflect.TypeOf(actions[0].Event) != reflect.TypeOf(test.event)) {
				t.Fatalf("event = %T, want %T", actions[0].Event, test.event)
			}
		})
	}
}

func TestPlanInboundPacketUnsolicitedPolicy(t *testing.T) {
	peerID := "peer-a"
	tests := []struct {
		name    string
		message *Message
		kind    InboundActionKind
	}{
		{"ping", &Message{Type: MessagePing, PeerID: peerID, Ping: &Ping{}}, InboundRespondPing},
		{"fetch_zone", &Message{Type: MessageFetchZone, PeerID: peerID, FetchZone: &FetchZone{}}, InboundRespondFetchZone},
		{"fetch_catalog", &Message{Type: MessageFetchCatalogPage, PeerID: peerID, FetchCatalogPage: &FetchCatalogPage{}}, InboundRespondFetchCatalogPage},
		{"object_chunk_nack", &Message{Type: MessageObjectChunkNACK, PeerID: peerID}, InboundHandleObjectChunkNACK},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			actions := PlanInboundPacket(&Packet{Message: test.message}, nil)
			if len(actions) != 1 || actions[0].Kind != test.kind || actions[0].ActiveSession {
				t.Fatalf("actions = %#v, want one unsolicited %s", actions, test.kind)
			}
		})
	}
}

func TestPlanInboundPacketIgnoresInvalidAndUnsolicitedPullResults(t *testing.T) {
	peerID := "peer-a"
	ignored := []*Message{
		nil,
		{Type: MessagePing, PeerID: peerID},
		{Type: MessagePong, PeerID: peerID, Pong: &Pong{}},
		{Type: MessageFetchZone, PeerID: peerID},
		{Type: MessageFetchCatalogPage, PeerID: peerID},
		{Type: MessageCatalogPage, PeerID: peerID, CatalogPage: &corestate.CatalogPage{}},
		{Type: MessageObjectChunk, PeerID: peerID},
		{Type: MessageType("unknown"), PeerID: peerID},
	}
	for _, message := range ignored {
		packet := &Packet{Message: message}
		if message == nil {
			packet = &Packet{}
		}
		if actions := PlanInboundPacket(packet, nil); len(actions) != 0 {
			t.Errorf("PlanInboundPacket(%#v) = %#v, want ignored", message, actions)
		}
	}
	if actions := PlanInboundPacket(nil, nil); len(actions) != 0 {
		t.Fatalf("PlanInboundPacket(nil) = %#v, want ignored", actions)
	}
}

func TestPlanInboundPacketNilSessionEntryUsesUnsolicitedPolicy(t *testing.T) {
	message := &Message{Type: MessagePing, PeerID: "peer-a", Ping: &Ping{}}
	actions := PlanInboundPacket(&Packet{Message: message}, map[string]*SyncSession{"peer-a": nil})
	if len(actions) != 1 || actions[0].ActiveSession {
		t.Fatalf("actions = %#v, want unsolicited ping", actions)
	}
}

func inboundActionKinds(actions []InboundAction) []InboundActionKind {
	out := make([]InboundActionKind, 0, len(actions))
	for _, action := range actions {
		out = append(out, action.Kind)
	}
	return out
}
