package gossip

import (
	"bytes"
	"testing"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

func TestMsgpackCodecRoundTrip(t *testing.T) {
	message := &Message{
		Type:      MessagePing,
		PeerID:    "node-a",
		Nonce:     42,
		Timestamp: 1717171717,
		Ping: &Ping{Summary: &corestate.CatalogSummary{
			CatalogRoot: []byte{1, 2, 3, 4},
			ZoneCount:   1,
		}},
	}
	codec := msgpackCodec{}
	data, err := encodeMessage(codec, message)
	if err != nil {
		t.Fatalf("encodeMessage: %v", err)
	}
	if !bytes.HasPrefix(data, wireMagicMsgpack) {
		t.Fatalf("expected msgpack magic prefix, got %q", data[:len(wireMagicMsgpack)])
	}
	got, err := decodeMessage(data)
	if err != nil {
		t.Fatalf("decodeMessage: %v", err)
	}
	if got.Type != MessagePing || got.PeerID != "node-a" || got.Nonce != 42 {
		t.Fatalf("round-trip mismatch: %+v", got)
	}
	if got.Ping.Summary == nil || got.Ping.Summary.ZoneCount != 1 || !bytes.Equal(got.Ping.Summary.CatalogRoot, []byte{1, 2, 3, 4}) {
		t.Fatalf("summary mismatch: %+v", got.Ping.Summary)
	}
}

func TestObjectChunkCodecRoundTrip(t *testing.T) {
	message := &Message{
		Type:      MessageObjectChunk,
		PeerID:    "node-a.catofes.",
		Nonce:     99,
		Timestamp: 1717171717,
		ObjectChunk: &ObjectChunk{
			TransferID: []byte("0123456789abcdef"),
			Object:     ObjectPullZone,
			Zone:       "catofes.",
			RootHash:   []byte{1, 2, 3},
			ObjectHash: []byte{4, 5, 6},
			Index:      1,
			Total:      2,
			Data:       []byte("chunk-data"),
		},
	}
	data, err := encodeMessage(msgpackCodec{}, message)
	if err != nil {
		t.Fatalf("encodeMessage(object_chunk): %v", err)
	}
	got, err := decodeMessage(data)
	if err != nil {
		t.Fatalf("decodeMessage(object_chunk): %v", err)
	}
	if got.Type != MessageObjectChunk || got.ObjectChunk == nil {
		t.Fatalf("decoded message = %#v, want object_chunk", got)
	}
	if got.ObjectChunk.Zone != "catofes." || got.ObjectChunk.Index != 1 || string(got.ObjectChunk.Data) != "chunk-data" {
		t.Fatalf("decoded chunk mismatch: %#v", got.ObjectChunk)
	}
}

func TestUnsupportedCodecsRejected(t *testing.T) {
	for _, magic := range []string{
		"higgs.gossip.m1\n",  // pre-Photon wire format
		"photon.gossip.v1\n", // retired JSON codec
		"photon.gossip.x9\n", // unknown codec
	} {
		data := append([]byte(magic), []byte(`{}`)...)
		_, err := decodeMessage(data)
		if err == nil {
			t.Fatalf("decodeMessage(%q) succeeded, want error", magic)
		}
		if RejectReason(err) != "unsupported_codec" {
			t.Fatalf("RejectReason(%q) = %q, want unsupported_codec; err=%v", magic, RejectReason(err), err)
		}
	}
}

func TestDefaultSendCodecIsMsgpack(t *testing.T) {
	if _, ok := DefaultSendCodec.(msgpackCodec); !ok {
		t.Fatalf("DefaultSendCodec should be msgpackCodec, got %T", DefaultSendCodec)
	}
}

func BenchmarkPingMsgpack(b *testing.B) {
	message := &Message{
		Type:      MessagePing,
		PeerID:    "node-a.catofes.",
		Nonce:     123456789,
		Timestamp: 1717171717,
		Ping:      &Ping{Summary: &corestate.CatalogSummary{CatalogRoot: make([]byte, 32), ZoneCount: 2}},
	}
	codec := msgpackCodec{}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = encodeMessage(codec, message)
	}
}

func TestCommonMessageSizesWithinDatagramBudget(t *testing.T) {
	digest := corestate.ZoneDigest{Zone: "node-a.catofes.", RootHash: make([]byte, 32)}

	cases := []struct {
		name    string
		message *Message
	}{
		{
			name:    "ping",
			message: commonWireMessage(MessagePing, &Ping{Summary: &corestate.CatalogSummary{CatalogRoot: digest.RootHash, ZoneCount: 1}}, nil, nil, nil),
		},
		{
			name:    "pong",
			message: commonWireMessage(MessagePong, nil, &Pong{Summary: &corestate.CatalogSummary{CatalogRoot: digest.RootHash, ZoneCount: 1}}, nil, nil),
		},
		{
			name:    "announce digest",
			message: commonWireMessage(MessageAnnounce, nil, nil, nil, &Announce{Zones: []corestate.ZoneDigest{digest}}),
		},
	}

	for _, tc := range cases {
		size, err := WireEncodeSize(tc.message)
		if err != nil {
			t.Fatalf("%s WireEncodeSize: %v", tc.name, err)
		}
		t.Logf("%s wire size: %d bytes, headroom: %d bytes", tc.name, size, DefaultDatagramBudget-size)
		if size > DefaultDatagramBudget {
			t.Fatalf("%s wire size = %d bytes, exceeds %d-byte datagram budget", tc.name, size, DefaultDatagramBudget)
		}
	}
}

func commonWireMessage(messageType MessageType, ping *Ping, pong *Pong, fetchZone *FetchZone, announce *Announce) *Message {
	return &Message{
		Version:   WireVersion,
		Type:      messageType,
		PeerID:    "node-a.catofes.",
		Nonce:     123456789,
		Timestamp: 1717171717,
		Ping:      ping,
		Pong:      pong,
		FetchZone: fetchZone,
		Announce:  announce,
	}
}
