package gossip

import (
	"bytes"
	"errors"
	"math"

	"github.com/vmihailenco/msgpack/v5"
)

var (
	wireMagicMsgpack    = []byte("photon.gossip.m1\n")
	ErrUnsupportedCodec = errors.New("unsupported gossip codec")
)

// MarshalMessage encodes a MessagePack datagram.
func MarshalMessage(message *Message) ([]byte, error) {
	if message != nil && message.Version == 0 {
		message.Version = WireVersion
	}
	if err := validateMessage(message); err != nil {
		return nil, err
	}
	payload, err := msgpack.Marshal(message)
	if err != nil {
		return nil, err
	}
	out := make([]byte, 0, len(wireMagicMsgpack)+len(payload))
	out = append(out, wireMagicMsgpack...)
	out = append(out, payload...)
	return out, nil
}

// UnmarshalMessage decodes a MessagePack datagram.
func UnmarshalMessage(data []byte) (*Message, error) {
	if !bytes.HasPrefix(data, wireMagicMsgpack) {
		return nil, ErrUnsupportedCodec
	}
	var message Message
	if err := msgpack.Unmarshal(data[len(wireMagicMsgpack):], &message); err != nil {
		return nil, err
	}
	if err := validateMessage(&message); err != nil {
		return nil, err
	}
	return &message, nil
}

// WireEncodeSizeForPeer returns the encoded wire size of message with the
// sender identity that Transport.Send will install. Max-width nonce and
// timestamp values reserve the largest MessagePack integer representation, so
// a page accepted by a builder cannot grow beyond its budget at send time.
func WireEncodeSizeForPeer(message *Message, senderPeerID string) (int, error) {
	if message == nil {
		return 0, errors.New("gossip message is nil")
	}
	candidate := *message
	if senderPeerID != "" {
		candidate.PeerID = senderPeerID
	} else if candidate.PeerID == "" {
		candidate.PeerID = "size-check"
	}
	if candidate.Nonce == 0 {
		candidate.Nonce = math.MaxUint64
	}
	if candidate.Timestamp == 0 {
		candidate.Timestamp = math.MaxInt64
	}
	data, err := MarshalMessage(&candidate)
	if err != nil {
		return 0, err
	}
	return len(data), nil
}
