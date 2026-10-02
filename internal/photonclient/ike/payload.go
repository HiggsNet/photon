// Derived from NickCao/ranet-lite internal/ike/{header,payload}.go,
// commit 24a24a2ff380c9f8ceb0092d640daa32e86b5eb5. Copyright (c) 2026 Nick Cao.
// Licensed under MIT; see third_party/ranet-lite/LICENSE.
// Photon changes: bounded messages, explicit errors, critical and duplicate checks.
package ike

import (
	"encoding/binary"
	"fmt"
)

const (
	HeaderLen            = 28
	MaxMessageSize       = 65507 // Maximum IPv4 UDP payload, including the IKE header.
	MaxPayloads          = 64
	PayloadSA      uint8 = 33
	PayloadKE      uint8 = 34
	PayloadNonce   uint8 = 40
	PayloadNotify  uint8 = 41
	PayloadVendor  uint8 = 43
	PayloadSK      uint8 = 46
	ExchangeSAInit uint8 = 34
	FlagInitiator  uint8 = 0x08
	FlagResponse   uint8 = 0x20
)

type Header struct {
	InitiatorSPI, ResponderSPI uint64
	ExchangeType, Flags        uint8
	MessageID                  uint32
}

// Marshal creates the fixed IKEv2 header. Message-specific SPI and flag rules
// are validated by the session, which knows the request being answered.
func (h Header) Marshal(next uint8, length int) ([]byte, error) {
	if length < HeaderLen || length > MaxMessageSize {
		return nil, fmt.Errorf("ike: invalid message size %d", length)
	}
	b := make([]byte, HeaderLen)
	binary.BigEndian.PutUint64(b, h.InitiatorSPI)
	binary.BigEndian.PutUint64(b[8:], h.ResponderSPI)
	b[16], b[17], b[18], b[19] = next, 0x20, h.ExchangeType, h.Flags
	binary.BigEndian.PutUint32(b[20:], h.MessageID)
	binary.BigEndian.PutUint32(b[24:], uint32(length))
	return b, nil
}

// DecodeHeader also verifies the enclosing datagram length before any parsing.
func DecodeHeader(b []byte) (Header, uint8, error) {
	if len(b) < HeaderLen || len(b) > MaxMessageSize {
		return Header{}, 0, fmt.Errorf("ike: invalid message size %d", len(b))
	}
	if binary.BigEndian.Uint32(b[24:]) != uint32(len(b)) {
		return Header{}, 0, fmt.Errorf("ike: message length mismatch")
	}
	if b[17]>>4 != 2 {
		return Header{}, 0, fmt.Errorf("ike: unsupported major version")
	}
	return Header{InitiatorSPI: binary.BigEndian.Uint64(b), ResponderSPI: binary.BigEndian.Uint64(b[8:]), ExchangeType: b[18], Flags: b[19], MessageID: binary.BigEndian.Uint32(b[20:])}, b[16], nil
}

type Payload struct {
	Type     uint8
	Critical bool
	Data     []byte
}

// EncodePayloads encodes a plaintext payload chain. SK is framed by the crypto
// layer because its next-payload byte refers to encrypted inner payloads.
func EncodePayloads(ps []Payload) (uint8, []byte, error) {
	if len(ps) > MaxPayloads {
		return 0, nil, fmt.Errorf("ike: too many payloads")
	}
	size := 0
	for _, p := range ps {
		if p.Type == 0 || p.Type == PayloadSK || len(p.Data) > 65531 {
			return 0, nil, fmt.Errorf("ike: invalid plaintext payload")
		}
		size += 4 + len(p.Data)
	}
	if size > MaxMessageSize-HeaderLen {
		return 0, nil, fmt.Errorf("ike: payload chain too large")
	}
	b := make([]byte, 0, size)
	for i, p := range ps {
		hdr := []byte{0, 0, 0, 0}
		if i+1 < len(ps) {
			hdr[0] = ps[i+1].Type
		}
		if p.Critical {
			hdr[1] = 0x80
		}
		binary.BigEndian.PutUint16(hdr[2:], uint16(4+len(p.Data)))
		b = append(b, hdr...)
		b = append(b, p.Data...)
	}
	first := uint8(0)
	if len(ps) > 0 {
		first = ps[0].Type
	}
	if _, err := DecodePayloads(first, b); err != nil {
		return 0, nil, err
	}
	return first, b, nil
}

// DecodePayloads returns owned payload bytes. Unknown noncritical payloads are
// retained for round trips but never treated as recognized protocol content.
func DecodePayloads(first uint8, b []byte) ([]Payload, error) {
	if len(b) > MaxMessageSize-HeaderLen {
		return nil, fmt.Errorf("ike: payload chain too large")
	}
	var ps []Payload
	seen := make(map[uint8]bool)
	for next := first; next != 0; {
		if len(ps) >= MaxPayloads || len(b) < 4 {
			return nil, fmt.Errorf("ike: payload count or truncated header")
		}
		n := int(binary.BigEndian.Uint16(b[2:4]))
		if n < 4 || n > len(b) {
			return nil, fmt.Errorf("ike: invalid payload length")
		}
		known := next >= 33 && next <= 48
		if next == PayloadSK {
			return nil, fmt.Errorf("ike: encrypted payload in plaintext chain")
		}
		if b[1]&0x80 != 0 && !known {
			return nil, fmt.Errorf("ike: unsupported critical payload %d", next)
		}
		// RFC 7296 permits repeated CERT, CERTREQ, Notify, Delete and Vendor ID.
		repeatable := next == 37 || next == 38 || next == 41 || next == 42 || next == 43
		if known && seen[next] && !repeatable {
			return nil, fmt.Errorf("ike: duplicate payload %d", next)
		}
		seen[next] = true
		ps = append(ps, Payload{Type: next, Critical: b[1]&0x80 != 0, Data: append([]byte(nil), b[4:n]...)})
		next, b = b[0], b[n:]
	}
	if len(b) != 0 {
		return nil, fmt.Errorf("ike: trailing payload bytes")
	}
	return ps, nil
}

func EncodeMessage(h Header, ps []Payload) ([]byte, error) {
	first, body, err := EncodePayloads(ps)
	if err != nil {
		return nil, err
	}
	b, err := h.Marshal(first, HeaderLen+len(body))
	if err != nil {
		return nil, err
	}
	return append(b, body...), nil
}
func DecodeMessage(b []byte) (Header, []Payload, error) {
	h, first, err := DecodeHeader(b)
	if err != nil {
		return Header{}, nil, err
	}
	ps, err := DecodePayloads(first, b[HeaderLen:])
	return h, ps, err
}
