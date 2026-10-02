// Derived from NickCao/ranet-lite internal/ike/payloads_misc.go,
// commit 24a24a2ff380c9f8ceb0092d640daa32e86b5eb5. Copyright (c) 2026 Nick Cao.
// Licensed under MIT; see third_party/ranet-lite/LICENSE.
// Photon changes: bounded nonce, KE and notification validation.
package ike

import (
	"encoding/binary"
	"fmt"
)

func EncodeKE(group uint16, pub []byte) []byte {
	b := make([]byte, 4+len(pub))
	binary.BigEndian.PutUint16(b, group)
	copy(b[4:], pub)
	return b
}
func DecodeKE(b []byte) (uint16, []byte, error) {
	if len(b) != 68 || binary.BigEndian.Uint16(b) != GroupP256 {
		return 0, nil, fmt.Errorf("ike: expected 64-byte ECP-256 KE")
	}
	return GroupP256, append([]byte(nil), b[4:]...), nil
}
func DecodeNonce(b []byte) ([]byte, error) {
	if len(b) < 16 || len(b) > 256 {
		return nil, fmt.Errorf("ike: nonce length outside 16..256")
	}
	return append([]byte(nil), b...), nil
}

type Notify struct {
	Protocol uint8
	SPI      []byte
	Type     uint16
	Data     []byte
}

func DecodeNotify(b []byte) (Notify, error) {
	if len(b) < 4 || len(b) > 65531 || int(b[1]) > len(b)-4 {
		return Notify{}, fmt.Errorf("ike: invalid notify length")
	}
	n := int(b[1])
	return Notify{Protocol: b[0], SPI: append([]byte(nil), b[4:4+n]...), Type: binary.BigEndian.Uint16(b[2:]), Data: append([]byte(nil), b[4+n:]...)}, nil
}
func EncodeNotify(n Notify) ([]byte, error) {
	if len(n.SPI) > 255 || 4+len(n.SPI)+len(n.Data) > 65531 {
		return nil, fmt.Errorf("ike: notification too large")
	}
	b := make([]byte, 4+len(n.SPI)+len(n.Data))
	b[0], b[1] = n.Protocol, byte(len(n.SPI))
	binary.BigEndian.PutUint16(b[2:], n.Type)
	copy(b[4:], n.SPI)
	copy(b[4+len(n.SPI):], n.Data)
	return b, nil
}
