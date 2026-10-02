// Derived from NickCao/ranet-lite internal/ike/payloads_sa.go,
// commit 24a24a2ff380c9f8ceb0092d640daa32e86b5eb5. Copyright (c) 2026 Nick Cao.
// Licensed under MIT; see third_party/ranet-lite/LICENSE.
// Photon changes: one CBC/HMAC suite, exact response selection and bounded parsing.
package ike

import (
	"encoding/binary"
	"fmt"
)

const GroupP256 uint16 = 19

// DefaultIKEProposal is the sole initial IKE offer: AES-CBC-128,
// PRF-HMAC-SHA256, AUTH-HMAC-SHA256-128 and ECP-256. No proposal SPI is
// present in IKE_SA_INIT; rekey proposals use a different wire shape.
func DefaultIKEProposal() []byte {
	return []byte{
		0, 0, 0, 44, 1, 1, 0, 4,
		3, 0, 0, 12, 1, 0, 0, 12, 0x80, 14, 0, 128,
		3, 0, 0, 8, 2, 0, 0, 5,
		3, 0, 0, 8, 3, 0, 0, 12,
		0, 0, 0, 8, 4, 0, 0, 19,
	}
}

// ValidateIKESelection accepts exactly one selection from DefaultIKEProposal.
// Transform order may differ, but duplicate/unknown attributes or transforms,
// extra proposals and proposal numbers/SPIs outside that offer are rejected.
func ValidateIKESelection(b []byte) error {
	if len(b) < 8 || len(b) > MaxMessageSize-HeaderLen {
		return fmt.Errorf("ike: invalid SA length")
	}
	if b[0] != 0 || int(binary.BigEndian.Uint16(b[2:])) != len(b) || b[4] != 1 || b[5] != 1 || b[6] != 0 || b[7] != 4 {
		return fmt.Errorf("ike: selection is not one initial IKE proposal from our offer")
	}
	rest := b[8:]
	var seen [5]bool
	ids := [5]uint16{0, 12, 5, 12, 19}
	for i := 0; i < 4; i++ {
		if len(rest) < 8 {
			return fmt.Errorf("ike: short transform")
		}
		more := byte(3)
		if i == 3 {
			more = 0
		}
		if rest[0] != more {
			return fmt.Errorf("ike: transform count mismatch")
		}
		n := int(binary.BigEndian.Uint16(rest[2:]))
		if n < 8 || n > len(rest) {
			return fmt.Errorf("ike: invalid transform length")
		}
		typ := rest[4]
		if typ < 1 || typ > 4 || seen[typ] || binary.BigEndian.Uint16(rest[6:]) != ids[typ] {
			return fmt.Errorf("ike: unoffered or duplicate transform")
		}
		seen[typ] = true
		attrs := rest[8:n]
		if typ == 1 {
			// KEY_LENGTH is a TV attribute in the negotiated AES-CBC transform.
			if len(attrs) != 4 || binary.BigEndian.Uint16(attrs) != 0x800e || binary.BigEndian.Uint16(attrs[2:]) != 128 {
				return fmt.Errorf("ike: AES key length is not 128 bits")
			}
		} else if len(attrs) != 0 {
			return fmt.Errorf("ike: unexpected transform attributes")
		}
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return fmt.Errorf("ike: trailing transform bytes")
	}
	return nil
}
