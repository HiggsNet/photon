package ike

// Initial CHILD_SA wire formats and key derivation follow RFC 7296 sections
// 2.9, 2.17, 3.3 and 3.13, and RFC 4106 section 8.1. No rekey/PFS is implied.
import (
	"encoding/binary"
	"fmt"
	"net/netip"
)

// EncodeChildProposal offers tunnel-mode ESP AES-GCM-16-128 without extended
// sequence numbers. Tunnel mode is implicit unless USE_TRANSPORT_MODE is sent.
// The SPI identifies the initiator's inbound SA. Reserved SPIs are not emitted.
func EncodeChildProposal(spi uint32) ([]byte, error) {
	if spi < 256 {
		return nil, fmt.Errorf("ike: reserved ESP SPI")
	}
	b := []byte{0, 0, 0, 32, 1, 3, 4, 2, 0, 0, 0, 0,
		3, 0, 0, 12, 1, 0, 0, 20, 0x80, 14, 0, 128,
		0, 0, 0, 8, 5, 0, 0, 0}
	binary.BigEndian.PutUint32(b[8:], spi)
	return b, nil
}

// ValidateChildSelection accepts one selection from EncodeChildProposal and
// returns the responder's inbound ESP SPI. Transform order is immaterial.
func ValidateChildSelection(b []byte) (uint32, error) {
	if len(b) != 32 || b[0] != 0 || binary.BigEndian.Uint16(b[2:]) != 32 || b[4] != 1 || b[5] != 3 || b[6] != 4 || b[7] != 2 {
		return 0, fmt.Errorf("ike: invalid initial CHILD proposal")
	}
	spi := binary.BigEndian.Uint32(b[8:])
	if spi < 256 {
		return 0, fmt.Errorf("ike: reserved ESP SPI")
	}
	rest := b[12:]
	var encryption, esn bool
	for i := 0; i < 2; i++ {
		if len(rest) < 8 {
			return 0, fmt.Errorf("ike: truncated CHILD transform")
		}
		more := byte(3)
		if i == 1 {
			more = 0
		}
		n := int(binary.BigEndian.Uint16(rest[2:]))
		if rest[0] != more || n < 8 || n > len(rest) {
			return 0, fmt.Errorf("ike: invalid CHILD transform length")
		}
		switch rest[4] {
		case 1:
			if encryption || n != 12 || binary.BigEndian.Uint16(rest[6:]) != 20 || binary.BigEndian.Uint16(rest[8:]) != 0x800e || binary.BigEndian.Uint16(rest[10:]) != 128 {
				return 0, fmt.Errorf("ike: unoffered CHILD encryption")
			}
			encryption = true
		case 5:
			if esn || n != 8 || binary.BigEndian.Uint16(rest[6:]) != 0 {
				return 0, fmt.Errorf("ike: unoffered CHILD ESN")
			}
			esn = true
		default:
			return 0, fmt.Errorf("ike: unoffered CHILD transform")
		}
		rest = rest[n:]
	}
	if !encryption || !esn || len(rest) != 0 {
		return 0, fmt.Errorf("ike: incomplete CHILD selection")
	}
	return spi, nil
}

type TrafficSelector struct {
	Protocol           uint8
	StartPort, EndPort uint16
	StartAddr, EndAddr netip.Addr
}

func (s TrafficSelector) validate() error {
	if !s.StartAddr.IsValid() || !s.EndAddr.IsValid() || s.StartAddr.Is4In6() || s.EndAddr.Is4In6() || s.StartAddr.Zone() != "" || s.EndAddr.Zone() != "" || s.StartAddr.BitLen() != s.EndAddr.BitLen() || s.StartAddr.Compare(s.EndAddr) > 0 || s.StartPort > s.EndPort {
		return fmt.Errorf("ike: invalid traffic selector range")
	}
	// ICMP encodes type/code in the port fields. For protocols without a
	// supported port interpretation, accept only the full range.
	switch s.Protocol {
	case 1, 6, 17, 33, 58, 132, 136:
	default:
		if s.StartPort != 0 || s.EndPort != 65535 {
			return fmt.Errorf("ike: protocol requires all ports")
		}
	}
	return nil
}

const maxTrafficSelectors = 64

func EncodeTrafficSelectors(selectors []TrafficSelector) ([]byte, error) {
	if len(selectors) == 0 || len(selectors) > maxTrafficSelectors {
		return nil, fmt.Errorf("ike: invalid traffic selector count")
	}
	b := []byte{byte(len(selectors)), 0, 0, 0}
	for _, s := range selectors {
		if err := s.validate(); err != nil {
			return nil, err
		}
		typ, size := byte(7), uint16(16)
		if s.StartAddr.Is6() {
			typ, size = 8, 40
		}
		b = append(b, typ, s.Protocol)
		b = binary.BigEndian.AppendUint16(b, size)
		b = binary.BigEndian.AppendUint16(b, s.StartPort)
		b = binary.BigEndian.AppendUint16(b, s.EndPort)
		b = append(b, s.StartAddr.AsSlice()...)
		b = append(b, s.EndAddr.AsSlice()...)
	}
	return b, nil
}

func DecodeTrafficSelectors(b []byte) ([]TrafficSelector, error) {
	if len(b) < 4 || b[0] == 0 || b[0] > maxTrafficSelectors {
		return nil, fmt.Errorf("ike: invalid traffic selector header")
	}
	count, rest := int(b[0]), b[4:]
	selectors := make([]TrafficSelector, 0, count)
	for i := 0; i < count; i++ {
		if len(rest) < 8 {
			return nil, fmt.Errorf("ike: truncated traffic selector")
		}
		n := int(binary.BigEndian.Uint16(rest[2:]))
		if (rest[0] != 7 || n != 16) && (rest[0] != 8 || n != 40) || n > len(rest) {
			return nil, fmt.Errorf("ike: unsupported traffic selector type or length")
		}
		addrLen := (n - 8) / 2
		start, _ := netip.AddrFromSlice(rest[8 : 8+addrLen])
		end, _ := netip.AddrFromSlice(rest[8+addrLen : n])
		s := TrafficSelector{Protocol: rest[1], StartPort: binary.BigEndian.Uint16(rest[4:]), EndPort: binary.BigEndian.Uint16(rest[6:]), StartAddr: start, EndAddr: end}
		if err := s.validate(); err != nil {
			return nil, err
		}
		selectors = append(selectors, s)
		rest = rest[n:]
	}
	if len(rest) != 0 {
		return nil, fmt.Errorf("ike: trailing traffic selector bytes")
	}
	return selectors, nil
}

// ValidateTrafficSelectorNarrowing conservatively requires each returned range
// to fit one offered range. It never merges distinct ranges to grant extra scope.
// Callers must use an authorized offer; this check cannot authorize that offer.
func ValidateTrafficSelectorNarrowing(selected, offered []TrafficSelector) error {
	if len(selected) == 0 || len(offered) == 0 || len(selected) > maxTrafficSelectors || len(offered) > maxTrafficSelectors {
		return fmt.Errorf("ike: invalid traffic selector count")
	}
	for _, s := range offered {
		if err := s.validate(); err != nil {
			return err
		}
	}
	for _, s := range selected {
		if err := s.validate(); err != nil {
			return err
		}
		contained := false
		for _, o := range offered {
			if o.StartAddr.BitLen() == s.StartAddr.BitLen() && (o.Protocol == 0 || o.Protocol == s.Protocol) && o.StartPort <= s.StartPort && o.EndPort >= s.EndPort && o.StartAddr.Compare(s.StartAddr) <= 0 && o.EndAddr.Compare(s.EndAddr) >= 0 {
				contained = true
				break
			}
		}
		if !contained {
			return fmt.Errorf("ike: traffic selector exceeds offered scope")
		}
	}
	return nil
}

type ChildKeys struct {
	// Each direction contains its 16-byte AES key followed by its 4-byte GCM salt.
	InitiatorToResponder, ResponderToInitiator []byte
}

// DeriveInitialChildKeys uses IKE_SA_INIT nonces, with no new DH exchange. It
// must not be used for a CHILD rekey with a fresh nonce or PFS requirement.
func DeriveInitialChildKeys(skD, initiatorNonce, responderNonce []byte) (ChildKeys, error) {
	if len(skD) != 32 || len(initiatorNonce) < 16 || len(initiatorNonce) > 256 || len(responderNonce) < 16 || len(responderNonce) > 256 {
		return ChildKeys{}, fmt.Errorf("ike: invalid initial CHILD key input")
	}
	seed := append(append([]byte(nil), initiatorNonce...), responderNonce...)
	material, err := PRFPlusSHA256(skD, seed, 40)
	if err != nil {
		return ChildKeys{}, err
	}
	return ChildKeys{InitiatorToResponder: material[:20:20], ResponderToInitiator: material[20:40:40]}, nil
}
