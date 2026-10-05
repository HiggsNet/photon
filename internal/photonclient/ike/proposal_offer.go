package ike

import (
	"bytes"
	"encoding/binary"
	"fmt"
)

// Offers can contain alternatives; selections cannot. Keep this parser separate
// from the strict response validators so an accepted offer never broadens the
// fixed suite that our own requests advertise.
type offeredTransform struct {
	kind       uint8
	id         uint16
	attributes []byte
}
type offeredProposal struct {
	number, protocol uint8
	spi              []byte
	transforms       []offeredTransform
}

func decodeProposalOffers(data []byte) ([]offeredProposal, error) {
	var proposals []offeredProposal
	previous := uint8(0)
	for len(data) > 0 {
		if len(proposals) >= 64 || len(data) < 8 {
			return nil, fmt.Errorf("ike: too many or truncated offered proposals")
		}
		size := int(binary.BigEndian.Uint16(data[2:]))
		spiSize := int(data[6])
		count := int(data[7])
		if size < 8+spiSize || size > len(data) || data[4] <= previous || count == 0 || count > 64 {
			return nil, fmt.Errorf("ike: malformed offered proposal")
		}
		more := byte(2)
		if size == len(data) {
			more = 0
		}
		if data[0] != more {
			return nil, fmt.Errorf("ike: offered proposal chain mismatch")
		}
		p := offeredProposal{number: data[4], protocol: data[5], spi: bytes.Clone(data[8 : 8+spiSize])}
		rest := data[8+spiSize : size]
		for n := 0; n < count; n++ {
			if len(rest) < 8 {
				return nil, fmt.Errorf("ike: truncated offered transform")
			}
			length := int(binary.BigEndian.Uint16(rest[2:]))
			more := byte(3)
			if n == count-1 {
				more = 0
			}
			if length < 8 || length > len(rest) || rest[0] != more {
				return nil, fmt.Errorf("ike: malformed offered transform")
			}
			attrs := rest[8:length]
			for remaining := attrs; len(remaining) > 0; {
				if len(remaining) < 4 {
					return nil, fmt.Errorf("ike: truncated transform attribute")
				}
				amount := 4
				if remaining[0]&0x80 == 0 {
					amount += int(binary.BigEndian.Uint16(remaining[2:]))
				}
				if amount > len(remaining) {
					return nil, fmt.Errorf("ike: invalid transform attribute length")
				}
				remaining = remaining[amount:]
			}
			p.transforms = append(p.transforms, offeredTransform{kind: rest[4], id: binary.BigEndian.Uint16(rest[6:]), attributes: bytes.Clone(attrs)})
			rest = rest[length:]
		}
		if len(rest) != 0 {
			return nil, fmt.Errorf("ike: offered transform count mismatch")
		}
		proposals = append(proposals, p)
		previous = p.number
		data = data[size:]
	}
	if len(proposals) == 0 {
		return nil, fmt.Errorf("ike: empty proposal offer")
	}
	return proposals, nil
}

func (p offeredProposal) has(kind uint8, id uint16, attrs []byte) bool {
	for _, t := range p.transforms {
		if t.kind == kind && t.id == id && bytes.Equal(t.attributes, attrs) {
			return true
		}
	}
	return false
}
func (p offeredProposal) hasKind(kind uint8) bool {
	for _, t := range p.transforms {
		if t.kind == kind {
			return true
		}
	}
	return false
}
func (p offeredProposal) onlyKinds(kinds ...uint8) bool {
	for _, t := range p.transforms {
		found := false
		for _, k := range kinds {
			found = found || t.kind == k
		}
		if !found {
			return false
		}
	}
	return true
}

func selectChildOffer(data []byte, keGroup uint16) (uint32, uint16, uint8, error) {
	proposals, err := decodeProposalOffers(data)
	if err != nil {
		return 0, 0, 0, err
	}
	for _, p := range proposals {
		if p.protocol != 3 || len(p.spi) != 4 || !p.onlyKinds(1, 4, 5) || !p.has(1, 20, []byte{0x80, 14, 0, 128}) || !p.has(5, 0, nil) {
			continue
		}
		spi := binary.BigEndian.Uint32(p.spi)
		if spi < 256 {
			continue
		}
		hasNone := !p.hasKind(4) || p.has(4, 0, nil)
		group := uint16(0)
		if !(keGroup == 0 && hasNone) {
			if p.has(4, GroupP256, nil) {
				group = GroupP256
			} else if !hasNone {
				continue
			}
		}
		return spi, group, p.number, nil
	}
	return 0, 0, 0, fmt.Errorf("ike: no supported ESP offer")
}

func selectIKERekeyOffer(data []byte) (uint64, uint8, error) {
	proposals, err := decodeProposalOffers(data)
	if err != nil {
		return 0, 0, err
	}
	for _, p := range proposals {
		if p.protocol != 1 || len(p.spi) != 8 || !p.onlyKinds(1, 2, 3, 4) || !p.has(1, 12, []byte{0x80, 14, 0, 128}) || !p.has(2, 5, nil) || !p.has(3, 12, nil) || !p.has(4, GroupP256, nil) {
			continue
		}
		spi := binary.BigEndian.Uint64(p.spi)
		if spi != 0 {
			return spi, p.number, nil
		}
	}
	return 0, 0, fmt.Errorf("ike: no supported IKE rekey offer")
}

func rawRequestKE(b []byte) (uint16, []byte, error) {
	if len(b) < 4 {
		return 0, nil, fmt.Errorf("ike: truncated KE payload")
	}
	group := binary.BigEndian.Uint16(b)
	if group == 0 || len(b) == 4 {
		return 0, nil, fmt.Errorf("ike: empty or NONE key exchange")
	}
	if group == GroupP256 {
		_, key, err := DecodeKE(b)
		return group, key, err
	}
	return group, bytes.Clone(b[4:]), nil
}

func (i *Initiator) replyInvalidKE(m *ExchangeMessage, h Header, expected uint16) ([]byte, error) {
	n, _ := EncodeNotify(Notify{Type: 17, Data: binary.BigEndian.AppendUint16(nil, expected)})
	return i.replyExchange(m.identity, h, []Payload{{Type: PayloadNotify, Data: n}})
}
