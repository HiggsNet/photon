// Package babel implements bounded Babel wire formats for Photon leaf peers.
// Wire behavior follows RFC 8966, RFC 9079 and RFC 9229. Codec results are not
// authorization: the caller must bind Router IDs to currently authorized origins.
package babel

import (
	"encoding/binary"
	"errors"
	"net/netip"
)

const (
	Magic                 = 42
	Version               = 2
	Port                  = 6696
	MaxPacket             = 4096
	MaxMessages           = 256
	MetricInfinity uint16 = 65535
)
const (
	TLVPad1 uint8 = iota
	TLVPadN
	TLVAckRequest
	TLVAck
	TLVHello
	TLVIHU
	TLVRouterID
	TLVNextHop
	TLVUpdate
	TLVRouteRequest
	TLVSeqnoRequest
)
const (
	AEWildcard uint8 = iota
	AEIPv4
	AEIPv6
	AEIPv6LinkLocal
	AEIPv4ViaIPv6
)

var ErrPacket = errors.New("babel: invalid or unsupported packet")

// Message is a decoded TLV. Updates carry the effective RouterID and NextHop
// from this packet's parser state. SourcePrefix is never discarded or converted
// to a destination-only route. Wildcard represents wildcard requests/retractions.
// Ignore marks an enclosing TLV with unsupported mandatory sub-TLV semantics;
// its parser-state side effects have already occurred and it must not be used.
type Message struct {
	Type, AE                        uint8
	Seqno, Interval, Metric, Opaque uint16
	RouterID                        [8]byte
	NextHop                         netip.Addr
	Prefix, SourcePrefix            netip.Prefix
	Address                         netip.Addr // IHU target; invalid means wildcard on this point-to-point peer
	HopCount                        uint8
	Unicast, Wildcard, Ignore       bool
}

type decodeState struct {
	prefix       [5]netip.Prefix
	next4, next6 netip.Addr
	routerID     [8]byte
}

// Decode accepts one Babel UDP payload. State is per packet, never per peer.
// Trailer TLVs are bounded/validated but cannot introduce routing messages.
func Decode(packet []byte, source netip.Addr) ([]Message, error) {
	if len(packet) < 4 || len(packet) > MaxPacket || packet[0] != Magic || packet[1] != Version {
		return nil, ErrPacket
	}
	n := int(binary.BigEndian.Uint16(packet[2:4]))
	if n > len(packet)-4 {
		return nil, ErrPacket
	}
	state := decodeState{}
	if source.Is4() {
		state.next4 = source
	} else if source.Is6() && !source.Is4In6() {
		state.next6 = source
	}
	var messages []Message
	count := 0
	parse := func(body []byte, trailer bool) error {
		for len(body) > 0 {
			count++
			if count > MaxMessages {
				return ErrPacket
			}
			typ := body[0]
			body = body[1:]
			if typ == TLVPad1 {
				continue
			}
			if len(body) < 1 || int(body[0]) > len(body)-1 {
				return ErrPacket
			}
			n := int(body[0])
			value := body[1 : 1+n]
			body = body[1+n:]
			if trailer || typ == TLVPadN {
				continue
			}
			message, known, err := state.decode(typ, value)
			if err != nil {
				return err
			}
			if known {
				messages = append(messages, message)
			}
		}
		return nil
	}
	if err := parse(packet[4:4+n], false); err != nil {
		return nil, err
	}
	if err := parse(packet[4+n:], true); err != nil {
		return nil, err
	}
	return messages, nil
}

func (state *decodeState) decode(typ uint8, b []byte) (Message, bool, error) {
	m := Message{Type: typ}
	used := 0
	switch typ {
	case TLVAckRequest:
		if len(b) < 6 {
			return m, false, ErrPacket
		}
		m.Opaque = binary.BigEndian.Uint16(b[2:4])
		m.Interval = binary.BigEndian.Uint16(b[4:6])
		m.Ignore = m.Interval == 0
		used = 6
	case TLVAck:
		if len(b) < 2 {
			return m, false, ErrPacket
		}
		m.Opaque = binary.BigEndian.Uint16(b)
		used = 2
	case TLVHello:
		if len(b) < 6 {
			return m, false, ErrPacket
		}
		m.Unicast = b[0]&0x80 != 0
		m.Seqno = binary.BigEndian.Uint16(b[2:4])
		m.Interval = binary.BigEndian.Uint16(b[4:6])
		used = 6
	case TLVIHU, TLVNextHop:
		base := 2
		if typ == TLVIHU {
			base = 6
		}
		if len(b) < base {
			return m, false, ErrPacket
		}
		m.AE = b[0]
		if m.AE > AEIPv6LinkLocal || typ == TLVNextHop && m.AE == AEWildcard {
			return m, false, nil
		}
		address, n, err := decodeAddress(m.AE, b[base:])
		if err != nil {
			return m, false, err
		}
		used = base + n
		if typ == TLVIHU {
			m.Address = address
			m.Metric = binary.BigEndian.Uint16(b[2:4])
			m.Interval = binary.BigEndian.Uint16(b[4:6])
			m.Ignore = m.Interval == 0
		} else {
			m.NextHop = address
			if address.Is4() {
				state.next4 = address
			} else {
				state.next6 = address
			}
		}
	case TLVRouterID:
		if len(b) < 10 {
			return m, false, ErrPacket
		}
		copy(m.RouterID[:], b[2:10])
		state.routerID = m.RouterID
		used = 10
		if !validRouterID(m.RouterID) {
			m.Ignore = true
		}
	case TLVUpdate:
		if len(b) < 10 {
			return m, false, ErrPacket
		}
		m.AE = b[0]
		flags, plen, omitted := b[1], int(b[2]), int(b[3])
		m.Interval = binary.BigEndian.Uint16(b[4:6])
		m.Seqno = binary.BigEndian.Uint16(b[6:8])
		m.Metric = binary.BigEndian.Uint16(b[8:10])
		if m.AE > AEIPv4ViaIPv6 {
			return m, false, nil
		}
		if m.AE == AEWildcard {
			m.Wildcard = true
			used = 10
			if plen != 0 || omitted != 0 || m.Metric != MetricInfinity {
				m.Ignore = true
			}
		} else {
			prefix, n, err := decodePrefix(m.AE, plen, omitted, b[10:], state.prefix[m.AE])
			if err != nil {
				return m, false, err
			}
			m.Prefix = prefix
			used = 10 + n
			if flags&0x80 != 0 {
				state.prefix[m.AE] = prefix
			}
			if flags&0x40 != 0 {
				raw := prefix.Addr().AsSlice()
				state.routerID = [8]byte{}
				if len(raw) >= 8 {
					copy(state.routerID[:], raw[len(raw)-8:])
				} else {
					copy(state.routerID[8-len(raw):], raw)
				}
			}
			m.RouterID = state.routerID
			m.NextHop = state.next6
			if m.AE == AEIPv4 {
				m.NextHop = state.next4
			}
			if m.Metric != MetricInfinity && (!validRouterID(m.RouterID) || !m.NextHop.IsValid()) {
				m.Ignore = true
			}
		}
		if m.Interval == 0 {
			m.Ignore = true
		}
	case TLVRouteRequest, TLVSeqnoRequest:
		base := 2
		if typ == TLVSeqnoRequest {
			base = 14
		}
		if len(b) < base {
			return m, false, ErrPacket
		}
		m.AE = b[0]
		if m.AE > AEIPv4ViaIPv6 {
			return m, false, nil
		}
		if m.AE == AEWildcard {
			m.Wildcard = true
			used = base
			if b[1] != 0 || typ == TLVSeqnoRequest {
				m.Ignore = true
			}
		} else {
			prefix, n, err := decodePrefix(m.AE, int(b[1]), 0, b[base:], netip.Prefix{})
			if err != nil {
				return m, false, err
			}
			m.Prefix = prefix
			used = base + n
		}
		if typ == TLVSeqnoRequest {
			m.Seqno = binary.BigEndian.Uint16(b[2:4])
			m.HopCount = b[4]
			copy(m.RouterID[:], b[6:14])
			if !validRouterID(m.RouterID) || m.HopCount == 0 {
				m.Ignore = true
			}
		}
	default:
		return m, false, nil
	}
	source, ignore := decodeSubs(b[used:], m.AE, typ == TLVUpdate || typ == TLVRouteRequest || typ == TLVSeqnoRequest)
	m.SourcePrefix = source
	m.Ignore = m.Ignore || ignore
	return m, true, nil
}

func decodeSubs(b []byte, ae uint8, allowSource bool) (netip.Prefix, bool) {
	var source netip.Prefix
	ignore := false
	for len(b) > 0 {
		typ := b[0]
		b = b[1:]
		if typ == 0 {
			continue
		}
		if len(b) < 1 || int(b[0]) > len(b)-1 {
			return netip.Prefix{}, true
		}
		n := int(b[0])
		value := b[1 : 1+n]
		b = b[1+n:]
		if typ < 128 {
			continue
		}
		if typ != 128 || !allowSource || source.IsValid() || len(value) < 1 || value[0] == 0 || ae == AEWildcard {
			ignore = true
			continue
		}
		var err error
		source, _, err = decodePrefix(ae, int(value[0]), 0, value[1:], netip.Prefix{})
		if err != nil {
			ignore = true
		}
	}
	return source, ignore
}

func decodeAddress(ae uint8, b []byte) (netip.Addr, int, error) {
	switch ae {
	case AEWildcard:
		return netip.Addr{}, 0, nil
	case AEIPv4:
		if len(b) >= 4 {
			return netip.AddrFrom4([4]byte(b[:4])), 4, nil
		}
	case AEIPv6:
		if len(b) >= 16 {
			return netip.AddrFrom16([16]byte(b[:16])), 16, nil
		}
	case AEIPv6LinkLocal:
		if len(b) >= 8 {
			var raw [16]byte
			raw[0], raw[1] = 0xfe, 0x80
			copy(raw[8:], b[:8])
			return netip.AddrFrom16(raw), 8, nil
		}
	}
	return netip.Addr{}, 0, ErrPacket
}

func decodePrefix(ae uint8, plen, omitted int, b []byte, previous netip.Prefix) (netip.Prefix, int, error) {
	bits, skip := 128, 0
	if ae == AEIPv4 || ae == AEIPv4ViaIPv6 {
		bits = 32
	} else if ae == AEIPv6LinkLocal {
		skip = 8
		if omitted != 0 || plen < 64 {
			return netip.Prefix{}, 0, ErrPacket
		}
	} else if ae != AEIPv6 {
		return netip.Prefix{}, 0, ErrPacket
	}
	if plen < 0 || plen > bits || omitted < 0 {
		return netip.Prefix{}, 0, ErrPacket
	}
	n := (plen+7)/8 - skip
	if omitted > n || n-omitted > len(b) || omitted > 0 && !previous.IsValid() {
		return netip.Prefix{}, 0, ErrPacket
	}
	var raw [16]byte
	if skip != 0 {
		raw[0], raw[1] = 0xfe, 0x80
	}
	if omitted > 0 {
		copy(raw[:omitted], previous.Addr().AsSlice()[:omitted])
	}
	copy(raw[skip+omitted:], b[:n-omitted])
	address := netip.AddrFrom16(raw)
	if bits == 32 {
		address = netip.AddrFrom4([4]byte(raw[:4]))
	}
	return netip.PrefixFrom(address, plen).Masked(), n - omitted, nil
}

func validRouterID(id [8]byte) bool {
	return id != [8]byte{} && id != [8]byte{255, 255, 255, 255, 255, 255, 255, 255}
}

// Encode emits uncompressed messages. Every finite Update establishes its own
// router ID and next hop, so a caller cannot accidentally reuse a prior origin.
func Encode(messages []Message) ([]byte, error) {
	if len(messages) > MaxMessages {
		return nil, ErrPacket
	}
	packet := []byte{Magic, Version, 0, 0}
	count := 0
	appendTLV := func(typ uint8, b []byte) error {
		count++
		if count > MaxMessages || len(b) > 255 || len(packet)+2+len(b) > MaxPacket {
			return ErrPacket
		}
		packet = append(packet, typ, byte(len(b)))
		packet = append(packet, b...)
		return nil
	}
	for _, m := range messages {
		if m.Ignore {
			return nil, ErrPacket
		}
		var b []byte
		switch m.Type {
		case TLVAckRequest:
			if m.Interval == 0 {
				return nil, ErrPacket
			}
			b = make([]byte, 6)
			binary.BigEndian.PutUint16(b[2:4], m.Opaque)
			binary.BigEndian.PutUint16(b[4:6], m.Interval)
		case TLVAck:
			b = binary.BigEndian.AppendUint16(nil, m.Opaque)
		case TLVHello:
			b = make([]byte, 6)
			if m.Unicast {
				b[0] = 0x80
			}
			binary.BigEndian.PutUint16(b[2:4], m.Seqno)
			binary.BigEndian.PutUint16(b[4:6], m.Interval)
		case TLVIHU, TLVNextHop:
			address := m.Address
			if m.Type == TLVNextHop {
				address = m.NextHop
				if !address.IsValid() {
					return nil, ErrPacket
				}
			}
			ae, raw, err := encodeAddress(address)
			if err != nil {
				return nil, err
			}
			b = []byte{ae, 0}
			if m.Type == TLVIHU {
				if m.Interval == 0 {
					return nil, ErrPacket
				}
				b = binary.BigEndian.AppendUint16(b, m.Metric)
				b = binary.BigEndian.AppendUint16(b, m.Interval)
			}
			b = append(b, raw...)
		case TLVRouterID:
			if !validRouterID(m.RouterID) {
				return nil, ErrPacket
			}
			b = append([]byte{0, 0}, m.RouterID[:]...)
		case TLVUpdate, TLVRouteRequest, TLVSeqnoRequest:
			ae := m.AE
			if m.Wildcard {
				if m.Prefix.IsValid() || m.SourcePrefix.IsValid() || m.Type == TLVSeqnoRequest || m.Type == TLVUpdate && m.Metric != MetricInfinity {
					return nil, ErrPacket
				}
				ae = AEWildcard
			} else {
				if !m.Prefix.IsValid() || m.Prefix.Addr().Is4In6() || m.Prefix != m.Prefix.Masked() {
					return nil, ErrPacket
				}
				if ae == 0 {
					ae = AEIPv6
					if m.Prefix.Addr().Is4() {
						ae = AEIPv4
						if m.Type == TLVUpdate && m.NextHop.Is6() {
							ae = AEIPv4ViaIPv6
						}
					}
				}
				if (ae != AEIPv4 && ae != AEIPv6 && ae != AEIPv4ViaIPv6) || (m.Prefix.Addr().Is4() != (ae == AEIPv4 || ae == AEIPv4ViaIPv6)) {
					return nil, ErrPacket
				}
			}
			plen := 0
			var prefix []byte
			if !m.Wildcard {
				plen = m.Prefix.Bits()
				prefix = m.Prefix.Addr().AsSlice()[:(plen+7)/8]
			}
			if m.Type == TLVUpdate {
				if m.Interval == 0 {
					return nil, ErrPacket
				}
				if m.Metric != MetricInfinity {
					if !validRouterID(m.RouterID) || !m.NextHop.IsValid() {
						return nil, ErrPacket
					}
					if ae == AEIPv4 && !m.NextHop.Is4() || (ae == AEIPv6 || ae == AEIPv4ViaIPv6) && !m.NextHop.Is6() {
						return nil, ErrPacket
					}
					if err := appendTLV(TLVRouterID, append([]byte{0, 0}, m.RouterID[:]...)); err != nil {
						return nil, err
					}
					hopAE, raw, err := encodeAddress(m.NextHop)
					if err != nil {
						return nil, err
					}
					if err := appendTLV(TLVNextHop, append([]byte{hopAE, 0}, raw...)); err != nil {
						return nil, err
					}
				}
				b = []byte{ae, 0x80, byte(plen), 0}
				b = binary.BigEndian.AppendUint16(b, m.Interval)
				b = binary.BigEndian.AppendUint16(b, m.Seqno)
				b = binary.BigEndian.AppendUint16(b, m.Metric)
			} else {
				b = []byte{ae, byte(plen)}
				if m.Type == TLVSeqnoRequest {
					if !validRouterID(m.RouterID) || m.HopCount == 0 {
						return nil, ErrPacket
					}
					b = binary.BigEndian.AppendUint16(b, m.Seqno)
					b = append(b, m.HopCount, 0)
					b = append(b, m.RouterID[:]...)
				}
			}
			b = append(b, prefix...)
			if m.SourcePrefix.IsValid() {
				if m.SourcePrefix.Bits() == 0 || m.SourcePrefix.Addr().Is4In6() || m.SourcePrefix != m.SourcePrefix.Masked() || m.SourcePrefix.Addr().BitLen() != m.Prefix.Addr().BitLen() {
					return nil, ErrPacket
				}
				raw := m.SourcePrefix.Addr().AsSlice()[:(m.SourcePrefix.Bits()+7)/8]
				b = append(b, 128, byte(1+len(raw)), byte(m.SourcePrefix.Bits()))
				b = append(b, raw...)
			}
		default:
			return nil, ErrPacket
		}
		if err := appendTLV(m.Type, b); err != nil {
			return nil, err
		}
	}
	binary.BigEndian.PutUint16(packet[2:4], uint16(len(packet)-4))
	return packet, nil
}

func encodeAddress(address netip.Addr) (uint8, []byte, error) {
	if !address.IsValid() {
		return AEWildcard, nil, nil
	}
	if address.Zone() != "" || address.Is4In6() {
		return 0, nil, ErrPacket
	}
	if address.Is4() {
		return AEIPv4, address.AsSlice(), nil
	}
	if address.Is6() {
		raw := address.As16()
		if address.IsLinkLocalUnicast() && raw[0] == 0xfe && raw[1] == 0x80 && raw[2] == 0 && raw[3] == 0 && raw[4] == 0 && raw[5] == 0 && raw[6] == 0 && raw[7] == 0 {
			return AEIPv6LinkLocal, raw[8:], nil
		}
		return AEIPv6, raw[:], nil
	}
	return 0, nil, ErrPacket
}
