package babel

import (
	"bytes"
	"encoding/binary"
	"net/netip"
)

var Multicast = netip.MustParseAddr("ff02::1:6")

// BuildPacket constructs the link-local IPv6/UDP control packet carried inside
// one authenticated peer's ESP SA. It requires no OS multicast membership.
func BuildPacket(source, destination netip.Addr, payload []byte) ([]byte, error) {
	if !linkLocal(source) || !(linkLocal(destination) || destination == Multicast) || len(payload) < 4 || len(payload) > MaxPacket {
		return nil, ErrPacket
	}
	packet := make([]byte, 48+len(payload))
	packet[0], packet[6], packet[7] = 0x60, 17, 1
	binary.BigEndian.PutUint16(packet[4:6], uint16(len(packet)-40))
	copy(packet[8:24], source.AsSlice())
	copy(packet[24:40], destination.AsSlice())
	udp := packet[40:]
	binary.BigEndian.PutUint16(udp[:2], Port)
	binary.BigEndian.PutUint16(udp[2:4], Port)
	binary.BigEndian.PutUint16(udp[4:6], uint16(len(udp)))
	copy(udp[8:], payload)
	checksum := udpChecksum(source, destination, udp)
	if checksum == 0 {
		checksum = 65535
	}
	binary.BigEndian.PutUint16(udp[6:8], checksum)
	return packet, nil
}

// ParsePacket returns detached payload storage only for checked Babel framing.
// It does not authorize source/router identity; the current authenticated SA
// and origin policy remain required. Extension headers and fragmentation are
// not supported on this point-to-point control channel.
func ParsePacket(packet []byte, local netip.Addr) (netip.Addr, []byte, error) {
	if !linkLocal(local) || len(packet) < 52 || len(packet) > 48+MaxPacket || packet[0]>>4 != 6 || packet[6] != 17 || int(binary.BigEndian.Uint16(packet[4:6])) != len(packet)-40 {
		return netip.Addr{}, nil, ErrPacket
	}
	source := netip.AddrFrom16([16]byte(packet[8:24]))
	destination := netip.AddrFrom16([16]byte(packet[24:40]))
	if !linkLocal(source) || (destination != local && destination != Multicast) {
		return netip.Addr{}, nil, ErrPacket
	}
	udp := packet[40:]
	if binary.BigEndian.Uint16(udp[:2]) != Port || binary.BigEndian.Uint16(udp[2:4]) != Port || int(binary.BigEndian.Uint16(udp[4:6])) != len(udp) || binary.BigEndian.Uint16(udp[6:8]) == 0 || udpChecksum(source, destination, udp) != 0 {
		return netip.Addr{}, nil, ErrPacket
	}
	return source, bytes.Clone(udp[8:]), nil
}

func linkLocal(address netip.Addr) bool {
	return address.Is6() && !address.Is4In6() && address.Zone() == "" && address.IsLinkLocalUnicast()
}

func udpChecksum(source, destination netip.Addr, udp []byte) uint16 {
	var sum uint32
	add := func(b []byte) {
		for len(b) >= 2 {
			sum += uint32(binary.BigEndian.Uint16(b))
			b = b[2:]
		}
		if len(b) == 1 {
			sum += uint32(b[0]) << 8
		}
	}
	add(source.AsSlice())
	add(destination.AsSlice())
	sum += uint32(len(udp)) + 17
	add(udp)
	for sum>>16 != 0 {
		sum = (sum & 65535) + (sum >> 16)
	}
	return ^uint16(sum)
}
