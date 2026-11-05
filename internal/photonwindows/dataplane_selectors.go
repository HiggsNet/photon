package photonwindows

import (
	"encoding/binary"
	"net/netip"

	"github.com/HiggsNet/photon/internal/photonclient/esp"
	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

type selectorFamilies uint8

const (
	selectorIPv4 selectorFamilies = 1 << iota
	selectorIPv6
)

// Compile only explicit full-family selectors. Other ranges and any
// protocol/port-specific selectors stay on the per-flow matcher.
func unrestrictedSelectorFamilies(selectors []ike.TrafficSelector) selectorFamilies {
	var families selectorFamilies
	for _, selector := range selectors {
		if selector.Protocol != 0 || selector.StartPort != 0 || selector.EndPort != 65535 {
			continue
		}
		switch selector.StartAddr {
		case netip.IPv4Unspecified():
			if selector.EndAddr == netip.MustParseAddr("255.255.255.255") {
				families |= selectorIPv4
			}
		case netip.IPv6Unspecified():
			if selector.EndAddr == netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff") {
				families |= selectorIPv6
			}
		}
	}
	return families
}

type dataplaneFlow struct {
	source, destination         netip.Addr
	sourcePort, destinationPort uint16
	protocol                    byte
	hasPorts                    bool
}

// Unsupported upper-layer headers fail closed for protocol/port-specific TS.
func parseDataplaneFlow(packet []byte) (dataplaneFlow, bool) {
	if len(packet) < 20 || len(packet) > esp.MaxInnerPacket {
		return dataplaneFlow{}, false
	}
	var source, destination netip.Addr
	var protocol byte
	var offset int
	fragment := false
	switch packet[0] >> 4 {
	case 4:
		offset = int(packet[0]&15) * 4
		if offset < 20 || offset > len(packet) || int(binary.BigEndian.Uint16(packet[2:4])) != len(packet) {
			return dataplaneFlow{}, false
		}
		source = netip.AddrFrom4([4]byte(packet[12:16]))
		destination = netip.AddrFrom4([4]byte(packet[16:20]))
		protocol = packet[9]
		fragment = binary.BigEndian.Uint16(packet[6:8])&0x3fff != 0
	case 6:
		if len(packet) < 40 || int(binary.BigEndian.Uint16(packet[4:6]))+40 != len(packet) {
			return dataplaneFlow{}, false
		}
		source = netip.AddrFrom16([16]byte(packet[8:24]))
		destination = netip.AddrFrom16([16]byte(packet[24:40]))
		protocol, offset = packet[6], 40
	default:
		return dataplaneFlow{}, false
	}
	var sourcePort, destinationPort uint16
	hasPorts := false
	if !fragment {
		switch protocol {
		case 6, 17, 33, 132, 136:
			if len(packet)-offset >= 4 {
				sourcePort, destinationPort = binary.BigEndian.Uint16(packet[offset:]), binary.BigEndian.Uint16(packet[offset+2:])
				hasPorts = true
			}
		case 1, 58:
			if len(packet)-offset >= 2 {
				sourcePort = binary.BigEndian.Uint16(packet[offset:])
				destinationPort, hasPorts = sourcePort, true
			}
		}
	}
	return dataplaneFlow{source, destination, sourcePort, destinationPort, protocol, hasPorts}, true
}

// matches enforces negotiated selectors separately from Photon route policy.
func (flow dataplaneFlow) matches(sa *dataplaneSA, outbound bool) bool {
	if sa.unrestrictedFamilies != 0 {
		// Parsing has already validated the header and built both addresses
		// from the same family. Both directions must cover that entire family.
		family := selectorIPv6
		if flow.source.Is4() {
			family = selectorIPv4
		}
		if sa.unrestrictedFamilies&family != 0 {
			return true
		}
	}
	local, remote := sa.local, sa.remote
	if !outbound {
		local, remote = remote, local
	}
	return dataplaneSelectorMatch(local, flow.source, flow.protocol, flow.sourcePort, flow.hasPorts) &&
		dataplaneSelectorMatch(remote, flow.destination, flow.protocol, flow.destinationPort, flow.hasPorts)
}

func dataplaneSelectors(sa *dataplaneSA, packet []byte, outbound bool) bool {
	flow, ok := parseDataplaneFlow(packet)
	return ok && flow.matches(sa, outbound)
}

func dataplaneSelectorMatch(selectors []ike.TrafficSelector, address netip.Addr, protocol byte, port uint16, hasPorts bool) bool {
	for _, selector := range selectors {
		if address.BitLen() != selector.StartAddr.BitLen() || address.Compare(selector.StartAddr) < 0 || address.Compare(selector.EndAddr) > 0 || (selector.Protocol != 0 && selector.Protocol != protocol) {
			continue
		}
		if selector.StartPort == 0 && selector.EndPort == 65535 {
			return true
		}
		if hasPorts && port >= selector.StartPort && port <= selector.EndPort {
			return true
		}
	}
	return false
}
