package ike

import (
	"bytes"
	"crypto/sha1" // RFC 7296 NAT detection, not authentication.
	"encoding/binary"
	"fmt"
	"net/netip"
)

const (
	NotifyNATDetectionSource      uint16 = 16388
	NotifyNATDetectionDestination uint16 = 16389
)

// NATStatus describes the unauthenticated SA_INIT observation. Checked is false
// if endpoints were not supplied or the peer did not send NAT detection.
// It grants no permission to accept traffic or change a peer address.
type NATStatus struct{ Checked, Local, Remote bool }

func (n NATStatus) Required() bool { return n.Checked && (n.Local || n.Remote) }

func validNATEndpoint(a netip.AddrPort) bool {
	address := a.Addr().Unmap()
	return a.IsValid() && a.Port() != 0 && !address.IsUnspecified() && !address.IsMulticast()
}

// NATDetectionHash implements RFC 7296 section 2.23. IPv4 mapped addresses use
// their four wire octets; an IPv6 scope zone is not part of the IP header.
func NATDetectionHash(spiI, spiR uint64, endpoint netip.AddrPort) ([]byte, error) {
	if !validNATEndpoint(endpoint) {
		return nil, fmt.Errorf("ike: invalid NAT detection endpoint")
	}
	var prefix [16]byte
	binary.BigEndian.PutUint64(prefix[:8], spiI)
	binary.BigEndian.PutUint64(prefix[8:], spiR)
	h := sha1.New()
	_, _ = h.Write(prefix[:])
	_, _ = h.Write(endpoint.Addr().Unmap().AsSlice())
	var port [2]byte
	binary.BigEndian.PutUint16(port[:], endpoint.Port())
	_, _ = h.Write(port[:])
	return h.Sum(nil), nil
}

func natPayload(kind uint16, spiI, spiR uint64, endpoint netip.AddrPort) Payload {
	hash, _ := NATDetectionHash(spiI, spiR, endpoint) // Endpoint validated by constructor.
	body, _ := EncodeNotify(Notify{Type: kind, Data: hash})
	return Payload{Type: PayloadNotify, Data: body}
}

func checkNAT(ps []Payload, h Header, local, remote netip.AddrPort) (NATStatus, error) {
	var sources [][]byte
	var destination []byte
	for _, p := range ps {
		if p.Type != PayloadNotify {
			continue
		}
		n, err := DecodeNotify(p.Data)
		if err != nil {
			return NATStatus{}, err
		}
		if n.Type != NotifyNATDetectionSource && n.Type != NotifyNATDetectionDestination {
			continue
		}
		// RFC 7296 section 3.10: with an empty SPI the protocol field is ignored.
		if len(n.SPI) != 0 || len(n.Data) != sha1.Size {
			return NATStatus{}, fmt.Errorf("ike: malformed NAT detection notification")
		}
		if n.Type == NotifyNATDetectionSource {
			sources = append(sources, n.Data)
		} else {
			if destination != nil {
				return NATStatus{}, fmt.Errorf("ike: duplicate NAT destination notification")
			}
			destination = n.Data
		}
	}
	if len(sources) == 0 && destination == nil {
		return NATStatus{}, nil
	}
	if len(sources) == 0 || destination == nil {
		return NATStatus{}, fmt.Errorf("ike: incomplete NAT detection notifications")
	}
	if !local.IsValid() {
		return NATStatus{}, nil
	}
	wantSource, _ := NATDetectionHash(h.InitiatorSPI, h.ResponderSPI, remote)
	wantDestination, _ := NATDetectionHash(h.InitiatorSPI, h.ResponderSPI, local)
	status := NATStatus{Checked: true, Local: !bytes.Equal(destination, wantDestination), Remote: true}
	for _, source := range sources {
		if bytes.Equal(source, wantSource) {
			status.Remote = false
		}
	}
	return status, nil
}

type NATDatagramKind uint8

const (
	NATDatagramIKE NATDatagramKind = iota + 1
	NATDatagramESP
	NATDatagramKeepalive
)

// EncapsulateIKE prepends the RFC 7296 non-ESP marker to a detached copy. The
// marker must never become part of the IKE authentication transcript.
func EncapsulateIKE(packet []byte) ([]byte, error) {
	if _, _, err := DecodeHeader(packet); err != nil {
		return nil, err
	}
	if len(packet) > MaxMessageSize-4 {
		return nil, fmt.Errorf("ike: NAT datagram too large")
	}
	return append(make([]byte, 4), packet...), nil
}

// ParseNATDatagram demultiplexes UDP/4500 framing only, without authenticating
// either IKE or ESP. The returned bytes alias packet. ESP validation, peer
// matching and keepalive scheduling remain the caller's responsibility.
func ParseNATDatagram(packet []byte) (NATDatagramKind, []byte, error) {
	if len(packet) > MaxMessageSize {
		return 0, nil, fmt.Errorf("ike: NAT datagram too large")
	}
	if len(packet) == 1 && packet[0] == 0xff {
		return NATDatagramKeepalive, nil, nil
	}
	if len(packet) < 4 {
		return 0, nil, fmt.Errorf("ike: truncated NAT datagram")
	}
	if binary.BigEndian.Uint32(packet[:4]) == 0 {
		if _, _, err := DecodeHeader(packet[4:]); err != nil {
			return 0, nil, err
		}
		return NATDatagramIKE, packet[4:], nil
	}
	if len(packet) < 8 {
		return 0, nil, fmt.Errorf("ike: truncated ESP header")
	}
	return NATDatagramESP, packet, nil
}
