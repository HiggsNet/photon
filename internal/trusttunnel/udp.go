package trusttunnel

import (
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
)

// UDPAuthority is the CONNECT authority for a datagram stream.
const UDPAuthority = "_udp2"

const (
	addressesSize = 36
	maxPayload    = 65535
)

// Datagram is a TrustTunnel UDP frame without the optional application label.
type Datagram struct {
	Source      netip.AddrPort
	Destination netip.AddrPort
	Payload     []byte
}

func ReadRequest(r io.Reader) (Datagram, error)  { return readDatagram(r, true) }
func ReadResponse(r io.Reader) (Datagram, error) { return readDatagram(r, false) }

func WriteRequest(w io.Writer, packet Datagram) error  { return writeDatagram(w, packet, true) }
func WriteResponse(w io.Writer, packet Datagram) error { return writeDatagram(w, packet, false) }

func readDatagram(r io.Reader, request bool) (Datagram, error) {
	var length [4]byte
	if _, err := io.ReadFull(r, length[:]); err != nil {
		return Datagram{}, err
	}
	size := binary.BigEndian.Uint32(length[:])
	minSize, maxSize := uint32(addressesSize), uint32(addressesSize+maxPayload)
	if request {
		minSize++
		maxSize += 1 + 255
	}
	if size < minSize || size > maxSize {
		return Datagram{}, errors.New("invalid TrustTunnel datagram length")
	}
	frame := make([]byte, size)
	if _, err := io.ReadFull(r, frame); err != nil {
		return Datagram{}, err
	}
	start := addressesSize
	if request {
		start += 1 + int(frame[addressesSize])
	}
	if start > len(frame) || len(frame)-start > maxPayload {
		return Datagram{}, errors.New("invalid TrustTunnel datagram payload")
	}
	return Datagram{
		Source:      readAddress(frame[:18]),
		Destination: readAddress(frame[18:addressesSize]),
		Payload:     frame[start:],
	}, nil
}

func writeDatagram(w io.Writer, packet Datagram, request bool) error {
	if !packet.Source.IsValid() || !packet.Destination.IsValid() || len(packet.Payload) > maxPayload {
		return errors.New("invalid TrustTunnel datagram")
	}
	start := 4 + addressesSize
	if request {
		start++ // empty application label
	}
	data := make([]byte, start+len(packet.Payload))
	binary.BigEndian.PutUint32(data[:4], uint32(len(data)-4))
	writeAddress(data[4:22], packet.Source)
	writeAddress(data[22:40], packet.Destination)
	copy(data[start:], packet.Payload)
	n, err := w.Write(data)
	if err == nil && n != len(data) {
		return io.ErrShortWrite
	}
	return err
}

func readAddress(data []byte) netip.AddrPort {
	addr := netip.AddrFrom16([16]byte(data[:16]))
	// IPv4 is zero-padded, rather than IPv4-mapped. Preserve IPv6 loopback,
	// whose bytes also form the reserved IPv4 address 0.0.0.1.
	if !addr.IsLoopback() && zeroPrefix.Contains(addr) {
		addr = netip.AddrFrom4([4]byte(data[12:16]))
	}
	return netip.AddrPortFrom(addr.Unmap(), binary.BigEndian.Uint16(data[16:18]))
}

var zeroPrefix = netip.MustParsePrefix("::/96")

func writeAddress(data []byte, addr netip.AddrPort) {
	ip := addr.Addr().Unmap()
	if ip.Is4() {
		v4 := ip.As4()
		copy(data[12:16], v4[:])
	} else {
		v6 := ip.As16()
		copy(data[:16], v6[:])
	}
	binary.BigEndian.PutUint16(data[16:18], addr.Port())
}
