package photonwindows

import (
	"net"
	"net/netip"
)

// The serial transmit worker owns this operation and its event until exit.
// A pending send can be canceled under the socket's submission gate.
type meshPacketWriter struct {
	socket *packetSockets
	op     *udpControlWrite
}

func (s *packetSockets) newMeshPacketWriter() *meshPacketWriter {
	return &meshPacketWriter{socket: s}
}

func (w *meshPacketWriter) close() {
	if w.op != nil {
		w.op.close()
	}
}

func (w *meshPacketWriter) writeTunnel(generation uint64, packet []byte, peer netip.AddrPort, timing *fixturePacketTiming) error {
	_, err := w.write(generation, peer, packet, 0, udpWriteTiming{single: timing})
	return err
}

func (w *meshPacketWriter) writeTunnelSegments(generation uint64, peer netip.AddrPort, packet []byte, size int, traces []fixturePacketTiming) (bool, error) {
	return w.write(generation, peer, packet, size, udpWriteTiming{batch: traces})
}

func (w *meshPacketWriter) write(generation uint64, peer netip.AddrPort, packet []byte, size int, timing udpWriteTiming) (bool, error) {
	if generation == 0 || !peer.IsValid() {
		return true, net.ErrClosed
	}
	scope, err := udpControlScope(peer.Addr())
	if err != nil {
		return true, err
	}
	if w.op == nil {
		w.op, err = newUDPWrite()
		if err != nil {
			return true, err
		}
	}
	_, submitted, err := w.socket.submitUDPWrite(w.op, packet, peer, scope, generation, size, timing)
	return submitted, err
}
