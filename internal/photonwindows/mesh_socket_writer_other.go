//go:build !windows

package photonwindows

import "net/netip"

type meshPacketWriter struct{ socket *packetSockets }

func (s *packetSockets) newMeshPacketWriter() *meshPacketWriter {
	return &meshPacketWriter{socket: s}
}

func (*meshPacketWriter) close() {}

func (w *meshPacketWriter) writeTunnel(generation uint64, packet []byte, peer netip.AddrPort, timing *fixturePacketTiming) error {
	return w.socket.writeTunnel(generation, packet, peer, timing)
}

func (w *meshPacketWriter) writeTunnelSegments(generation uint64, peer netip.AddrPort, packet []byte, size int, traces []fixturePacketTiming) (bool, error) {
	return w.socket.writeTunnelSegments(generation, peer, packet, size, traces)
}

func (s *packetSockets) writeTunnel(generation uint64, packet []byte, peer netip.AddrPort, timing *fixturePacketTiming) error {
	return s.writeTunnelDefault(generation, packet, peer, timing)
}
