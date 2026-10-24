package photonwindows

import "net/netip"

type tunnelEndpoints struct{ ike, natt netip.AddrPort }

// Each peer owns a reservation. Retiring one peer cannot invalidate another
// peer's queued packets or writes. Rebind still invalidates every reservation.
func (s *packetSockets) reserveTunnel(ikePeer, nattPeer netip.AddrPort) uint64 {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.tunnelGeneration++
	if !s.closed {
		s.addTunnelLocked(s.tunnelGeneration, ikePeer, nattPeer)
	}
	return s.tunnelGeneration
}

func (s *packetSockets) addTunnelLocked(generation uint64, ikePeer, nattPeer netip.AddrPort) {
	if s.tunnels == nil {
		s.tunnels = make(map[uint64]tunnelEndpoints)
	}
	if s.tunnelPeers == nil {
		s.tunnelPeers = make(map[netip.AddrPort]map[uint64]bool)
	}
	s.tunnels[generation] = tunnelEndpoints{ikePeer, nattPeer}
	for _, peer := range []netip.AddrPort{ikePeer, nattPeer} {
		if !peer.IsValid() {
			continue
		}
		if s.tunnelPeers[peer] == nil {
			s.tunnelPeers[peer] = make(map[uint64]bool)
		}
		s.tunnelPeers[peer][generation] = true
	}
}

func (s *packetSockets) releaseTunnel(generation uint64) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	endpoints := s.tunnels[generation]
	delete(s.tunnels, generation)
	for _, peer := range []netip.AddrPort{endpoints.ike, endpoints.natt} {
		delete(s.tunnelPeers[peer], generation)
		if len(s.tunnelPeers[peer]) == 0 {
			delete(s.tunnelPeers, peer)
		}
	}
}
