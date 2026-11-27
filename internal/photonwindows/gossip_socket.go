package photonwindows

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

// packetSockets shares one UDP endpoint between Gossip and independently reserved tunnels,
// keeping receive and accept loops alive across a local socket replacement.
// It owns no protocol state, workers or database handles.
// A failed replacement leaves both protocols unavailable until the next retry.
type packetSockets struct {
	// Replacement and close own the old descriptors through completion.
	// Neither data path lock is held across close or bind.
	replaceMu sync.Mutex
	// Every mutation of udp, closed, tunnelGeneration and reservations
	// holds writeMu then mu. Either lock protects reads of those fields. The
	// Windows overlapped path holds writeMu only through submission, and the
	// reader uses mu independently. Reader metadata also uses mu.
	udpSegmentationDisabled atomic.Bool            // Capability is scoped to the current socket.
	outboundRoutes          *outboundRouteResolver // Configured before starting the daemon workers.
	writeMu                 sync.Mutex
	mu                      sync.Mutex
	udp                     *net.UDPConn
	tcp                     net.Listener
	address                 string
	changed                 chan struct{}
	failed                  chan struct{}
	closed                  bool
	readDeadline            time.Time
	tunnelGeneration        uint64
	tunnels                 map[uint64]tunnelEndpoints
	tunnelPeers             map[netip.AddrPort]map[uint64]bool
	controlWrites           map[*udpControlWrite]struct{} // Windows overlapped sends, guarded by writeMu.
	ikePackets              chan ikeDatagram
	espPackets              chan tunnelDatagram
	ikeTrace                *ikeTrace // Set before starting the reader.
	ikeIngressDrops         atomic.Uint64
}

// These are bounded ingress queues, not protocol workers. The GossipDriver's
// sole reader performs the demux; Daemon remains the tunnel lifecycle owner.
type tunnelDatagram struct {
	timing     fixturePacketTiming
	generation uint64
	peer       netip.AddrPort
	packet     []byte
}

type ikeDatagram struct {
	tunnelDatagram
	trace *ikeTraceDatagram
}

func openPacketSockets(ctx context.Context, address string) (*packetSockets, error) {
	s := &packetSockets{address: address, changed: make(chan struct{}), failed: make(chan struct{}, 1), ikePackets: make(chan ikeDatagram, 16), espPackets: make(chan tunnelDatagram, 64)}
	if err := s.Rebind(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Rebind closes the old generation before binding the same local endpoint.
// Detach first so readers and socket state queries can continue while the
// old descriptors wait for outstanding I/O to finish.
func (s *packetSockets) Rebind(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	s.replaceMu.Lock()
	defer s.replaceMu.Unlock()
	s.outboundRoutes.invalidate()
	s.writeMu.Lock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.writeMu.Unlock()
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		s.mu.Unlock()
		s.writeMu.Unlock()
		return err
	}
	oldUDP, oldTCP := s.detachLocked()
	s.mu.Unlock()
	s.writeMu.Unlock()
	_ = closeSocketPair(oldUDP, oldTCP)
	if err := ctx.Err(); err != nil {
		return err
	}
	lc := net.ListenConfig{}
	// UDP port zero does not reserve the same TCP port. It may already be
	// occupied or excluded by Windows for TCP. Retry only the first dynamic
	// allocation, never silently change a configured or published endpoint.
	attempts := 1
	if _, port, err := net.SplitHostPort(s.address); err == nil && port == "0" {
		attempts = 16
	}
	var udp *net.UDPConn
	var listener net.Listener
	for attempt := 0; attempt < attempts; attempt++ {
		packet, err := lc.ListenPacket(ctx, "udp", s.address)
		if err != nil {
			return err
		}
		udp = packet.(*net.UDPConn)
		listener, err = lc.Listen(ctx, "tcp", udp.LocalAddr().String())
		if err == nil {
			break
		}
		_ = udp.Close()
		if attempt+1 == attempts || ctx.Err() != nil {
			return err
		}
	}
	if err := s.installSocketPair(ctx, udp, listener); err != nil {
		_ = closeSocketPair(udp, listener)
		return err
	}
	return nil
}

func (s *packetSockets) installSocketPair(ctx context.Context, udp *net.UDPConn, listener net.Listener) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := udp.SetReadDeadline(s.readDeadline); err != nil {
		return err
	}
	s.udp, s.tcp = udp, listener
	// Port zero is resolved once, then retained for every replacement.
	s.address = udp.LocalAddr().String()
	close(s.changed)
	s.changed = make(chan struct{})
	return nil
}

func (s *packetSockets) Close() error {
	s.replaceMu.Lock()
	defer s.replaceMu.Unlock()
	s.writeMu.Lock()
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		s.writeMu.Unlock()
		return nil
	}
	s.closed = true
	udp, tcp := s.detachLocked()
	s.mu.Unlock()
	s.writeMu.Unlock()
	return closeSocketPair(udp, tcp)
}

// detachLocked requires writeMu and mu. Its caller closes the returned pair
// outside those locks while holding replaceMu to retain the listening port.
func (s *packetSockets) detachLocked() (*net.UDPConn, net.Listener) {
	s.udpSegmentationDisabled.Store(false)
	s.clearTunnelLocked()
	s.cancelUDPControlLocked(0, true)
	udp, tcp := s.udp, s.tcp
	s.udp, s.tcp = nil, nil
	close(s.changed)
	s.changed = make(chan struct{})
	return udp, tcp
}

func closeSocketPair(udp *net.UDPConn, tcp net.Listener) error {
	var err error
	if tcp != nil {
		err = tcp.Close()
	}
	if udp != nil {
		err = errors.Join(err, udp.Close())
	}
	return err
}

func (s *packetSockets) bound() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.udp != nil
}

func (s *packetSockets) ReadDatagram(b []byte) (int, *net.UDPAddr, error) {
	// Gossip has a 1200-byte budget; IKE/ESP must not be truncated to it.
	// One reader owns this fixed-size buffer, with copies only on queue admission.
	var wire [65535]byte
	for {
		s.mu.Lock()
		conn, changed, closed, deadline := s.udp, s.changed, s.closed, s.readDeadline
		s.mu.Unlock()
		if closed {
			return 0, nil, net.ErrClosed
		}
		if conn == nil {
			if deadline.IsZero() {
				<-changed
			} else {
				timer := time.NewTimer(time.Until(deadline))
				select {
				case <-changed:
					timer.Stop()
				case <-timer.C:
					return 0, nil, context.DeadlineExceeded
				}
			}
			continue
		}
		n, peer, err := conn.ReadFromUDPAddrPort(wire[:])
		var received *ikeTraceDatagram
		if err == nil && s.ikeTrace != nil {
			received = s.ikeTrace.read(wire[:n])
		}
		s.mu.Lock()
		current := conn == s.udp
		consumed := current && err == nil && s.demuxLocked(wire[:n], peer, received)
		s.mu.Unlock()
		if !current {
			if received != nil {
				s.ikeTrace.ingress(time.Now(), "obsolete_socket", ikeDatagram{tunnelDatagram: tunnelDatagram{peer: peer}, trace: received})
			}
			continue
		} // discard packets/errors from an obsolete socket
		if consumed {
			continue
		}
		if errors.Is(err, net.ErrClosed) {
			// UDP can report an ICMP error for an unreachable remote peer.
			// That does not invalidate this local socket: rebinding and syncing
			// immediately would repeatedly provoke the same remote error.
			// Local interface changes have their own OS notification path.
			s.invalidate(conn, nil)
		}
		// IKE/ESP only need the value endpoint. Gossip retains its original
		// UDPAddr interface, including mapped addresses and IPv6 zones; failed
		// reads have no sender address, just as ReadFromUDP did.
		var addr *net.UDPAddr
		if err == nil {
			addr = net.UDPAddrFromAddrPort(peer)
		}
		return copy(b, wire[:n]), addr, err
	}
}

// invalidate retires a broken local socket pair and wakes the owner's event
// loop. The driver then waits for replacement instead of spinning on errors or
// terminating its sole accept worker permanently.
func (s *packetSockets) invalidate(udp *net.UDPConn, tcp net.Listener) {
	s.replaceMu.Lock()
	defer s.replaceMu.Unlock()
	s.writeMu.Lock()
	s.mu.Lock()
	if s.closed || (udp != nil && udp != s.udp) || (tcp != nil && tcp != s.tcp) {
		s.mu.Unlock()
		s.writeMu.Unlock()
		return
	}
	oldUDP, oldTCP := s.detachLocked()
	s.mu.Unlock()
	s.writeMu.Unlock()
	select {
	case s.failed <- struct{}{}:
	default:
	}
	_ = closeSocketPair(oldUDP, oldTCP)
}

func (s *packetSockets) WriteDatagram(b []byte, addr *net.UDPAddr) (int, error) {
	return s.writeUDPControl(b, addr, 0)
}

func (s *packetSockets) WriteIKE(generation uint64, packet []byte, peer netip.AddrPort) error {
	if generation == 0 || !peer.IsValid() {
		return net.ErrClosed
	}
	_, err := s.writeUDPControl(packet, net.UDPAddrFromAddrPort(peer), generation)
	return err
}

func (s *packetSockets) udpControlCurrentLocked(conn *net.UDPConn, generation uint64, peer netip.AddrPort) bool {
	if conn == nil || conn != s.udp || s.closed {
		return false
	}
	if generation == 0 {
		return true
	}
	endpoints, reserved := s.tunnels[generation]
	return reserved && (peer == endpoints.ike || peer == endpoints.natt)
}

func (s *packetSockets) clearTunnelLocked() {
	s.tunnelGeneration++
	clear(s.tunnels)
	clear(s.tunnelPeers)
}

// SelectTunnel reserves the exact remote IKE/NAT-T endpoints. It invalidates
// queued packets and writes from the previous selection, including same-peer
// reconnects; a zero endpoint clears the reservation. Endpoints are reachability
// hints only: the IKE session and current verified policy must authenticate them.
func (s *packetSockets) SelectTunnel(ikePeer, nattPeer netip.AddrPort) uint64 {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearTunnelLocked()
	s.cancelUDPControlLocked(0, false)
	if !s.closed {
		s.addTunnelLocked(s.tunnelGeneration, ikePeer, nattPeer)
	}
	return s.tunnelGeneration
}

func (s *packetSockets) demuxLocked(packet []byte, peer netip.AddrPort, received *ikeTraceDatagram) bool {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	reservations := s.tunnelPeers[peer]
	if len(reservations) == 0 {
		if received != nil {
			s.ikeTrace.ingress(time.Now(), "no_reservation", ikeDatagram{tunnelDatagram: tunnelDatagram{peer: peer}, trace: received})
		}
		return false
	}
	for generation := range reservations {
		s.demuxTunnelLocked(packet, peer, generation, s.tunnels[generation], received)
	}
	return true
}

func (s *packetSockets) demuxTunnelLocked(packet []byte, peer netip.AddrPort, generation uint64, endpoints tunnelEndpoints, received *ikeTraceDatagram) bool {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if peer != endpoints.ike && peer != endpoints.natt {
		return false
	}
	datagram := ikeDatagram{tunnelDatagram: tunnelDatagram{generation: generation, peer: peer}, trace: received}
	if peer == endpoints.natt {
		kind, body, err := ike.ParseNATDatagram(packet)
		if err != nil {
			if received != nil {
				s.ikeTrace.ingress(time.Now(), "demux_rejected", datagram, slog.String("reason", err.Error()))
			}
			return true
		}
		if kind == ike.NATDatagramKeepalive {
			return true
		}
		packet = body
		if kind == ike.NATDatagramESP {
			s.queueTunnelESP(datagram.tunnelDatagram, body)
			return true
		}
	} else if _, _, err := ike.DecodeHeader(packet); err != nil {
		if received != nil {
			s.ikeTrace.ingress(time.Now(), "demux_rejected", datagram, slog.String("reason", err.Error()))
		}
		return true
	}
	// A full IKE queue drops the datagram without blocking the socket reader.
	depth, capacity := len(s.ikePackets), cap(s.ikePackets)
	stage := "ingress_queued"
	var at time.Time
	if received != nil {
		at = time.Now()
	}
	if depth < capacity {
		datagram.packet = append([]byte(nil), packet...)
		s.ikePackets <- datagram
	} else {
		s.ikeIngressDrops.Add(1)
		stage = "ingress_queue_full"
	}
	if received != nil {
		s.ikeTrace.ingress(at, stage, datagram, slog.Int("depth_before", depth), slog.Int("capacity", capacity))
	}
	return true
}

func (s *packetSockets) queueTunnelESP(datagram tunnelDatagram, packet []byte) {
	// Admission timing precedes the detach and channel send.
	datagram.timing = beginFixturePacketTimingQueue(fixturePacketTimingInbound)
	if len(s.espPackets) < cap(s.espPackets) {
		datagram.packet = append([]byte(nil), packet...)
		s.espPackets <- datagram
	} else {
		datagram.timing.QueueRejected()
		recordESPIngressDrop()
	}
}

// WriteTunnel is serialized with rebind/selection and has the same one-second
// bound as Gossip sends. Control and standalone callers use plain UDP.
func (s *packetSockets) WriteTunnel(generation uint64, packet []byte, peer netip.AddrPort) error {
	var timing fixturePacketTiming
	return s.writeTunnel(generation, packet, peer, &timing)
}

// Only a synchronous sampled business completion lends its scalar trace.
// Ordinary and control callers keep WriteTunnel's unchanged public contract.
func (s *packetSockets) writeTunnelDefault(generation uint64, packet []byte, peer netip.AddrPort, timing *fixturePacketTiming) error {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	timing.MarkUDPWriterAcquired()
	conn := s.udp
	endpoints, reserved := s.tunnels[generation]
	valid := !s.closed && conn != nil && reserved && peer.IsValid() && (peer == endpoints.ike || peer == endpoints.natt)
	timing.MarkUDPValidationDone()
	if !valid {
		return net.ErrClosed
	}
	err := conn.SetWriteDeadline(time.Now().Add(time.Second))
	timing.MarkUDPDeadlineDone()
	if err != nil {
		return err
	}
	_, err = conn.WriteToUDPAddrPort(packet, peer)
	timing.MarkUDPWriteDone()
	return err
}

// writeTunnelSegments serializes endpoint validation and the single Winsock
// operation against socket replacement. A false result means no datagrams
// were submitted and the caller can use the ordinary writes.
func (s *packetSockets) writeTunnelSegments(generation uint64, peer netip.AddrPort, packet []byte, size int, traces []fixturePacketTiming) (bool, error) {
	s.writeMu.Lock()
	defer s.writeMu.Unlock()
	if s.udpSegmentationDisabled.Load() {
		return false, nil
	}
	for i := range traces {
		traces[i].MarkUDPWriterAcquired()
	}
	conn := s.udp
	endpoints, reserved := s.tunnels[generation]
	valid := !s.closed && conn != nil && reserved && peer.IsValid() && (peer == endpoints.ike || peer == endpoints.natt)
	for i := range traces {
		traces[i].MarkUDPValidationDone()
	}
	if !valid {
		return true, net.ErrClosed
	}
	err := conn.SetWriteDeadline(time.Now().Add(time.Second))
	for i := range traces {
		traces[i].MarkUDPDeadlineDone()
	}
	if err != nil {
		return true, err
	}
	submitted, unsupported, err := writeUDPSegments(conn, packet, size, peer)
	if unsupported {
		s.udpSegmentationDisabled.Store(true)
	}
	for i := range traces {
		traces[i].MarkUDPWriteDone()
	}
	return submitted, err
}

func (s *packetSockets) SetReadDeadline(deadline time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	s.readDeadline = deadline
	close(s.changed)
	s.changed = make(chan struct{})
	if s.udp != nil {
		return s.udp.SetReadDeadline(deadline)
	}
	return nil
}

func (s *packetSockets) LocalAddr() *net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	addr, _ := net.ResolveUDPAddr("udp", s.address)
	return addr
}

// gossipListener adapts only the differing Addr signature of net.Listener.
type gossipListener struct{ *packetSockets }

func (s gossipListener) Addr() net.Addr { return s.LocalAddr() }
func (s gossipListener) Accept() (net.Conn, error) {
	for {
		s.mu.Lock()
		listener, changed, closed := s.tcp, s.changed, s.closed
		s.mu.Unlock()
		if closed {
			return nil, net.ErrClosed
		}
		if listener == nil {
			<-changed
			continue
		}
		conn, err := listener.Accept()
		s.mu.Lock()
		current := listener == s.tcp
		s.mu.Unlock()
		if !current {
			if conn != nil {
				_ = conn.Close()
			}
			continue
		}
		if err != nil {
			s.invalidate(nil, listener)
			continue
		}
		return conn, err
	}
}
