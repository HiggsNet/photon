package photonwindows

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/photonclient/ike"
)

// packetSockets shares one UDP endpoint between Gossip and a selected tunnel,
// keeping receive and accept loops alive across a local socket replacement.
// It owns no protocol state, workers or database handles.
// A failed replacement leaves both protocols unavailable until the next retry.
type packetSockets struct {
	mu                sync.Mutex
	udp               *net.UDPConn
	tcp               net.Listener
	address           string
	changed           chan struct{}
	failed            chan struct{}
	closed            bool
	readDeadline      time.Time
	tunnelGeneration  uint64
	ikePeer, nattPeer netip.AddrPort
	ikePackets        chan tunnelDatagram
	espPackets        chan tunnelDatagram
}

// These are bounded ingress queues, not protocol workers. The GossipDriver's
// sole reader performs the demux; Daemon remains the tunnel lifecycle owner.
type tunnelDatagram struct {
	generation uint64
	peer       netip.AddrPort
	packet     []byte
}

func openPacketSockets(ctx context.Context, address string) (*packetSockets, error) {
	s := &packetSockets{address: address, changed: make(chan struct{}), failed: make(chan struct{}, 1), ikePackets: make(chan tunnelDatagram, 16), espPackets: make(chan tunnelDatagram, 64)}
	if err := s.Rebind(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Rebind closes the old generation before binding the same local endpoint.
// Holding mu serializes rebind and close; bind performs only numeric local I/O
// under a deadline. No reader holds mu while waiting on a socket.
func (s *packetSockets) Rebind(ctx context.Context) error {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return net.ErrClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	s.clearTunnelLocked()
	if s.udp != nil {
		_ = s.udp.Close()
		s.udp = nil
	}
	if s.tcp != nil {
		_ = s.tcp.Close()
		s.tcp = nil
	}
	defer func() { close(s.changed); s.changed = make(chan struct{}) }()
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
	if err := ctx.Err(); err != nil {
		_ = udp.Close()
		_ = listener.Close()
		return err
	}
	if err := udp.SetReadDeadline(s.readDeadline); err != nil {
		_ = udp.Close()
		_ = listener.Close()
		return err
	}
	s.udp, s.tcp = udp, listener
	// Port zero is resolved once, then retained for every replacement.
	s.address = udp.LocalAddr().String()
	return nil
}

func (s *packetSockets) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
	s.clearTunnelLocked()
	var err error
	if s.udp != nil {
		err = errors.Join(err, s.udp.Close())
	}
	if s.tcp != nil {
		err = errors.Join(err, s.tcp.Close())
	}
	s.udp, s.tcp = nil, nil
	close(s.changed)
	return err
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
		n, addr, err := conn.ReadFromUDP(wire[:])
		s.mu.Lock()
		current := conn == s.udp
		consumed := current && err == nil && s.demuxLocked(wire[:n], addr.AddrPort())
		s.mu.Unlock()
		if !current {
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
		return copy(b, wire[:n]), addr, err
	}
}

// invalidate retires a broken local socket pair and wakes the owner's event
// loop. The driver then waits for replacement instead of spinning on errors or
// terminating its sole accept worker permanently.
func (s *packetSockets) invalidate(udp *net.UDPConn, tcp net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || (udp != nil && udp != s.udp) || (tcp != nil && tcp != s.tcp) {
		return
	}
	s.clearTunnelLocked()
	if s.udp != nil {
		_ = s.udp.Close()
		s.udp = nil
	}
	if s.tcp != nil {
		_ = s.tcp.Close()
		s.tcp = nil
	}
	close(s.changed)
	s.changed = make(chan struct{})
	select {
	case s.failed <- struct{}{}:
	default:
	}
}

func (s *packetSockets) WriteDatagram(b []byte, addr *net.UDPAddr) (int, error) {
	// Serialize writes with replacement so stale completion cannot claim success.
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.udp == nil {
		return 0, net.ErrClosed
	}
	if err := s.udp.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return 0, err
	}
	return s.udp.WriteToUDP(b, addr)
}

func (s *packetSockets) clearTunnelLocked() {
	s.tunnelGeneration++
	s.ikePeer, s.nattPeer = netip.AddrPort{}, netip.AddrPort{}
}

// SelectTunnel reserves the exact remote IKE/NAT-T endpoints. It invalidates
// queued packets and writes from the previous selection, including same-peer
// reconnects; a zero endpoint clears the reservation. Endpoints are reachability
// hints only: the IKE session and current verified policy must authenticate them.
func (s *packetSockets) SelectTunnel(ikePeer, nattPeer netip.AddrPort) uint64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.clearTunnelLocked()
	if !s.closed {
		s.ikePeer, s.nattPeer = ikePeer, nattPeer
	}
	return s.tunnelGeneration
}

func (s *packetSockets) demuxLocked(packet []byte, peer netip.AddrPort) bool {
	peer = netip.AddrPortFrom(peer.Addr().Unmap(), peer.Port())
	if peer != s.ikePeer && peer != s.nattPeer {
		return false
	}
	queue := s.ikePackets
	if peer == s.nattPeer {
		kind, body, err := ike.ParseNATDatagram(packet)
		if err != nil || kind == ike.NATDatagramKeepalive {
			return true
		}
		packet = body
		if kind == ike.NATDatagramESP {
			queue = s.espPackets
		}
	} else if _, _, err := ike.DecodeHeader(packet); err != nil {
		return true
	}
	// Full queues drop datagrams; IKE retransmission recovers without blocking
	// gossip reception, and ESP never creates an unbounded backlog.
	if len(queue) < cap(queue) {
		queue <- tunnelDatagram{s.tunnelGeneration, peer, append([]byte(nil), packet...)}
	}
	return true
}

// WriteTunnel is serialized with rebind/selection and has the same one-second
// bound as Gossip sends. Windows uses one WriteToUDP per packet; no batch API
// or background send queue is required to preserve packet lifetime.
func (s *packetSockets) WriteTunnel(generation uint64, packet []byte, peer netip.AddrPort) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || s.udp == nil || generation != s.tunnelGeneration || !peer.IsValid() || (peer != s.ikePeer && peer != s.nattPeer) {
		return net.ErrClosed
	}
	if err := s.udp.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return err
	}
	_, err := s.udp.WriteToUDPAddrPort(packet, peer)
	return err
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
