package photonwindows

import (
	"context"
	"errors"
	"net"
	"sync"
	"time"
)

// gossipSockets keeps the driver's receive and accept loops alive across a local
// socket replacement. It owns no protocol state, workers or database handles.
// A failed replacement leaves both protocols unavailable until the next retry.
type gossipSockets struct {
	mu           sync.Mutex
	udp          *net.UDPConn
	tcp          net.Listener
	address      string
	changed      chan struct{}
	failed       chan struct{}
	closed       bool
	readDeadline time.Time
}

func openGossipSockets(ctx context.Context, address string) (*gossipSockets, error) {
	s := &gossipSockets{address: address, changed: make(chan struct{}), failed: make(chan struct{}, 1)}
	if err := s.Rebind(ctx); err != nil {
		s.Close()
		return nil, err
	}
	return s, nil
}

// Rebind closes the old generation before binding the same local endpoint.
// Holding mu serializes rebind and close; bind performs only numeric local I/O
// under a deadline. No reader holds mu while waiting on a socket.
func (s *gossipSockets) Rebind(ctx context.Context) error {
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
	packet, err := lc.ListenPacket(ctx, "udp", s.address)
	if err != nil {
		return err
	}
	udp := packet.(*net.UDPConn)
	listener, err := lc.Listen(ctx, "tcp", udp.LocalAddr().String())
	if err != nil {
		_ = udp.Close()
		return err
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

func (s *gossipSockets) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil
	}
	s.closed = true
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

func (s *gossipSockets) ReadDatagram(b []byte) (int, *net.UDPAddr, error) {
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
		n, addr, err := conn.ReadFromUDP(b)
		s.mu.Lock()
		current := conn == s.udp
		s.mu.Unlock()
		if !current {
			continue
		} // discard packets/errors from an obsolete socket
		if errors.Is(err, net.ErrClosed) {
			// UDP can report an ICMP error for an unreachable remote peer.
			// That does not invalidate this local socket: rebinding and syncing
			// immediately would repeatedly provoke the same remote error.
			// Local interface changes have their own OS notification path.
			s.invalidate(conn, nil)
		}
		return n, addr, err
	}
}

// invalidate retires a broken local socket pair and wakes the owner's event
// loop. The driver then waits for replacement instead of spinning on errors or
// terminating its sole accept worker permanently.
func (s *gossipSockets) invalidate(udp *net.UDPConn, tcp net.Listener) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || (udp != nil && udp != s.udp) || (tcp != nil && tcp != s.tcp) {
		return
	}
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

func (s *gossipSockets) WriteDatagram(b []byte, addr *net.UDPAddr) (int, error) {
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

func (s *gossipSockets) SetReadDeadline(deadline time.Time) error {
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

func (s *gossipSockets) LocalAddr() *net.UDPAddr {
	s.mu.Lock()
	defer s.mu.Unlock()
	addr, _ := net.ResolveUDPAddr("udp", s.address)
	return addr
}

// gossipListener adapts only the differing Addr signature of net.Listener.
type gossipListener struct{ *gossipSockets }

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
