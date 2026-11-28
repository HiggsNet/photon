package photonproxy

import (
	"context"
	"net"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
)

const (
	udpIdleTimeout = time.Minute
	udpFlowLimit   = 32
)

type udpFlowKey struct {
	source netip.AddrPort
	target netip.AddrPort
}

type udpFlows struct {
	mu      sync.Mutex
	sockets map[udpFlowKey]net.Conn
	workers sync.WaitGroup
}

func (h *tunnelHandler) serveUDP(w http.ResponseWriter, r *http.Request, delegatedScope []netip.Prefix) {
	stream, err := startResponse(w)
	if err != nil {
		return
	}
	ctx, cancel := context.WithCancel(r.Context())
	flows := udpFlows{sockets: make(map[udpFlowKey]net.Conn)}
	replies := make(chan trusttunnel.Datagram, udpFlowLimit)
	inputDone := make(chan struct{})
	go func() {
		defer close(inputDone)
		for {
			packet, err := trusttunnel.ReadRequest(r.Body)
			if err != nil || ctx.Err() != nil {
				return
			}
			if packet.Destination.Port() != 0 && h.permitsTarget("udp", packet.Destination) && (delegatedScope == nil || withinPrefixes(packet.Destination.Addr(), delegatedScope)) {
				flows.send(ctx, h.dialDestination, packet, replies)
			}
		}
	}()
	defer func() {
		cancel()
		_ = r.Body.Close()
		<-inputDone
		flows.close()
	}()
	for {
		select {
		case <-ctx.Done():
			return
		case <-inputDone:
			return
		case reply := <-replies:
			if err := trusttunnel.WriteResponse(stream, reply); err != nil {
				return
			}
		}
	}
}

func (f *udpFlows) send(ctx context.Context, dial func(context.Context, string, netip.AddrPort) (net.Conn, error), packet trusttunnel.Datagram, replies chan<- trusttunnel.Datagram) {
	key := udpFlowKey{source: packet.Source, target: packet.Destination}
	f.mu.Lock()
	conn := f.sockets[key]
	if conn == nil && len(f.sockets) < udpFlowLimit {
		conn, _ = dial(ctx, "udp", key.target)
		if conn != nil {
			_ = conn.SetDeadline(time.Now().Add(udpIdleTimeout))
			f.sockets[key] = conn
			f.workers.Go(func() { f.readReplies(ctx, key, conn, replies) })
		}
	}
	f.mu.Unlock()
	if conn == nil {
		return
	}
	_ = conn.SetDeadline(time.Now().Add(udpIdleTimeout))
	_, _ = conn.Write(packet.Payload)
}

func (f *udpFlows) readReplies(ctx context.Context, key udpFlowKey, conn net.Conn, replies chan<- trusttunnel.Datagram) {
	defer func() {
		_ = conn.Close()
		f.mu.Lock()
		delete(f.sockets, key)
		f.mu.Unlock()
	}()
	var buffer [65535]byte
	for {
		n, err := conn.Read(buffer[:])
		if err != nil || ctx.Err() != nil {
			return
		}
		_ = conn.SetReadDeadline(time.Now().Add(udpIdleTimeout))
		packet := trusttunnel.Datagram{
			Source: key.target, Destination: key.source, Payload: append([]byte(nil), buffer[:n]...),
		}
		select {
		case replies <- packet:
		case <-ctx.Done():
			return
		default: // drop datagrams when the client cannot drain the reply queue
		}
	}
}

func (f *udpFlows) close() {
	f.mu.Lock()
	for _, conn := range f.sockets {
		_ = conn.Close()
	}
	f.mu.Unlock()
	f.workers.Wait()
}

func udpTarget(ctx context.Context, host string, port uint16) (netip.AddrPort, error) {
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	addresses, err := resolveAddresses(ctx, host)
	if err != nil {
		return netip.AddrPort{}, err
	}
	if len(addresses) == 0 {
		return netip.AddrPort{}, errDenied
	}
	return netip.AddrPortFrom(addresses[0].Unmap(), port), nil
}
