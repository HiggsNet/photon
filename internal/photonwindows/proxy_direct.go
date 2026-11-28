package photonwindows

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"time"

	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/service"
)

type proxyDirectHost struct {
	ctx       context.Context
	mesh      *meshRuntime
	mu        sync.Mutex
	links     map[service.ProxyDirectLink]*proxyDirectStack
	listeners map[uint16]*proxyDirectListener
	workers   sync.WaitGroup
}

func newProxyDirectHost(ctx context.Context, mesh *meshRuntime) *proxyDirectHost {
	return &proxyDirectHost{ctx: ctx, mesh: mesh, links: make(map[service.ProxyDirectLink]*proxyDirectStack),
		listeners: make(map[uint16]*proxyDirectListener)}
}

func (h *proxyDirectHost) run() {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for h.ctx.Err() == nil {
		h.sync()
		select {
		case <-h.ctx.Done():
		case <-ticker.C:
		}
	}
	h.mu.Lock()
	for _, listener := range h.listeners {
		listener.closeLocked()
	}
	for key, link := range h.links {
		delete(h.links, key)
		link.close()
	}
	h.mu.Unlock()
	h.workers.Wait()
}

func (h *proxyDirectHost) sync() {
	h.mesh.stateMu.Lock()
	now := time.Now()
	wanted := make(map[service.ProxyDirectLink]struct{}, len(h.mesh.peers))
	for key, peer := range h.mesh.peers {
		var facts packetAuthorization
		if h.mesh.packetFacts(peer, corestate.View{}, now, &facts) {
			if link := proxyPeerLink(key, peer, &facts); link.ID != "" {
				wanted[link] = struct{}{}
			}
		}
	}
	h.mesh.stateMu.Unlock()
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ctx.Err() != nil {
		return
	}
	for key, link := range h.links {
		if _, ok := wanted[key]; ok {
			continue
		}
		for _, listener := range h.listeners {
			if binding := listener.bindings[link]; binding != nil {
				_ = binding.Close()
				delete(listener.bindings, link)
			}
		}
		delete(h.links, key)
		h.workers.Go(link.close)
	}
	for key := range wanted {
		if h.links[key] != nil {
			continue
		}
		// The direct packets are IPv6. Keep their MTU within the minimum
		// IPv6 path limit, independently of the business Wintun settings.
		link, err := newProxyDirectStack(h.ctx, key, 1280)
		if err != nil {
			h.mesh.logger.Warn("proxy_direct_link_failed", "peer", key.Peer, "error", err)
			continue
		}
		h.links[key] = link
		h.workers.Go(func() { link.readOutbound(func(packet []byte) { h.mesh.sendProxyDirect(link, packet) }) })
		for _, listener := range h.listeners {
			if err := listener.bindLocked(link); err != nil {
				h.mesh.logger.Warn("proxy_direct_bind_failed", "peer", key.Peer, "port", listener.port, "error", err)
			}
		}
	}
}

func (h *proxyDirectHost) snapshot() []service.ProxyDirectLink {
	h.mu.Lock()
	defer h.mu.Unlock()
	out := make([]service.ProxyDirectLink, 0, len(h.links))
	for key := range h.links {
		out = append(out, key)
	}
	return out
}

func (h *proxyDirectHost) lookup(key service.ProxyDirectLink) *proxyDirectStack {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.links[key]
}

func (h *proxyDirectHost) dial(ctx context.Context, key service.ProxyDirectLink, port uint16) (net.Conn, error) {
	if link := h.lookup(key); link != nil {
		return link.dial(ctx, port)
	}
	return nil, errors.New("the requested direct IPsec link has been withdrawn")
}

func (h *proxyDirectHost) listen(ctx context.Context, port uint16) (net.Listener, error) {
	// Serve the shared listener's local TLS readiness check on ephemeral
	// loopback. Route requests still require an authenticated scoped link.
	probe, err := (&net.ListenConfig{}).Listen(ctx, "tcp6", "[::1]:0")
	if err != nil {
		return nil, err
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ctx.Err() != nil || h.listeners[port] != nil {
		_ = probe.Close()
		return nil, fmt.Errorf("direct proxy port %d unavailable", port)
	}
	listener := &proxyDirectListener{host: h, probe: probe, port: port, done: make(chan struct{}),
		incoming: make(chan net.Conn), bindings: make(map[*proxyDirectStack]net.Listener)}
	for _, link := range h.links {
		if err := listener.bindLocked(link); err != nil {
			listener.closeLocked()
			return nil, err
		}
	}
	h.listeners[port] = listener
	return listener, nil
}

type proxyDirectListener struct {
	host     *proxyDirectHost
	probe    net.Listener
	port     uint16
	done     chan struct{}
	incoming chan net.Conn
	bindings map[*proxyDirectStack]net.Listener
	start    sync.Once
}

func (l *proxyDirectListener) Addr() net.Addr { return l.probe.Addr() }

func (l *proxyDirectListener) Accept() (net.Conn, error) {
	l.host.mu.Lock()
	if l.host.ctx.Err() == nil {
		l.start.Do(func() { l.host.workers.Go(func() { l.forward(l.probe, "", l.host.ctx) }) })
	}
	l.host.mu.Unlock()
	select {
	case conn := <-l.incoming:
		return conn, nil
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *proxyDirectListener) Close() error {
	l.host.mu.Lock()
	defer l.host.mu.Unlock()
	l.closeLocked()
	return nil
}

func (l *proxyDirectListener) closeLocked() {
	select {
	case <-l.done:
		return
	default:
		close(l.done)
	}
	if l.host.listeners[l.port] == l {
		delete(l.host.listeners, l.port)
	}
	_ = l.probe.Close()
	for _, binding := range l.bindings {
		_ = binding.Close()
	}
	clear(l.bindings)
}

func (l *proxyDirectListener) bindLocked(link *proxyDirectStack) error {
	listener, err := link.listen(l.port)
	if err != nil {
		return err
	}
	l.bindings[link] = listener
	l.host.workers.Go(func() { l.forward(listener, link.link.Interface, link.ctx) })
	return nil
}

func (l *proxyDirectListener) forward(listener net.Listener, scope string, ctx context.Context) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		if scope != "" {
			conn = proxyScopedConn{Conn: conn, scope: scope}
		}
		select {
		case l.incoming <- conn:
		case <-l.done:
			_ = conn.Close()
			return
		case <-ctx.Done():
			_ = conn.Close()
			return
		}
	}
}

func proxyPeerLink(key meshPath, p *meshPeer, facts *packetAuthorization) service.ProxyDirectLink {
	pipeline := p.leaf.pipeline
	data := p.tunnel.data
	if facts.plan.Selected == nil || facts.plan.Selected.Zone != key.zone || facts.plan.outerFamily != key.family ||
		pipeline == nil || !pipeline.local.IsLinkLocalUnicast() || !pipeline.peer.IsLinkLocalUnicast() ||
		!data.current(p.tunnel.generation, data.active, facts.plan) {
		return service.ProxyDirectLink{}
	}
	return service.ProxyDirectLink{
		Peer: key.zone, Family: key.family, ID: string(key.zone) + key.family,
		Generation: data.generation, Interface: fmt.Sprintf("%s-%x", key.family, data.generation),
		Local: pipeline.local, Remote: pipeline.peer,
	}
}

func proxyDirectPacket(link service.ProxyDirectLink, packet []byte, outbound bool) bool {
	const ipv6Header, tcpHeader = 40, 20
	if len(packet) < ipv6Header+tcpHeader || packet[0]>>4 != 6 || packet[6] != 6 ||
		int(binary.BigEndian.Uint16(packet[4:6]))+ipv6Header != len(packet) {
		return false
	}
	source, destination := link.Remote, link.Local
	if outbound {
		source, destination = destination, source
	}
	return netip.AddrFrom16([16]byte(packet[8:24])) == source && netip.AddrFrom16([16]byte(packet[24:40])) == destination
}

func (m *meshRuntime) sendProxyDirect(link *proxyDirectStack, packet []byte) {
	m.stateMu.Lock()
	defer m.stateMu.Unlock()
	key := meshPath{zone: link.link.Peer, family: link.link.Family}
	peer := m.peers[key]
	var facts packetAuthorization
	if link.ctx.Err() != nil || peer == nil || !m.packetFacts(peer, corestate.View{}, time.Now(), &facts) ||
		proxyPeerLink(key, peer, &facts) != link.link || !proxyDirectPacket(link.link, packet, true) {
		return
	}
	data := peer.tunnel.data
	if !dataplaneSelectors(data.active, packet, true) {
		return
	}
	if job, ok := data.newJob(data.active, packet, true); ok {
		job.proxyDirect = link
		data.enqueue(job)
	}
}
