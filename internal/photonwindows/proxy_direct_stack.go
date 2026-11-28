package photonwindows

import (
	"context"
	"fmt"
	"net"
	"net/netip"

	"github.com/HiggsNet/photon/pkg/service"
	"github.com/metacubex/gvisor/pkg/buffer"
	"github.com/metacubex/gvisor/pkg/tcpip"
	"github.com/metacubex/gvisor/pkg/tcpip/adapters/gonet"
	"github.com/metacubex/gvisor/pkg/tcpip/link/channel"
	"github.com/metacubex/gvisor/pkg/tcpip/network/ipv6"
	"github.com/metacubex/gvisor/pkg/tcpip/stack"
	"github.com/metacubex/gvisor/pkg/tcpip/transport/tcp"
)

const proxyDirectNIC tcpip.NICID = 1

// A stack has exactly one authenticated IPv6 link. A shared Wintun interface
// would erase the identity of the outer IPv4/IPv6 SA on received packets.
type proxyDirectStack struct {
	ctx      context.Context
	cancel   context.CancelFunc
	link     service.ProxyDirectLink
	stack    *stack.Stack
	endpoint *channel.Endpoint
}

func newProxyDirectStack(ctx context.Context, link service.ProxyDirectLink, mtu uint32) (*proxyDirectStack, error) {
	ctx, cancel := context.WithCancel(ctx)
	s := &proxyDirectStack{ctx: ctx, cancel: cancel, link: link,
		stack: stack.New(stack.Options{
			NetworkProtocols:   []stack.NetworkProtocolFactory{ipv6.NewProtocol},
			TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
		}),
		endpoint: channel.New(128, mtu, ""),
	}
	local := tcpip.AddrFrom16(link.Local.As16()).WithPrefix()
	remote := tcpip.AddrFrom16(link.Remote.As16()).WithPrefix()
	if err := s.stack.CreateNIC(proxyDirectNIC, s.endpoint); err != nil {
		s.close()
		return nil, fmt.Errorf("create proxy direct interface: %s", err)
	}
	if err := s.stack.AddProtocolAddress(proxyDirectNIC, tcpip.ProtocolAddress{
		Protocol: ipv6.ProtocolNumber, AddressWithPrefix: local,
	}, stack.AddressProperties{}); err != nil {
		s.close()
		return nil, fmt.Errorf("assign proxy direct link address: %s", err)
	}
	s.stack.SetRouteTable([]tcpip.Route{{Destination: remote.Subnet(), NIC: proxyDirectNIC}})
	return s, nil
}

func (s *proxyDirectStack) close() {
	s.cancel()
	s.stack.Close()
	s.endpoint.Close()
	s.stack.Wait()
}

func (s *proxyDirectStack) readOutbound(send func([]byte)) {
	for packet := s.endpoint.ReadContext(s.ctx); packet != nil; packet = s.endpoint.ReadContext(s.ctx) {
		view := packet.ToView()
		packet.DecRef()
		send(view.AsSlice())
		view.Release()
	}
}

func (s *proxyDirectStack) inject(packet []byte) {
	if s.ctx.Err() != nil {
		return
	}
	pkt := stack.NewPacketBuffer(stack.PacketBufferOptions{Payload: buffer.MakeWithData(packet)})
	s.endpoint.InjectInbound(ipv6.ProtocolNumber, pkt)
	pkt.DecRef()
}

func (s *proxyDirectStack) dial(ctx context.Context, port uint16) (net.Conn, error) {
	ctx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(s.ctx, cancel)
	defer func() { stop(); cancel() }()
	local := tcpip.FullAddress{NIC: proxyDirectNIC, Addr: tcpip.AddrFrom16(s.link.Local.As16())}
	peer := tcpip.FullAddress{NIC: proxyDirectNIC, Addr: tcpip.AddrFrom16(s.link.Remote.As16()), Port: port}
	return gonet.DialTCPWithBind(ctx, s.stack, local, peer, ipv6.ProtocolNumber)
}

func (s *proxyDirectStack) listen(port uint16) (net.Listener, error) {
	return gonet.ListenTCP(s.stack, tcpip.FullAddress{
		NIC: proxyDirectNIC, Addr: tcpip.AddrFrom16(s.link.Local.As16()), Port: port,
	}, ipv6.ProtocolNumber)
}

type proxyScopedConn struct {
	net.Conn
	scope string
}

func (c proxyScopedConn) LocalAddr() net.Addr  { return proxyScopedAddr(c.Conn.LocalAddr(), c.scope) }
func (c proxyScopedConn) RemoteAddr() net.Addr { return proxyScopedAddr(c.Conn.RemoteAddr(), c.scope) }

func proxyScopedAddr(address net.Addr, scope string) net.Addr {
	if tcp, ok := address.(*net.TCPAddr); ok {
		addr := tcp.AddrPort()
		return net.TCPAddrFromAddrPort(netip.AddrPortFrom(addr.Addr().WithZone(scope), addr.Port()))
	}
	return address
}
