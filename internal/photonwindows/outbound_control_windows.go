package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"math/bits"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

func (r *outboundRouteResolver) ikeSource(target netip.Addr) (netip.Addr, error) {
	path, err := r.packetPath(target, 1) // IKE is always an outer packet.
	return path.source, err
}

func bindUnicastInterface(peer netip.Addr, index uint32, conn syscall.RawConn) error {
	var optionErr error
	if err := conn.Control(func(fd uintptr) {
		const unicastIF = 31
		level, value := windows.IPPROTO_IPV6, index
		if peer.Is4() {
			level, value = windows.IPPROTO_IP, bits.ReverseBytes32(index)
		}
		optionErr = windows.SetsockoptInt(windows.Handle(fd), level, unicastIF, int(value))
	}); err != nil {
		return err
	}
	return optionErr
}

func dialBoundControl(ctx context.Context, dialer net.Dialer, network string, peer netip.AddrPort, index uint32) (net.Conn, error) {
	if index != 0 {
		dialer.Control = func(_, _ string, conn syscall.RawConn) error {
			return bindUnicastInterface(peer.Addr(), index, conn)
		}
	}
	if peer.Addr().Is4() {
		network += "4"
	} else {
		network += "6"
	}
	return dialer.DialContext(ctx, network, peer.String())
}

func (r *outboundRouteResolver) dialObjectPull(ctx context.Context, dialer net.Dialer, address string) (net.Conn, error) {
	if r == nil {
		return dialer.DialContext(ctx, "tcp", address)
	}
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	n, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, err
	}
	var addrs []netip.Addr
	if ip, err := netip.ParseAddr(host); err == nil {
		addrs = []netip.Addr{ip}
	} else {
		addrs, err = controlDNS(ctx).LookupNetIP(ctx, "ip", host)
		if err != nil {
			return nil, err
		}
	}
	var dialErr error
	for _, ip := range addrs {
		ip = ip.Unmap()
		path, err := r.packetPath(ip, 0)
		if err == nil {
			var conn net.Conn
			conn, err = dialBoundControl(ctx, dialer, "tcp", netip.AddrPortFrom(ip, uint16(n)), path.index)
			if err == nil {
				return conn, nil
			}
		}
		dialErr = errors.Join(dialErr, err)
	}
	if dialErr == nil {
		dialErr = errors.New("no address returned")
	}
	return nil, fmt.Errorf("Gossip TCP to %s: %w", address, dialErr)
}

type windowsControlDNS struct{}

func newControlDNS() outboundDNS { return windowsControlDNS{} }

func (r windowsControlDNS) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	addresses, err := r.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return nil, err
	}
	ips := make([]net.IPAddr, 0, len(addresses))
	for _, address := range addresses {
		ips = append(ips, net.IPAddr{IP: net.IP(address.AsSlice()), Zone: address.Zone()})
	}
	return ips, nil
}

func (windowsControlDNS) LookupNetIP(ctx context.Context, family, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return net.DefaultResolver.LookupNetIP(ctx, family, ip.String())
	}
	servers, err := controlDNSServers()
	if err != nil {
		return nil, err
	}
	var lookupErr error
	for i, server := range servers {
		if ctx.Err() != nil {
			break
		}
		// A DNS server whose route exists can still silently drop packets.
		// Leave time for the remaining interfaces within the caller's budget.
		wait := time.Second
		if deadline, ok := ctx.Deadline(); ok {
			wait = min(wait, time.Until(deadline)/time.Duration(len(servers)-i))
		}
		queryCtx, cancel := context.WithTimeout(ctx, wait)
		resolver := net.Resolver{PreferGo: true, Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
			return dialBoundControl(ctx, net.Dialer{}, network, server.peer, server.index)
		}}
		ips, err := resolver.LookupNetIP(queryCtx, family, host)
		cancel()
		if err == nil {
			return ips, nil
		}
		var dnsErr *net.DNSError
		if errors.As(err, &dnsErr) && dnsErr.IsNotFound {
			return nil, err
		}
		lookupErr = errors.Join(lookupErr, err)
	}
	return nil, fmt.Errorf("Photon underlay DNS for %s: %w", host, errors.Join(lookupErr, ctx.Err()))
}

type controlDNSServer struct {
	peer   netip.AddrPort
	index  uint32
	metric uint32
}

var windowsDeprecatedDNS = netip.MustParsePrefix("fec0::/10")

func controlDNSServers() ([]controlDNSServer, error) {
	interfaces, err := outboundInterfaces()
	if err != nil {
		return nil, err
	}
	size := uint32(15 * 1024)
	for attempts := 0; attempts < 3; attempts++ {
		buf := make([]byte, size)
		head := (*windows.IpAdapterAddresses)(unsafe.Pointer(&buf[0]))
		err := windows.GetAdaptersAddresses(windows.AF_UNSPEC, windows.GAA_FLAG_SKIP_ANYCAST|windows.GAA_FLAG_SKIP_MULTICAST|windows.GAA_FLAG_SKIP_UNICAST, 0, head, &size)
		if errors.Is(err, windows.ERROR_BUFFER_OVERFLOW) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var servers []controlDNSServer
		for row := head; row != nil; row = row.Next {
			for dns := row.FirstDnsServerAddress; dns != nil; dns = dns.Next {
				addr, ok := netip.AddrFromSlice(dns.Address.IP())
				addr = addr.Unmap()
				if !ok || windowsDeprecatedDNS.Contains(addr) || !addr.IsGlobalUnicast() && !addr.IsLinkLocalUnicast() {
					continue
				}
				family := uint16(windows.AF_INET6)
				if addr.Is4() {
					family = windows.AF_INET
				}
				for _, link := range interfaces {
					if row.Luid != link.luid || family != link.family {
						continue
					}
					if addr.Is6() && addr.IsLinkLocalUnicast() {
						addr = addr.WithZone(strconv.FormatUint(uint64(link.index), 10))
					}
					servers = append(servers, controlDNSServer{netip.AddrPortFrom(addr, 53), link.index, link.metric})
					break
				}
			}
		}
		slices.SortStableFunc(servers, func(a, b controlDNSServer) int {
			if a.metric < b.metric {
				return -1
			}
			if a.metric > b.metric {
				return 1
			}
			return 0
		})
		if len(servers) == 0 {
			return nil, errors.New("no DNS server configured on a usable Windows underlay interface")
		}
		return servers, nil
	}
	return nil, windows.ERROR_BUFFER_OVERFLOW
}
