package photonwindows

import (
	"context"
	"net"
	"net/netip"
)

func dialProxyPeer(ctx context.Context, resolver *outboundRouteResolver, adapter, via, device string, address netip.AddrPort) (net.Conn, error) {
	if via == "photon" && device == "" {
		device = adapter
	}
	var index uint32
	if device != "" {
		iface, err := net.InterfaceByName(device)
		if err != nil {
			return nil, err
		}
		index = uint32(iface.Index)
	} else if resolver != nil {
		path, err := resolver.packetPath(address.Addr(), 1)
		if err != nil {
			return nil, err
		}
		index = path.index
	}
	return dialBoundControl(ctx, net.Dialer{}, "tcp", address, index)
}

func dialProxyExit(ctx context.Context, resolver *outboundRouteResolver, config *Config, network string, address netip.AddrPort) (net.Conn, error) {
	for _, prefix := range config.Overlay.SplitRoutes {
		if prefix.Contains(address.Addr()) {
			iface, err := net.InterfaceByName(config.Wintun.AdapterName)
			if err != nil {
				return nil, err
			}
			return dialBoundControl(ctx, net.Dialer{}, network, address, uint32(iface.Index))
		}
	}
	path, err := resolver.packetPath(address.Addr(), 1)
	if err != nil {
		return nil, err
	}
	return dialBoundControl(ctx, net.Dialer{}, network, address, path.index)
}
