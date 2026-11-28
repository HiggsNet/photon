//go:build !windows

package photonwindows

import (
	"context"
	"net"
	"net/netip"
)

func dialProxyPeer(ctx context.Context, _ *outboundRouteResolver, _, _, _ string, address netip.AddrPort) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, "tcp", address.String())
}

func dialProxyExit(ctx context.Context, _ *outboundRouteResolver, _ *Config, network string, address netip.AddrPort) (net.Conn, error) {
	return (&net.Dialer{}).DialContext(ctx, network, address.String())
}
