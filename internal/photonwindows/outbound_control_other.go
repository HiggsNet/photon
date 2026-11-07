//go:build !windows

package photonwindows

import (
	"context"
	"net"
	"net/netip"
)

func newControlDNS() outboundDNS { return net.DefaultResolver }

func (*outboundRouteResolver) ikeSource(netip.Addr) (netip.Addr, error) {
	return netip.Addr{}, nil
}

func (*outboundRouteResolver) dialObjectPull(ctx context.Context, dialer net.Dialer, address string) (net.Conn, error) {
	return dialer.DialContext(ctx, "tcp", address)
}
