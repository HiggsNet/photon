package photonwindows

import (
	"context"
	"net"
	"net/netip"
)

type outboundDNSKey struct{}

type outboundDNS interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

func controlDNS(ctx context.Context) outboundDNS {
	if resolver, ok := ctx.Value(outboundDNSKey{}).(outboundDNS); ok {
		return resolver
	}
	return net.DefaultResolver
}

func (s *packetSockets) outerLocal(local, remote netip.AddrPort) (netip.AddrPort, error) {
	if s != nil {
		source, err := s.outboundRoutes.ikeSource(remote.Addr())
		if err != nil {
			return netip.AddrPort{}, err
		}
		if source.IsValid() {
			return netip.AddrPortFrom(source, local.Port()), nil
		}
	}
	return outboundUDPLocal(local, remote)
}
