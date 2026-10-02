package photonwindows

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"
)

// resolveGossipBootstrap refreshes discovery hints only, never peer authority.
// The whole list shares a one-second budget so slow DNS cannot hold up the
// gateway planner or consume the next periodic refresh interval.
func resolveGossipBootstrap(ctx context.Context, config *Config, listen netip.AddrPort) (map[string]*net.UDPAddr, error) {
	return resolveGossipBootstrapWith(ctx, config, listen, net.DefaultResolver)
}

type bootstrapResolver interface {
	LookupNetIP(context.Context, string, string) ([]netip.Addr, error)
}

func resolveGossipBootstrapWith(ctx context.Context, config *Config, listen netip.AddrPort, resolver bootstrapResolver) (map[string]*net.UDPAddr, error) {
	ctx, cancel := context.WithTimeout(ctx, time.Second)
	defer cancel()
	bootstrap := make(map[string]*net.UDPAddr)
	family := "ip6"
	if listen.Addr().Is4() {
		family = "ip4"
	}
	for _, hint := range config.Gateway.BootstrapHints {
		host, port, err := net.SplitHostPort(hint.Address)
		if err != nil {
			return nil, err
		}
		addresses, err := resolver.LookupNetIP(ctx, family, host)
		if err != nil {
			return nil, fmt.Errorf("resolve bootstrap %s: %w", hint.Peer, err)
		}
		if len(addresses) == 0 {
			return nil, fmt.Errorf("bootstrap %s has no addresses", hint.Peer)
		}
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addresses[0].String(), port))
		if err != nil {
			return nil, err
		}
		bootstrap[string(hint.Peer)] = addr
	}
	return bootstrap, nil
}
