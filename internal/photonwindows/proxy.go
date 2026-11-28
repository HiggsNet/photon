package photonwindows

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"time"

	"github.com/HiggsNet/photon/internal/photonproxy"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
	"github.com/HiggsNet/photon/pkg/routing"
	"github.com/HiggsNet/photon/pkg/service"
	"github.com/HiggsNet/photon/pkg/transport/ipsec"
)

func (c *Config) RotateProxy(group string, key bool) error {
	if c.proxyV2 == nil {
		return errors.New("proxy_v2_config is not enabled")
	}
	return c.proxyV2.Rotate(group, key)
}

func (d *Daemon) runProxyV2(ctx context.Context, logger *slog.Logger, store *corestate.Store, direct *proxyDirectHost, resolver *outboundRouteResolver, updates chan<- struct{}) {
	host := photonproxy.Host{
		Read: func(_ context.Context, request service.ProxyReadRequest) (service.ProxyReadResponse, error) {
			switch request.Kind {
			case service.ProxyReadDirectory:
				return readWindowsProxyDirectory(store, d.instanceID, request), nil
			case service.ProxyReadLinks:
				return service.ProxyReadResponse{Links: direct.snapshot()}, nil
			default:
				return service.ProxyReadResponse{}, errors.New("unsupported proxy directory request")
			}
		},
		Publish: func(ctx context.Context, publication service.ProxyV2Publication) error {
			result, err := store.ApplyLocalIntent(ctx, corestate.ProxyV2Intent{Publication: publication}, time.Now())
			if err == nil && result.Committed {
				select {
				case updates <- struct{}{}:
				default:
				}
			}
			return err
		},
		DialDirect: direct.dial, ListenDirect: direct.listen,
		DialPeer: func(ctx context.Context, via, device string, address netip.AddrPort) (net.Conn, error) {
			return dialProxyPeer(ctx, resolver, d.config.Wintun.AdapterName, via, device, address)
		},
		LookupPeer: controlDNS(ctx).LookupNetIP,
		DialExit: func(ctx context.Context, network string, address netip.AddrPort) (net.Conn, error) {
			return dialProxyExit(ctx, resolver, d.config, network, address)
		},
	}
	for ctx.Err() == nil {
		err := d.config.proxyV2.Run(ctx, host)
		if ctx.Err() != nil {
			return
		}
		logger.Warn("proxy_v2_restart", "error", err)
		timer := time.NewTimer(5 * time.Second)
		select {
		case <-ctx.Done():
			timer.Stop()
		case <-timer.C:
		}
	}
}

func readWindowsProxyDirectory(store *corestate.Store, epoch string, request service.ProxyReadRequest) service.ProxyReadResponse {
	response := service.ProxyReadResponse{Epoch: epoch, Revision: uint64(store.VerifiedRevision())}
	if request.Epoch == epoch && request.Revision == response.Revision {
		return response
	}
	view := store.ReadDiscoveryRecordPrefixes("", service.RecordKeyProxy,
		routing.RecordKeyPrefixRoutes, routing.RecordKeyPrefixIPAMAssignments, routing.RecordKeyPrefixIPAMPools,
		ipsec.RecordKeyAddresses)
	if view != nil {
		response.Revision = uint64(view.Revision)
		response.ManagedZone, response.Network = view.ManagedZone, view.Network
	}
	return response
}
