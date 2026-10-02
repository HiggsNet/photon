package photonwindows

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"reflect"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	corestate "github.com/HiggsNet/photon/pkg/core/state"
)

// RunConsole owns the common state and gossip resources until cancellation.
// It restores an existing database; it does not provision identity or a tunnel.
func RunConsole(ctx context.Context, config *Config, logger *slog.Logger) (err error) {
	if config == nil {
		return errors.New("Windows config is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if logger == nil {
		logger = slog.Default()
	}
	listenAddr, err := netip.ParseAddrPort(config.GossipListen)
	if err != nil {
		return fmt.Errorf("gossip_listen: %w", err)
	}
	state, err := OpenState(config.State.Path, config.ManagedZone, config.TrustedRootPublicKey, time.Second)
	if err != nil {
		return err
	}
	defer func() { err = errors.Join(err, state.Close()) }()
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	bootstrap := make(map[string]*net.UDPAddr)
	var peers []string
	for _, hint := range config.Gateway.BootstrapHints {
		host, port, err := net.SplitHostPort(hint.Address)
		if err != nil {
			return err
		}
		resolveCtx, resolveCancel := context.WithTimeout(ctx, 5*time.Second)
		family := "ip6"
		if listenAddr.Addr().Is4() {
			family = "ip4"
		}
		addresses, err := net.DefaultResolver.LookupNetIP(resolveCtx, family, host)
		resolveCancel()
		if err != nil {
			return fmt.Errorf("resolve bootstrap %s: %w", hint.Peer, err)
		}
		if len(addresses) == 0 {
			return fmt.Errorf("bootstrap %s has no addresses", hint.Peer)
		}
		addr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(addresses[0].String(), port))
		if err != nil {
			return err
		}
		bootstrap[string(hint.Peer)] = addr
		peers = append(peers, string(hint.Peer))
	}
	driver := corehost.NewGossipDriver(nil, 0, state.Store(), corehost.GossipDriverConfig{
		PeerID: string(config.ManagedZone), Limits: corestate.DefaultSyncLimits(),
		Discovery: corehost.GossipDiscoveryConfig{Bootstrap: bootstrap, BootstrapPeers: peers},
		Log: func(record corehost.GossipDriverLog) {
			level := slog.LevelDebug
			switch record.Level {
			case "info":
				level = slog.LevelInfo
			case "warn":
				level = slog.LevelWarn
			case "error":
				level = slog.LevelError
			}
			attrs := []any{"peer", record.PeerID, "phase", record.Phase}
			if record.Err != nil {
				attrs = append(attrs, "error", record.Err)
			}
			for key, value := range record.Fields {
				attrs = append(attrs, key, value)
			}
			logger.Log(ctx, level, record.Event, attrs...)
		},
	})
	defer driver.Stop()
	listen := net.ListenConfig{}
	packet, err := listen.ListenPacket(ctx, "udp", config.GossipListen)
	if err != nil {
		return fmt.Errorf("listen gossip UDP: %w", err)
	}
	defer packet.Close()
	transport, err := gossip.NewTransport(gossip.Config{PeerID: string(config.ManagedZone), KnownPeers: bootstrap}, &gossipDatagram{packet.(*net.UDPConn)})
	if err != nil {
		return err
	}
	listener, err := listen.Listen(ctx, "tcp", packet.LocalAddr().String())
	if err != nil {
		return fmt.Errorf("listen gossip object-pull: %w", err)
	}
	defer listener.Close()
	if err := driver.StartGossipObjectPullServer(ctx, listener, 0, 0); err != nil {
		return err
	}
	executor := corehost.NewGossipObjectPullExecutor(corehost.GossipObjectPullExecutorConfig{
		Client: objectPullClient{}, Discovery: func() corehost.GossipDiscoveryInput { return driver.GossipDiscoveryInput(nil) },
	})
	if err := driver.StartGossipObjectPullWorkers(ctx, executor, 0, 0); err != nil {
		return err
	}
	if err := driver.RefreshGossipDiscovery(ctx, nil, time.Now(), transport); err != nil {
		return err
	}
	if err := driver.StartGossipTransport(ctx, transport, func(err error) { logger.Warn("gossip_receive_failed", "error", err) }); err != nil {
		return err
	}
	logger.Info("gossip_started", "address", packet.LocalAddr().String(), "zone", config.ManagedZone, "tunnel_ready", false)
	var lastGateways []GatewayCandidate
	observeGateways := func() {
		view := state.Store().ReadView()
		now := time.Now()
		candidates := GatewayCandidates(config, view, now)
		if !reflect.DeepEqual(lastGateways, candidates) {
			logger.Info("gateway_candidates_changed", "revision", view.Revision, "evaluated_at", now,
				"candidates", candidates, "tunnel_ready", false, "route_authorized", false)
			lastGateways = candidates
		}
	}
	observeGateways()
	syncPeers := func() {
		if _, err := driver.SyncGossipPeers(ctx, time.Now(), nil, false); err != nil && ctx.Err() == nil {
			logger.Warn("gossip_sync_failed", "error", err)
		}
	}
	syncPeers()
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			observeGateways()
			if err := driver.RefreshGossipDiscovery(ctx, nil, time.Now(), transport); err != nil {
				if ctx.Err() != nil {
					return nil
				}
				return fmt.Errorf("refresh gossip discovery: %w", err)
			}
			syncPeers()
		case event := <-driver.Events():
			before := state.Store().VerifiedRevision()
			if _, err := driver.HandleGossipHostEvent(ctx, event, time.Now(), nil); err != nil && !errors.Is(err, corehost.ErrGossipSessionNotFound) && ctx.Err() == nil {
				logger.Warn("gossip_event_failed", "error", err)
			}
			if state.Store().VerifiedRevision() != before {
				observeGateways()
			}
		}
	}
}

type gossipDatagram struct{ *net.UDPConn }

func (d *gossipDatagram) ReadDatagram(b []byte) (int, *net.UDPAddr, error) { return d.ReadFromUDP(b) }
func (d *gossipDatagram) WriteDatagram(b []byte, a *net.UDPAddr) (int, error) {
	if err := d.SetWriteDeadline(time.Now().Add(time.Second)); err != nil {
		return 0, err
	}
	return d.WriteToUDP(b, a)
}
func (d *gossipDatagram) LocalAddr() *net.UDPAddr { return d.UDPConn.LocalAddr().(*net.UDPAddr) }

type objectPullClient struct{}

func (objectPullClient) Exchange(ctx context.Context, addr string, request *gossip.ObjectPullRequest) (*gossip.ObjectPullResponse, error) {
	conn, err := (&net.Dialer{Timeout: 1500 * time.Millisecond}).DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		return nil, err
	}
	return gossip.ExchangeObjectPull(conn, request)
}
