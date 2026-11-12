package main

import (
	"context"
	"errors"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/HiggsNet/photon/pkg/core/gossip"
	corehost "github.com/HiggsNet/photon/pkg/core/host"
	"github.com/HiggsNet/photon/pkg/core/zone"
)

func listenPortFromAddr(addr string) uint16 {
	_, portStr, err := net.SplitHostPort(addr)
	if err != nil {
		return uint16(gossip.DefaultPort)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port <= 0 || port > 65535 {
		return uint16(gossip.DefaultPort)
	}
	return uint16(port)
}

type endpointDiscoveryResult struct {
	PublicIPs []net.IP
	Error     error
}

// All lifecycle fields are owned by the main loop. The worker only collects
// candidates and sends one result, without retaining a state snapshot.
func (d *Daemon) startEndpointDiscovery(ctx context.Context) bool {
	if d.endpointResults != nil {
		return true
	}
	if d.Config == nil || !d.Config.PublishEndpoints || ctx.Err() != nil {
		return false
	}
	verified := d.State.Common.ReadView().State
	if verified == nil || verified.Network == nil || verified.ManagedZone == zone.RootZone || len(verified.IdentityPrivateKey) == 0 || gossip.AutoJoinPending(verified) {
		return false
	}
	port := listenPortFromAddr(d.Config.ListenAddr)
	_, reflectors := filterEndpointDiscoveryInputs(d.Config, port)
	if len(reflectors) == 0 {
		return false
	}
	reflectors = append([]string(nil), reflectors...)
	timeout := d.Config.ReflectorTimeout
	if timeout <= 0 {
		timeout = 3 * time.Second
	}
	queryCtx, cancel := context.WithTimeout(ctx, timeout)
	results := make(chan endpointDiscoveryResult, 1)
	d.endpointResults, d.endpointCancel = results, cancel
	go func() {
		defer close(results)
		defer cancel()
		ips, err := gossip.QueryPublicIPs(queryCtx, reflectors, http.DefaultClient)
		results <- endpointDiscoveryResult{PublicIPs: ips, Error: err}
	}()
	return true
}

func (d *Daemon) stopEndpointDiscovery() {
	if d.endpointResults == nil {
		return
	}
	d.endpointCancel()
	for range d.endpointResults {
	}
	d.endpointResults, d.endpointCancel = nil, nil
}

func (d *Daemon) endpointRefreshInterval() time.Duration {
	if d.Config != nil && d.Config.ReflectorInterval > 0 {
		return d.Config.ReflectorInterval
	}
	return 5 * time.Minute
}

func (d *Daemon) localEndpointCandidates(publicIPs []net.IP) []gossip.LocalEndpoint {
	port := listenPortFromAddr(d.Config.ListenAddr)
	advertiseAddrs, reflectors := filterEndpointDiscoveryInputs(d.Config, port)
	if len(reflectors) == 0 {
		publicIPs = nil
	}
	return gossip.CollectLocalEndpoints(port, advertiseAddrs, publicIPs, d.Config.FilterPrivateIPv4)
}

func (d *Daemon) handleEndpointDiscoveryResult(ctx context.Context, result endpointDiscoveryResult) (bool, error) {
	d.stopEndpointDiscovery()
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if result.Error != nil {
		d.logWarn("endpoint", "reflector_failed", map[string]any{"error": result.Error})
	}
	changed, err := d.publishLocalEndpoints(d.localEndpointCandidates(result.PublicIPs))
	if err != nil {
		return changed, err
	}
	// IPsec consumes the newly committed endpoint record in this same event.
	published, err := d.publishLocalProtocols()
	return changed || published, err
}

func (d *Daemon) publishLocalEndpoints(endpoints []gossip.LocalEndpoint) (bool, error) {
	config := d.Config
	if config == nil {
		return false, errors.New("gossip configuration is not initialized")
	}
	intent, err := corehost.PlanGossipEndpointIntent(corehost.GossipEndpointIntentInput{
		Verified: d.State.Common.ReadView().State, Disabled: !config.PublishEndpoints,
		Endpoints: endpoints, Now: d.now(),
		TTL: config.EndpointTTL, Grace: config.EndpointGrace, Refresh: config.EndpointRefresh,
	})
	if err != nil || intent == nil {
		return false, err
	}
	result, err := d.State.Common.ApplyLocalIntent(context.Background(), *intent, d.now())
	if result.Committed {
		d.refreshGossipDiscovery()
		d.notifyStateChanged()
	}
	return result.Committed, err
}

// filterEndpointDiscoveryInputs returns the advertise addresses and reflectors
// to use when publishing local endpoints, respecting the endpoint_discovery
// configuration. loopback_only suppresses public IP reflectors and interface
// scans, keeping only loopback addresses and explicit loopback advertise_addrs.
// advertise_only uses only explicit advertise_addrs.
//
// When endpoint_discovery is unset, the daemon auto-detects loopback-only test
// deployments: if every configured bootstrap peer uses a loopback address, it
// behaves like loopback_only to avoid publishing unreachable public IPs that
// would starve loopback bootstrap paths.
func filterEndpointDiscoveryInputs(config *appConfig, port uint16) (advertiseAddrs, reflectors []string) {
	mode := strings.ToLower(strings.TrimSpace(config.EndpointDiscovery))
	if mode == "" && allBootstrapAddrsLoopback(config.Bootstrap) {
		mode = "loopback_only"
	}
	switch mode {
	case "advertise_only":
		return config.AdvertiseAddrs, nil
	case "loopback_only":
		for _, addr := range config.AdvertiseAddrs {
			if host, _, err := net.SplitHostPort(addr); err == nil && isLoopbackIP(host) {
				advertiseAddrs = append(advertiseAddrs, addr)
			}
		}
		// Derive loopback endpoints from listen_addr. If listen_addr is not a
		// specific loopback address, fall back to the well-known loopback IPs.
		if host, _, err := net.SplitHostPort(config.ListenAddr); err == nil && isLoopbackIP(host) {
			advertiseAddrs = append(advertiseAddrs, net.JoinHostPort(host, strconv.Itoa(int(port))))
		} else {
			advertiseAddrs = append(advertiseAddrs, net.JoinHostPort("127.0.0.1", strconv.Itoa(int(port))))
			advertiseAddrs = append(advertiseAddrs, net.JoinHostPort("::1", strconv.Itoa(int(port))))
		}
		return advertiseAddrs, nil
	case "", "all":
		return config.AdvertiseAddrs, config.Reflectors
	default:
		return config.AdvertiseAddrs, config.Reflectors
	}
}

func allBootstrapAddrsLoopback(peers []syncConfigPeer) bool {
	if len(peers) == 0 {
		return false
	}
	for _, peer := range peers {
		if peer.Addr == "" {
			return false
		}
		host, _, err := net.SplitHostPort(peer.Addr)
		if err != nil {
			host = peer.Addr
		}
		if !isLoopbackIP(host) {
			return false
		}
	}
	return true
}

func isLoopbackIP(host string) bool {
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}
