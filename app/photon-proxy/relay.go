package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"

	"github.com/HiggsNet/photon/internal/trusttunnel"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

const relayAuthority = "_photon_relay"

const (
	relayZoneHeader    = "Photon-Relay-Zone"
	relayAddressHeader = "Photon-Relay-Endpoint"
)

type relayTarget struct {
	zone    zone.ZonePath
	address string
}

type relayTargets map[relayTarget]struct{}

func (t relayTargets) add(argument string) error {
	name, address, ok := strings.Cut(argument, "=")
	path := zone.ZonePath(name)
	if !ok || !path.Valid() {
		return fmt.Errorf("invalid relay target %q, expected Zone=host:port", argument)
	}
	if _, err := splitTarget(address); err != nil {
		return err
	}
	t[relayTarget{zone: path, address: address}] = struct{}{}
	return nil
}

func (h *tunnelHandler) serveRelay(w http.ResponseWriter, r *http.Request, source zone.ZonePath) {
	if r.Host != relayAuthority || h.access == nil || !source.Valid() {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	paths, addresses := r.Header.Values(relayZoneHeader), r.Header.Values(relayAddressHeader)
	if len(paths) != 1 || len(addresses) != 1 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	next := relayTarget{zone: zone.ZonePath(paths[0]), address: addresses[0]}
	if _, ok := h.relay[next]; !ok || next.zone == source {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	value, ok := h.access.directory.peer(next.zone)
	if !ok || value.Relay || value.Transport != service.ProxyTransport || value.Address != next.address {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	ctx, release, ok := h.access.directory.watch(r.Context(), proxyPeer{zone: next.zone, pin: value.SPKI, role: proxyExit})
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	defer release()
	grants, targets := r.Header.Values(delegationHeader), r.Header.Values(delegationTarget)
	if len(grants) != 0 || len(targets) != 0 {
		if h.delegatedRelay == nil || len(grants) != 1 || len(targets) != 1 {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		grant, _, _, err := decodeDelegation(grants[0])
		if err != nil || grant.Source != source {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		target := targets[0]
		udp := target == trusttunnel.UDPAuthority
		if !udp {
			if _, err := splitTarget(target); err != nil {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
		}
		client := h.delegatedRelay.client(next, value)
		stream, err := client.connect(ctx, target, http.Header{delegationHeader: {grants[0]}}, udp)
		if err != nil {
			status := http.StatusBadGateway
			if errors.Is(err, errDenied) {
				status = http.StatusForbidden
			}
			w.WriteHeader(status)
			return
		}
		serveTCPStream(w, r.WithContext(ctx), stream)
		return
	}
	dialCtx, stopDial := context.WithTimeout(ctx, setupTimeout)
	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", value.Address)
	stopDial()
	if err != nil {
		w.WriteHeader(http.StatusBadGateway)
		return
	}
	serveTCPStream(w, r.WithContext(ctx), conn.(*net.TCPConn))
}

func (c *zoneTunnelClient) dialRelay(ctx context.Context, outer *tunnelClient, relay, exit service.ProxyCapability) (net.Conn, error) {
	// The HTTP transport uses a dial context for setup. Once connected, the
	// inner HTTP/2 connection owns the outer stream and may outlive that dial.
	lifetime, cancel := context.WithCancel(context.WithoutCancel(ctx))
	stopSetup := context.AfterFunc(ctx, cancel)
	defer stopSetup()
	lifetime, release, ok := c.directory.watch(lifetime, proxyPeer{zone: c.via, pin: relay.SPKI, role: proxyRelay})
	if !ok {
		cancel()
		return nil, errors.New("selected relay's identity changed")
	}
	stream, err := outer.connect(lifetime, relayAuthority, http.Header{
		relayZoneHeader:    {c.zone.String()},
		relayAddressHeader: {exit.Address},
	}, false)
	if err != nil || ctx.Err() != nil {
		if stream != nil {
			_ = stream.Close()
		}
		release()
		cancel()
		if err == nil {
			err = ctx.Err()
		}
		return nil, err
	}
	inner, bridge := net.Pipe()
	stopLifetime := context.AfterFunc(lifetime, func() { _ = bridge.Close() })
	closeBridge := sync.OnceFunc(func() {
		_ = bridge.Close()
		stopLifetime()
		_ = stream.Close()
		release()
		cancel()
	})
	go func() {
		defer closeBridge()
		_, _ = io.Copy(stream, bridge)
	}()
	go func() {
		defer closeBridge()
		_, _ = io.Copy(bridge, stream)
	}()
	return inner, nil
}

type relayConnection struct {
	pin    string
	tunnel *tunnelClient
}

type delegatedRelay struct {
	tls   *tls.Config
	mu    sync.Mutex
	exits map[relayTarget]relayConnection
}

func (d *delegatedRelay) client(next relayTarget, value service.ProxyCapability) *tunnelClient {
	d.mu.Lock()
	defer d.mu.Unlock()
	if current, exists := d.exits[next]; exists {
		if current.pin == value.SPKI {
			return current.tunnel
		}
		current.tunnel.closeIdleConnections()
	}
	client := newTunnelClient(value.Address, pinnedProxyTLS(d.tls, value))
	if d.exits == nil {
		d.exits = make(map[relayTarget]relayConnection)
	}
	d.exits[next] = relayConnection{pin: value.SPKI, tunnel: client}
	return client
}

func (d *delegatedRelay) closeIdleConnections() {
	d.mu.Lock()
	defer d.mu.Unlock()
	for _, entry := range d.exits {
		entry.tunnel.closeIdleConnections()
	}
}
