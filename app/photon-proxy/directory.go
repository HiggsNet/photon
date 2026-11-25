package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"slices"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/service"
)

const (
	directoryRefresh = time.Minute
	directoryTimeout = time.Second
	directoryRetry   = 5 * time.Second
)

type proxyPeer struct {
	zone          zone.ZonePath
	pin           string
	role          proxyRole
	delegationKey string
}

type proxyRole uint8

const (
	proxyIdentity proxyRole = iota
	proxyExit
	proxyRelay
)

func (p proxyPeer) matches(value service.ProxyCapability) bool {
	if p.pin != value.SPKI || (p.delegationKey != "" && p.delegationKey != value.DelegationKey) {
		return false
	}
	if p.role == proxyIdentity {
		return true
	}
	return (value.Address != "" || len(value.Endpoints) != 0) && value.Transport == service.ProxyTransport && value.Relay == (p.role == proxyRelay)
}

type watchedSession struct {
	peer   proxyPeer
	cancel context.CancelFunc
}

type proxyDirectory struct {
	mu         sync.Mutex
	view       service.ProxyDirectory
	sessions   map[*watchedSession]struct{}
	v2Sessions map[*watchedV2Session]struct{}
}

func openProxyDirectory(ctx context.Context, socket string) (*proxyDirectory, error) {
	return openProxyDirectoryWithRefresh(ctx, socket, directoryRefresh)
}

func openProxyDirectoryWithRefresh(ctx context.Context, socket string, refresh time.Duration) (*proxyDirectory, error) {
	request := service.ProxyReadRequest{Kind: service.ProxyReadDirectory}
	reply, err := readProxyData(ctx, socket, request)
	if err != nil {
		return nil, err
	}
	if reply.Network == nil || !reply.ManagedZone.Valid() {
		return nil, errors.New("proxy daemon did not provide a directory snapshot")
	}
	now := time.Now()
	cache := directoryCache{source: reply}
	cache.refresh(refresh, now)
	directory := &proxyDirectory{view: cache.view, sessions: make(map[*watchedSession]struct{})}
	go directory.run(ctx, socket, refresh, &cache)
	return directory, nil
}

type directoryCache struct {
	source    service.ProxyReadResponse
	view      service.ProxyDirectory
	verifier  photoncrypto.Verifier
	expiry    time.Time
	checkedAt time.Time
	boundary  time.Time
}

func (c *directoryCache) refresh(interval time.Duration, now time.Time) {
	c.expiry = now.Add(interval).Add(directoryRetry)
	c.rebuild(now)
}

func (c *directoryCache) rebuild(now time.Time) {
	c.view = buildProxyDirectory(c.source.Network, now, &c.verifier)
	c.view.ManagedZone = c.source.ManagedZone
	c.view.V2, c.view.MeshPrefixes = buildProxyV2Directory(c.source.Network, c.source.ManagedZone, now, &c.verifier)
	c.checkedAt = now
	c.boundary = nextDirectoryBoundary(c.source.Network, now)
	c.setLifetime()
}

func (c *directoryCache) setLifetime() {
	c.view.ValidUntil = c.expiry
	if !c.boundary.IsZero() && c.boundary.Before(c.expiry) {
		c.view.ValidUntil = c.boundary
	}
}

func (d *proxyDirectory) run(ctx context.Context, socket string, refresh time.Duration, cache *directoryCache) {
	nextRefresh := cache.checkedAt.Add(refresh)
	timer := time.NewTimer(0)
	defer timer.Stop()
	defer d.update(&service.ProxyDirectory{}, time.Time{})
	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
		}
		now := time.Now()
		rebuild := now.Before(cache.checkedAt) || !cache.boundary.IsZero() && !now.Before(cache.boundary)
		if !now.Before(nextRefresh) {
			request := service.ProxyReadRequest{Kind: service.ProxyReadDirectory, Epoch: cache.source.Epoch, Revision: cache.source.Revision}
			reply, err := readProxyData(ctx, socket, request)
			now = time.Now()
			switch {
			case err == nil && reply.Network != nil && reply.ManagedZone.Valid():
				cache.source = reply
				cache.refresh(refresh, now)
				rebuild = false
				nextRefresh = now.Add(refresh)
			case err == nil && reply.Network == nil && reply.Epoch == request.Epoch && reply.Revision == request.Revision:
				cache.expiry = now.Add(refresh).Add(directoryRetry)
				nextRefresh = now.Add(refresh)
			default:
				nextRefresh = now.Add(min(directoryRetry, refresh))
			}
		}
		if rebuild || !cache.boundary.IsZero() && !now.Before(cache.boundary) {
			cache.rebuild(now)
		} else {
			cache.setLifetime()
		}
		d.update(&cache.view, now)
		next := nextRefresh
		if cache.view.ValidUntil.After(now) && cache.view.ValidUntil.Before(next) {
			next = cache.view.ValidUntil
		}
		timer.Reset(time.Until(next))
	}
}

func readProxyData(ctx context.Context, socket string, request service.ProxyReadRequest) (service.ProxyReadResponse, error) {
	var reply service.ProxyReadResponse
	ctx, cancel := context.WithTimeout(ctx, directoryTimeout)
	defer cancel()
	conn, err := (&net.Dialer{}).DialContext(ctx, "unix", socket)
	if err != nil {
		return reply, err
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stop()
	if err := json.NewEncoder(conn).Encode(request); err != nil {
		return reply, err
	}
	data, err := io.ReadAll(io.LimitReader(conn, service.ProxyReadMaxBytes))
	if err != nil {
		return reply, err
	}
	if len(data) == service.ProxyReadMaxBytes {
		return reply, errors.New("proxy read response exceeds size limit")
	}
	if err := json.Unmarshal(data, &reply); err != nil {
		return reply, err
	}
	if reply.Epoch == "" {
		return reply, errors.New("proxy daemon does not support versioned read requests")
	}
	return reply, nil
}

func (d *proxyDirectory) record(path zone.ZonePath, now time.Time) (service.ProxyCapability, bool) {
	value, ok := d.view.Peers[path]
	return value, ok && value.Active && value.ExpiresAt.After(now) && d.view.ValidUntil.After(now)
}

func (d *proxyDirectory) peer(path zone.ZonePath) (service.ProxyCapability, bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.record(path, time.Now())
}

func (d *proxyDirectory) managedZone() zone.ZonePath {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.view.ManagedZone
}

func (d *proxyDirectory) watch(ctx context.Context, peer proxyPeer) (context.Context, func(), bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	value, ok := d.record(peer.zone, time.Now())
	if !ok || !peer.matches(value) {
		return ctx, func() {}, false
	}
	ctx, cancel := context.WithCancel(ctx)
	session := &watchedSession{peer: peer, cancel: cancel}
	d.sessions[session] = struct{}{}
	return ctx, func() {
		cancel()
		d.mu.Lock()
		delete(d.sessions, session)
		d.mu.Unlock()
	}, true
}

// Apply only a complete view. On read failure an existing view can be used
// until its short local deadline, after which its sessions are closed.
func (d *proxyDirectory) update(view *service.ProxyDirectory, now time.Time) {
	d.mu.Lock()
	defer d.mu.Unlock()
	if view != nil {
		d.view = *view
	}
	for session := range d.sessions {
		value, ok := d.record(session.peer.zone, now)
		if !ok || !session.peer.matches(value) {
			delete(d.sessions, session)
			session.cancel()
		}
	}
	for session := range d.v2Sessions {
		if !d.view.ValidUntil.After(now) || !session.valid(d.view, now) {
			delete(d.v2Sessions, session)
			session.cancel()
		}
	}
}

type zoneAccess struct {
	directory *proxyDirectory
	allowed   []zone.ZonePath
	delegates []zone.ZonePath
}

func (a *zoneAccess) match(cert *x509.Certificate) (proxyPeer, bool) {
	now := time.Now()
	if now.Before(cert.NotBefore) || !cert.NotAfter.After(now) {
		return proxyPeer{}, false
	}
	pin := service.ProxyPublicKeyID(cert)
	a.directory.mu.Lock()
	defer a.directory.mu.Unlock()
	for _, paths := range [][]zone.ZonePath{a.allowed, a.delegates} {
		for _, path := range paths {
			if value, ok := a.directory.record(path, now); ok && value.SPKI == pin {
				return proxyPeer{zone: path, pin: pin}, true
			}
		}
	}
	return proxyPeer{}, false
}

func (a *zoneAccess) verify(state tls.ConnectionState) error {
	if len(state.PeerCertificates) > 0 {
		if _, ok := a.match(state.PeerCertificates[0]); ok {
			return nil
		}
	}
	return errors.New("client certificate is not bound to an allowed Photon Zone")
}

type zoneTunnelClient struct {
	directory       *proxyDirectory
	zone            zone.ZonePath
	via             zone.ZonePath
	relayServerName string
	tls             *tls.Config
	auth            string
	delegation      ed25519.PrivateKey
	delegationUDP   string
	mu              sync.Mutex
	address         string
	pin             string
	relayAddress    string
	relayPin        string
	client          *tunnelClient
	outer           *tunnelClient
}

func (c *zoneTunnelClient) open(ctx context.Context, target string) (*tunnelStream, error) {
	value, ok := c.directory.peer(c.zone)
	if !ok || value.Relay || value.Address == "" || value.Transport != service.ProxyTransport {
		return nil, errors.New("selected Zone has no active TrustTunnel endpoint")
	}
	var relay service.ProxyCapability
	if c.via != "" {
		relay, ok = c.directory.peer(c.via)
		if !ok || !relay.Relay || relay.Address == "" || relay.Transport != service.ProxyTransport {
			return nil, errors.New("selected relay Zone has no active relay endpoint")
		}
	}
	ctx, release, ok := c.directory.watch(ctx, proxyPeer{zone: c.zone, pin: value.SPKI, role: proxyExit})
	if !ok {
		return nil, errors.New("selected Zone's TrustTunnel identity changed")
	}
	if c.via != "" {
		relayContext, releaseRelay, ok := c.directory.watch(ctx, proxyPeer{zone: c.via, pin: relay.SPKI, role: proxyRelay})
		if !ok {
			release()
			return nil, errors.New("selected relay's identity changed")
		}
		releaseExit := release
		release = func() {
			releaseRelay()
			releaseExit()
		}
		ctx = relayContext
	}
	client := c.transportFor(value, relay)
	var stream *tunnelStream
	var err error
	if len(c.delegation) != 0 {
		stream, err = c.openDelegated(ctx, client, value.Address, target)
	} else {
		stream, err = client.open(ctx, target)
	}
	if err != nil {
		release()
		return nil, err
	}
	cancel := stream.cancel
	stream.cancel = func() {
		cancel()
		release()
	}
	return stream, nil
}

func (c *zoneTunnelClient) openDelegated(ctx context.Context, relay *tunnelClient, endpoint, target string) (*tunnelStream, error) {
	source := c.directory.managedZone()
	value, ok := c.directory.peer(source)
	key := delegationEncoding.EncodeToString(c.delegation.Public().(ed25519.PublicKey))
	if !ok || value.DelegationKey != key || slices.Contains([]zone.ZonePath{c.via, c.zone}, source) {
		return nil, errors.New("local Zone has no matching delegation key")
	}
	var udp string
	if target == trusttunnel.UDPAuthority {
		udp = c.delegationUDP
		if udp == "" {
			return nil, errors.New("delegated UDP needs an explicit prefix scope")
		}
	}
	grant, err := issueDelegation(c.delegation, source, delegationBinding{relay: c.via, exit: c.zone, endpoint: endpoint, target: target}, udp, time.Now())
	if err != nil {
		return nil, err
	}
	ctx, release, ok := c.directory.watch(ctx, proxyPeer{zone: source, pin: value.SPKI, delegationKey: key})
	if !ok {
		return nil, errDenied
	}
	stream, err := relay.connect(ctx, relayAuthority, http.Header{
		relayZoneHeader: {c.zone.String()}, relayAddressHeader: {endpoint}, delegationTarget: {target}, delegationHeader: {grant},
	}, target == trusttunnel.UDPAuthority)
	if err != nil {
		release()
		return nil, err
	}
	cancel := stream.cancel
	stream.cancel = func() { cancel(); release() }
	return stream, nil
}

func (c *zoneTunnelClient) transportFor(value, relay service.ProxyCapability) *tunnelClient {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.client != nil && c.address == value.Address && c.pin == value.SPKI &&
		c.relayAddress == relay.Address && c.relayPin == relay.SPKI {
		return c.client
	}
	c.closeIdleLocked()
	var connect func(context.Context) (net.Conn, error)
	if relay.Address != "" {
		config := c.tls.Clone()
		config.ServerName = c.relayServerName
		outer := newTunnelClient(relay.Address, pinnedProxyTLS(config, relay))
		if len(c.delegation) != 0 {
			c.address, c.pin = value.Address, value.SPKI
			c.relayAddress, c.relayPin = relay.Address, relay.SPKI
			c.client = outer
			return outer
		}
		c.outer = outer
		connect = func(ctx context.Context) (net.Conn, error) {
			return c.dialRelay(ctx, outer, relay, value)
		}
	}
	c.address, c.pin = value.Address, value.SPKI
	c.relayAddress, c.relayPin = relay.Address, relay.SPKI
	c.client = newTunnelClientWithRelay(value.Address, pinnedProxyTLS(c.tls, value), connect)
	c.client.authorization = c.auth
	return c.client
}

func pinnedProxyTLS(base *tls.Config, value service.ProxyCapability) *tls.Config {
	config := base.Clone()
	if config.ServerName == "" {
		config.ServerName, _, _ = net.SplitHostPort(value.Address)
	}
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if len(state.PeerCertificates) == 0 || service.ProxyPublicKeyID(state.PeerCertificates[0]) != value.SPKI {
			return errors.New("server certificate does not match the selected Zone public key")
		}
		return nil
	}
	return config
}

func (c *zoneTunnelClient) closeIdleConnections() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closeIdleLocked()
}

func (c *zoneTunnelClient) closeIdleLocked() {
	if c.client != nil {
		c.client.closeIdleConnections()
	}
	if c.outer != nil {
		c.outer.closeIdleConnections()
		c.outer = nil
	}
}
