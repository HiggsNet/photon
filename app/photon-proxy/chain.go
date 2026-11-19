package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

const (
	chainAuthority   = "_photon_relay_chain"
	chainRouteHeader = "Photon-Relay-Route"
	chainRouteLimit  = 4096
	chainHopLimit    = 8
)

type chainSelector struct {
	zone zone.ZonePath
	name string
}

func parseChainSelector(value string) (chainSelector, error) {
	path, name, ok := strings.Cut(value, "/")
	selector := chainSelector{zone: zone.ZonePath(path), name: name}
	if !ok || !selector.zone.Valid() || strings.ContainsAny(path, ",= \t\r\n\x00") || !service.ProxyEndpointNameValid(name) {
		return chainSelector{}, fmt.Errorf("invalid chain hop %q, expected Zone/public-v4, Zone/public-v6 or Zone/photon", value)
	}
	return selector, nil
}

type chainHop struct {
	chainSelector
	address string
}

func parseChainRoute(value string) ([]chainHop, error) {
	if value == "" || len(value) > chainRouteLimit || strings.Count(value, ",") >= chainHopLimit {
		return nil, errDenied
	}
	var hops []chainHop
	for item := range strings.SplitSeq(value, ",") {
		selector, address, ok := strings.Cut(item, "=")
		path, err := parseChainSelector(selector)
		if !ok || err != nil || service.ValidateProxyEndpoint(path.name, address) != nil {
			return nil, errDenied
		}
		hops = append(hops, chainHop{chainSelector: path, address: address})
	}
	return hops, nil
}

// A resolves selected endpoints before signing. Receivers check those exact
// endpoints against their current verified directory before forwarding.
func resolveChain(directory *proxyDirectory, origin zone.ZonePath, hops []chainHop) ([]chainHop, []proxyPeer, error) {
	if len(hops) == 0 || len(hops) > chainHopLimit {
		return nil, nil, errors.New("invalid proxy chain length")
	}
	seen := map[zone.ZonePath]bool{origin: true}
	resolved := slices.Clone(hops)
	peers := make([]proxyPeer, 0, len(hops))
	for index, hop := range hops {
		if seen[hop.zone] {
			return nil, nil, fmt.Errorf("repeated Zone %s in proxy chain", hop.zone)
		}
		seen[hop.zone] = true
		value, ok := directory.peer(hop.zone)
		address := value.Endpoints[hop.name]
		role := proxyRelay
		if index == len(hops)-1 {
			role = proxyExit
		}
		peer := proxyPeer{zone: hop.zone, pin: value.SPKI, role: role}
		if !ok || value.SPKI == "" || !peer.matches(value) || address == "" || (hop.address != "" && hop.address != address) {
			return nil, nil, fmt.Errorf("no matching %s endpoint for Zone %s", hop.name, hop.zone)
		}
		resolved[index].address = address
		peers = append(peers, peer)
	}
	return resolved, peers, nil
}

func watchChain(ctx context.Context, directory *proxyDirectory, peers []proxyPeer) (context.Context, func(), bool) {
	releases := make([]func(), 0, len(peers))
	release := func() {
		for _, stop := range releases {
			stop()
		}
	}
	for _, peer := range peers {
		watched, stop, ok := directory.watch(ctx, peer)
		if !ok {
			release()
			return ctx, func() {}, false
		}
		ctx = watched
		releases = append(releases, stop)
	}
	return ctx, release, true
}

type chainPool struct {
	tls          *tls.Config
	publicDevice string
	photonDevice string
	mu           sync.Mutex
	clients      map[chainSelector]chainConnection
}

type chainConnection struct {
	address string
	pin     string
	tunnel  *tunnelClient
}

func newChainPool(ca, publicDevice, photonDevice string) (*chainPool, error) {
	if ca == "" {
		return nil, errors.New("signed chain dialing requires a peer server CA")
	}
	roots, err := loadPeerCA(ca)
	if err != nil {
		return nil, err
	}
	return &chainPool{
		tls:          &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots},
		publicDevice: publicDevice, photonDevice: photonDevice,
	}, nil
}

func (p *chainPool) client(hop chainHop, pin string) *tunnelClient {
	p.mu.Lock()
	defer p.mu.Unlock()
	previous := p.clients[hop.chainSelector]
	if previous.tunnel != nil {
		if previous.address == hop.address && previous.pin == pin {
			return previous.tunnel
		}
		previous.tunnel.closeIdleConnections()
	}
	network, device := "tcp", p.publicDevice
	switch hop.name {
	case "public-v4":
		network = "tcp4"
	case "public-v6":
		network = "tcp6"
	case "photon":
		device = p.photonDevice
	}
	dialer := net.Dialer{Timeout: setupTimeout}
	if device != "" {
		dialer.Control = bindChainDevice(device)
	}
	config := pinnedProxyTLS(p.tls, service.ProxyCapability{Address: hop.address, SPKI: pin})
	client := newTunnelClientWithRelay(hop.address, config, func(ctx context.Context) (net.Conn, error) {
		return dialer.DialContext(ctx, network, hop.address)
	})
	if p.clients == nil {
		p.clients = make(map[chainSelector]chainConnection)
	}
	p.clients[hop.chainSelector] = chainConnection{address: hop.address, pin: pin, tunnel: client}
	return client
}

func (p *chainPool) closeIdleConnections() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, client := range p.clients {
		client.tunnel.closeIdleConnections()
	}
}

type chainClient struct {
	directory *proxyDirectory
	hops      []chainHop
	key       ed25519.PrivateKey
	udp       string
	pool      *chainPool
}

func (c *chainClient) open(ctx context.Context, target string) (*tunnelStream, error) {
	origin := c.directory.managedZone()
	value, ok := c.directory.peer(origin)
	public := delegationEncoding.EncodeToString(c.key.Public().(ed25519.PublicKey))
	if !ok || value.DelegationKey != public {
		return nil, errors.New("local Zone has no matching delegation key")
	}
	hops, peers, err := resolveChain(c.directory, origin, c.hops)
	if err != nil {
		return nil, err
	}
	encoded := make([]string, 0, len(hops))
	for _, hop := range hops {
		encoded = append(encoded, hop.zone.String()+"/"+hop.name+"="+hop.address)
	}
	route := strings.Join(encoded, ",")
	if len(route) > chainRouteLimit {
		return nil, errors.New("proxy chain exceeds the route header budget")
	}
	var scope string
	if target == trusttunnel.UDPAuthority {
		scope = c.udp
		if scope == "" {
			return nil, errors.New("delegated UDP needs an explicit prefix scope")
		}
	}
	grant, err := issueDelegation(c.key, origin, delegationBinding{route: route, target: target}, scope, time.Now())
	if err != nil {
		return nil, err
	}
	ctx, release, ok := watchChain(ctx, c.directory, append(peers, proxyPeer{zone: origin, pin: value.SPKI, delegationKey: public}))
	if !ok {
		return nil, errDenied
	}
	stream, err := c.pool.client(hops[0], peers[0].pin).connect(ctx, chainAuthority, chainHeaders(route, target, grant), target == trusttunnel.UDPAuthority)
	if err != nil {
		release()
		return nil, err
	}
	cancel := stream.cancel
	stream.cancel = func() { cancel(); release() }
	return stream, nil
}

func chainHeaders(route, target, grant string) http.Header {
	return http.Header{chainRouteHeader: {route}, delegationTarget: {target}, delegationHeader: {grant}}
}

type chainServer struct {
	directory *proxyDirectory
	origins   []zone.ZonePath
	local     map[string]string
	next      map[chainSelector]struct{}
	pool      *chainPool
	replay    delegationVerifier
}

func configureChainServer(ctx context.Context, socket, origins, allowed, ca, publicDevice, photonDevice string, local map[string]string, next map[chainSelector]struct{}) (*chainServer, []netip.Prefix, error) {
	if socket == "" || origins == "" {
		return nil, nil, errors.New("-chain-endpoint requires -directory-socket and -allow-zones")
	}
	allowedOrigins, err := parseProxyZones(origins)
	if err != nil {
		return nil, nil, err
	}
	s := &chainServer{local: local, origins: allowedOrigins, next: next}
	var prefixes []netip.Prefix
	if len(next) == 0 {
		if ca != "" || publicDevice != "" || photonDevice != "" {
			return nil, nil, errors.New("outgoing chain settings require -chain-next")
		}
		prefixes, err = parseAllowed(allowed)
	} else {
		if allowed != "" {
			return nil, nil, errors.New("-allow is for chain exits, use -chain-next for a relay")
		}
		s.pool, err = newChainPool(ca, publicDevice, photonDevice)
	}
	if err != nil {
		return nil, nil, err
	}
	s.directory, err = openProxyDirectory(ctx, socket)
	if err != nil {
		return nil, nil, fmt.Errorf("read proxy directory: %w", err)
	}
	return s, prefixes, nil
}

func (h *tunnelHandler) serveChain(w http.ResponseWriter, r *http.Request) {
	s := h.chain
	routes, targets, grants := r.Header.Values(chainRouteHeader), r.Header.Values(delegationTarget), r.Header.Values(delegationHeader)
	if r.TLS == nil || r.Host != chainAuthority || len(routes) != 1 || len(targets) != 1 || len(grants) != 1 {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	select {
	case h.slots <- struct{}{}:
		defer func() { <-h.slots }()
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	route, target, ticket := routes[0], targets[0], grants[0]
	hops, err := parseChainRoute(route)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	local := s.directory.managedZone()
	index := slices.IndexFunc(hops, func(hop chainHop) bool { return hop.zone == local })
	if index < 0 || s.local[hops[index].name] != hops[index].address || (s.pool == nil) != (index == len(hops)-1) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	now := time.Now()
	grant, payload, signature, err := decodeDelegation(ticket)
	issued := time.Unix(0, grant.Issued)
	expires := issued.Add(delegationLifetime)
	if err != nil || !slices.Contains(s.origins, grant.Source) || issued.After(now.Add(2*time.Second)) ||
		!expires.After(now) || issued.Before(s.replay.started) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	origin, ok := s.directory.peer(grant.Source)
	public, keyErr := delegationEncoding.DecodeString(origin.DelegationKey)
	binding := delegationBinding{route: route, target: target}
	if !ok || keyErr != nil || len(public) != ed25519.PublicKeySize || delegationKeyID(public) != grant.KeyID ||
		!ed25519.Verify(public, binding.input(payload), signature) {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	var scope []netip.Prefix
	udp := target == trusttunnel.UDPAuthority
	if udp {
		scope, err = parseAllowed(grant.UDP)
	} else if grant.UDP != "" {
		err = errDenied
	} else {
		_, err = splitTarget(target)
	}
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	_, peers, err := resolveChain(s.directory, grant.Source, hops)
	if err != nil {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	ctx, release, ok := watchChain(r.Context(), s.directory, append(peers, proxyPeer{zone: grant.Source, pin: origin.SPKI, delegationKey: origin.DelegationKey}))
	if !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	defer release()
	r = r.WithContext(ctx)
	if s.pool == nil {
		if !s.replay.consume(delegationNonce{source: grant.Source, id: grant.Nonce}, now, expires) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		h.serveDestination(w, r, target, scope)
		return
	}
	next := hops[index+1]
	if _, ok := s.next[next.chainSelector]; !ok {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	stream, err := s.pool.client(next, peers[index+1].pin).connect(ctx, chainAuthority, chainHeaders(route, target, ticket), udp)
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errDenied) {
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
		return
	}
	serveTCPStream(w, r, stream)
}
