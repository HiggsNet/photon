package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

type watchedV2Session struct {
	valid  func(service.ProxyDirectory, time.Time) bool
	cancel context.CancelFunc
}

func (d *proxyDirectory) snapshotV2() service.ProxyDirectory {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.view
}

func (d *proxyDirectory) watchV2(ctx context.Context, valid func(service.ProxyDirectory, time.Time) bool) (context.Context, func(), bool) {
	d.mu.Lock()
	defer d.mu.Unlock()
	now := time.Now()
	if !d.view.ValidUntil.After(now) || !valid(d.view, now) {
		return ctx, func() {}, false
	}
	ctx, cancel := context.WithCancel(ctx)
	session := &watchedV2Session{valid: valid, cancel: cancel}
	if d.v2Sessions == nil {
		d.v2Sessions = make(map[*watchedV2Session]struct{})
	}
	d.v2Sessions[session] = struct{}{}
	return ctx, func() {
		cancel()
		d.mu.Lock()
		delete(d.v2Sessions, session)
		d.mu.Unlock()
	}, true
}

type v2HopError struct {
	code  string
	index int
	inner error
}

func (e *v2HopError) Error() string {
	if e.inner != nil {
		return fmt.Sprintf("%s at hop %d: %v", e.code, e.index, e.inner)
	}
	return fmt.Sprintf("%s at hop %d", e.code, e.index)
}

func (e *v2HopError) Unwrap() error {
	if e.code == "policy_denied" {
		return errDenied
	}
	return e.inner
}

type v2Endpoint struct {
	binding service.ProxyV2Binding
	tls     service.ProxyV2TLS
	via     string
	mesh    []string
	ipsec   []string
}

func resolveV2Endpoint(view service.ProxyDirectory, hop v2Hop, protocol, role string, now time.Time) (v2Endpoint, bool) {
	peer := view.V2[hop.Zone]
	endpoint, ok := peer.Endpoints[hop.Endpoint]
	if !ok || !view.ValidUntil.After(now) || !endpoint.ValidAt(now) || endpoint.Role != role {
		return v2Endpoint{}, false
	}
	transport, via := v2Link(hop.Link)
	for _, binding := range endpoint.Bindings {
		if binding.Transport != transport || !slices.Contains(binding.Protocols, protocol) {
			continue
		}
		identity, ok := peer.TLS[binding.TLSID]
		if !ok || !identity.ValidAt(now) {
			continue
		}
		for _, address := range binding.Addresses {
			if slices.Contains(address.Via, via) {
				return v2Endpoint{binding: binding, tls: identity, via: via, mesh: peer.Mesh, ipsec: peer.IPsec}, true
			}
		}
	}
	return v2Endpoint{}, false
}

func v2Role(index, count int) string {
	if index == count-1 {
		return "exit"
	}
	return "relay"
}

// Verify that a signed identity and the trust bindings outlive the stream.
// Address and port rotation leave already established streams alone.
func watchV2Route(ctx context.Context, directory *proxyDirectory, view service.ProxyDirectory,
	origin zone.ZonePath, key string, hops []v2Hop, protocol string) (context.Context, func(), bool) {
	now := time.Now()
	required := make([]v2Endpoint, 0, len(hops))
	for i, hop := range hops {
		endpoint, ok := resolveV2Endpoint(view, hop, protocol, v2Role(i, len(hops)), now)
		if !ok {
			return ctx, func() {}, false
		}
		required = append(required, endpoint)
	}
	return directory.watchV2(ctx, func(next service.ProxyDirectory, timeNow time.Time) bool {
		identity := next.V2[origin].Identity
		if identity == nil || !identity.ValidAt(timeNow) || identity.PublicKey != key {
			return false
		}
		for i, hop := range hops {
			endpoint, ok := resolveV2Endpoint(next, hop, protocol, v2Role(i, len(hops)), timeNow)
			if !ok || endpoint.binding.TLSID != required[i].binding.TLSID {
				return false
			}
			// With overlapping pins, a retired pin may have been used by a
			// pooled TLS connection. Conservatively invalidate those streams.
			for _, pin := range required[i].tls.Pins {
				if !slices.Contains(endpoint.tls.Pins, pin) {
					return false
				}
			}
		}
		return true
	})
}

type v2DialPool struct {
	mu                       sync.Mutex
	connections              map[v2Hop]v2PooledEndpoint
	dns                      map[string]v2DNSAnswer
	publicDevice, meshDevice string
}

type v2PooledEndpoint struct {
	spec      v2Endpoint
	addresses v2DialAddresses
	client    *tunnelClient
	retryAt   *atomic.Int64
}

type v2DNSAnswer struct {
	addresses []netip.Addr
	refreshAt time.Time
}

type v2DialAddresses struct{ current, previous []netip.AddrPort }

func (p *v2DialPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, entry := range p.connections {
		entry.client.closeIdleConnections()
	}
	clear(p.connections)
}

func (p *v2DialPool) client(hop v2Hop, spec v2Endpoint, addresses v2DialAddresses) *tunnelClient {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.connections == nil {
		p.connections = make(map[v2Hop]v2PooledEndpoint)
	}
	if previous, ok := p.connections[hop]; ok {
		// Lease renewals do not require replacing the pool.
		prior := previous.spec
		prior.tls.ExpiresAt = spec.tls.ExpiresAt
		retryAt := previous.retryAt.Load()
		if (retryAt == 0 || time.Now().UnixNano() < retryAt) &&
			reflect.DeepEqual(prior, spec) && reflect.DeepEqual(previous.addresses, addresses) {
			return previous.client
		}
		previous.client.closeIdleConnections()
	}
	if len(p.connections) >= 512 {
		for key, entry := range p.connections {
			entry.client.closeIdleConnections()
			delete(p.connections, key)
			break
		}
	}
	retryAt := new(atomic.Int64)
	client := newTunnelClientWithDial(hop.Zone.String(), func(ctx context.Context, _, _ string) (net.Conn, error) {
		return p.dial(ctx, spec, addresses, retryAt)
	})
	p.connections[hop] = v2PooledEndpoint{spec: spec, addresses: addresses, client: client, retryAt: retryAt}
	return client
}

func (p *v2DialPool) lookup(ctx context.Context, family, host string) []netip.Addr {
	key := family + ":" + host
	p.mu.Lock()
	answer, ok := p.dns[key]
	p.mu.Unlock()
	if ok && time.Now().Before(answer.refreshAt) {
		return answer.addresses
	}
	probe, cancel := context.WithTimeout(ctx, 2*time.Second)
	addresses, err := net.DefaultResolver.LookupNetIP(probe, family, host)
	cancel()
	refresh := 30 * time.Second
	if err != nil {
		addresses = nil
		refresh = 2 * time.Second
	}
	p.mu.Lock()
	if p.dns == nil || len(p.dns) >= 1024 {
		p.dns = make(map[string]v2DNSAnswer)
	}
	p.dns[key] = v2DNSAnswer{addresses: addresses, refreshAt: time.Now().Add(refresh)}
	p.mu.Unlock()
	return addresses
}

func (p *v2DialPool) candidates(ctx context.Context, spec v2Endpoint, meshPrefixes []string) v2DialAddresses {
	var current, previous []netip.AddrPort
	var internal []netip.Prefix
	if spec.via != "photon" {
		for _, prefix := range meshPrefixes {
			if parsed, err := netip.ParsePrefix(prefix); err == nil {
				internal = append(internal, parsed)
			}
		}
	}
	seenCurrent := make(map[netip.AddrPort]bool)
	seenPrevious := make(map[netip.AddrPort]bool)
	for _, source := range spec.binding.Addresses {
		if !slices.Contains(source.Via, spec.via) {
			continue
		}
		hosts := []string{source.Host}
		switch source.Source {
		case "route-local":
			hosts = spec.mesh
		case "ipsec":
			hosts = spec.ipsec
		}
		for _, host := range hosts {
			var addresses []netip.Addr
			if addr, err := netip.ParseAddr(host); err == nil {
				addresses = []netip.Addr{addr.Unmap()}
			} else if spec.via != "photon" {
				family := "ip4"
				if spec.via == "public-v6" {
					family = "ip6"
				}
				addresses = p.lookup(ctx, family, host)
			}
			for _, addr := range addresses {
				addr = addr.Unmap()
				if !addr.IsValid() || addr.IsUnspecified() || addr.Zone() != "" {
					continue
				}
				if spec.via != "photon" && (!service.ProxyV2PublicAddress(addr) || addr.Is4() != (spec.via == "public-v4") || withinPrefixes(addr, internal)) {
					continue
				}
				set := spec.binding.PortSets[source.PortSet]
				next := netip.AddrPortFrom(addr, set.Current.Port)
				if !seenCurrent[next] {
					current = append(current, next)
					seenCurrent[next] = true
				}
				if set.Previous != nil {
					old := netip.AddrPortFrom(addr, set.Previous.Port)
					if !seenPrevious[old] {
						previous = append(previous, old)
						seenPrevious[old] = true
					}
				}
			}
		}
	}
	previous = slices.DeleteFunc(previous, func(old netip.AddrPort) bool { return seenCurrent[old] })
	compare := func(a, b netip.AddrPort) int { return a.Compare(b) }
	slices.SortFunc(current, compare)
	slices.SortFunc(previous, compare)
	return v2DialAddresses{current: current, previous: previous}
}

func (p *v2DialPool) dial(ctx context.Context, spec v2Endpoint, addresses v2DialAddresses, retryAt *atomic.Int64) (net.Conn, error) {
	ctx, cancel := context.WithTimeout(ctx, setupTimeout)
	defer cancel()
	current, previous := slices.Clone(addresses.current), slices.Clone(addresses.previous)
	rand.Shuffle(len(current), func(i, j int) { current[i], current[j] = current[j], current[i] })
	rand.Shuffle(len(previous), func(i, j int) { previous[i], previous[j] = previous[j], previous[i] })
	candidates := append(current, previous...)
	if len(candidates) == 0 {
		return nil, &v2HopError{code: "no_candidate", index: -1}
	}
	device := p.publicDevice
	if spec.via == "photon" {
		device = p.meshDevice
	}
	config := &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true, NextProtos: []string{"h2"}}
	// The certificate's key is authenticated by the verified Zone and
	// referenced TLS record rather than by a CA.
	config.VerifyConnection = func(state tls.ConnectionState) error {
		if state.NegotiatedProtocol != "h2" || len(state.PeerCertificates) == 0 {
			return errors.New("missing HTTP/2 ALPN or certificate")
		}
		cert := state.PeerCertificates[0]
		now := time.Now()
		if now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || !slices.Contains(spec.tls.Pins, service.ProxyPublicKeyID(cert)) {
			return errors.New("untrusted or expired proxy certificate")
		}
		return nil
	}
	dialer := &tls.Dialer{NetDialer: &net.Dialer{}, Config: config}
	if device != "" {
		dialer.NetDialer.Control = bindChainDevice(device)
	}
	var lastErr error
	for i, candidate := range candidates {
		timeout := setupTimeout
		if i < len(candidates)-1 {
			timeout = 2 * time.Second
		}
		attempt, stop := context.WithTimeout(ctx, timeout)
		conn, err := dialer.DialContext(attempt, "tcp", candidate.String())
		stop()
		if err == nil {
			if i >= len(current) {
				retryAt.Store(time.Now().Add(15 * time.Second).UnixNano())
			}
			return conn, nil
		}
		lastErr = err
		if ctx.Err() != nil {
			break
		}
	}
	return nil, &v2HopError{code: "dial_failed", index: -1, inner: lastErr}
}

func (p *v2DialPool) connect(ctx context.Context, view service.ProxyDirectory, hops []v2Hop, index int, protocol string, headers http.Header) (*tunnelStream, error) {
	hop := hops[index]
	spec, ok := resolveV2Endpoint(view, hop, protocol, v2Role(index, len(hops)), time.Now())
	if !ok {
		return nil, &v2HopError{code: "no_candidate", index: index}
	}
	headers = headers.Clone()
	headers.Set("User-Agent", "")
	resolveCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	addresses := p.candidates(resolveCtx, spec, view.MeshPrefixes)
	cancel()
	stream, err := p.client(hop, spec, addresses).connect(ctx, v2Authority, headers, protocol == "udp")
	if err == nil {
		return stream, nil
	}
	var hopErr *v2HopError
	if errors.As(err, &hopErr) {
		if hopErr.index < 0 {
			return nil, &v2HopError{code: hopErr.code, index: index, inner: hopErr.inner}
		}
		return nil, hopErr
	}
	return nil, &v2HopError{code: "dial_failed", index: index, inner: err}
}

type v2Client struct {
	directory  *proxyDirectory
	pool       *v2DialPool
	key        ed25519.PrivateKey
	route, udp string
}

func (c *v2Client) open(ctx context.Context, target string) (*tunnelStream, error) {
	view := c.directory.snapshotV2()
	origin := view.ManagedZone
	hops, err := v2Hops(c.route, origin)
	if err != nil {
		return nil, err
	}
	targetHeader := "tcp=" + target
	protocol := "tcp"
	if target == trusttunnel.UDPAuthority {
		targetHeader, protocol = "udp="+c.udp, "udp"
	}
	headers, err := signV2Route(c.key, origin, c.route, targetHeader, time.Now())
	if err != nil {
		return nil, err
	}
	publicKey := delegationEncoding.EncodeToString(c.key.Public().(ed25519.PublicKey))
	ctx, release, ok := watchV2Route(ctx, c.directory, view, origin, publicKey, hops, protocol)
	if !ok {
		return nil, &v2HopError{code: "no_candidate", index: -1}
	}
	stream, err := c.pool.connect(ctx, view, hops, 0, protocol, headers)
	if err != nil {
		release()
		return nil, err
	}
	cancel := stream.cancel
	stream.cancel = func() { cancel(); release() }
	return stream, nil
}

type v2EndpointACL struct {
	relay  service.ProxyV2RelayACL
	exit   service.ProxyV2ExitACL
	groups map[string][]string
}

type v2Server struct {
	directory *proxyDirectory
	pool      *v2DialPool
	endpoints map[string]v2EndpointACL
	replay    delegationVerifier
	slots     chan struct{}
	internal  atomic.Pointer[[]netip.Prefix]
}

func (s *v2Server) serve(w http.ResponseWriter, r *http.Request, group string, active func() bool) {
	defer r.Body.Close()
	if r.Method != http.MethodConnect || r.ProtoMajor != 2 || r.TLS == nil || r.Host != v2Authority {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !active() {
		v2WriteError(w, http.StatusServiceUnavailable, "no_candidate", -1)
		return
	}
	select {
	case s.slots <- struct{}{}:
		defer func() { <-s.slots }()
	default:
		w.WriteHeader(http.StatusServiceUnavailable)
		return
	}
	routes, targets, auth := r.Header.Values(v2RouteHeader), r.Header.Values(v2TargetHeader), r.Header.Values(v2AuthHeader)
	if len(routes) != 1 || len(targets) != 1 || len(auth) != 1 {
		v2WriteError(w, http.StatusBadRequest, "invalid_request", -1)
		return
	}
	grant, err := parseV2Grant(auth[0])
	if err != nil {
		v2WriteError(w, http.StatusForbidden, "policy_denied", -1)
		return
	}
	view := s.directory.snapshotV2()
	now := time.Now()
	identity := view.V2[grant.origin].Identity
	if identity == nil || !identity.ValidAt(now) || !grant.verifies(identity.PublicKey, routes[0], targets[0], now, s.replay.started) {
		v2WriteError(w, http.StatusForbidden, "policy_denied", -1)
		return
	}
	target, targetErr := parseV2Target(targets[0])
	hops, routeErr := v2Hops(routes[0], grant.origin)
	if targetErr != nil || routeErr != nil {
		v2WriteError(w, http.StatusBadRequest, "invalid_request", -1)
		return
	}
	index := slices.IndexFunc(hops, func(h v2Hop) bool { return h.Zone == view.ManagedZone })
	if index < 0 {
		v2WriteError(w, http.StatusForbidden, "policy_denied", -1)
		return
	}
	hop := hops[index]
	_, via := v2Link(hop.Link)
	local, ok := s.endpoints[hop.Endpoint]
	if !ok || !slices.Contains(local.groups[group], via) {
		v2WriteError(w, http.StatusForbidden, "policy_denied", index)
		return
	}
	isExit := index == len(hops)-1
	if (isExit && !local.exit.AllowsSource(grant.origin)) || (!isExit && !local.relay.Allows(grant.origin, hops[index+1].Zone)) {
		v2WriteError(w, http.StatusForbidden, "policy_denied", index)
		return
	}
	ctx, release, ok := watchV2Route(r.Context(), s.directory, view, grant.origin, identity.PublicKey, hops, target.protocol)
	if !ok {
		v2WriteError(w, http.StatusServiceUnavailable, "no_candidate", index)
		return
	}
	defer release()
	if !s.replay.consume(delegationNonce{source: grant.origin, id: grant.nonce}, now, grant.expires) {
		v2WriteError(w, http.StatusForbidden, "policy_denied", index)
		return
	}
	r = r.WithContext(ctx)
	if !isExit {
		headers := http.Header{v2RouteHeader: routes, v2TargetHeader: targets, v2AuthHeader: auth}
		stream, err := s.pool.connect(ctx, view, hops, index+1, target.protocol, headers)
		if err != nil {
			var failure *v2HopError
			if errors.As(err, &failure) {
				status := http.StatusBadGateway
				if failure.code == "policy_denied" {
					status = http.StatusForbidden
				}
				v2WriteError(w, status, failure.code, failure.index)
			} else {
				v2WriteError(w, http.StatusBadGateway, "dial_failed", index+1)
			}
			return
		}
		serveTCPStream(w, r, stream)
		return
	}
	exit := &tunnelHandler{allowTarget: func(protocol string, target netip.AddrPort) bool {
		return local.exit.AllowsTargetWithPublicFilter(protocol, target, func(addr netip.Addr) bool {
			local := s.internal.Load()
			return local != nil && withinPrefixes(addr, *local)
		})
	}}
	if target.protocol == "udp" {
		scope, _ := parseAllowed(target.udpScope)
		exit.serveUDP(w, r, scope)
		return
	}
	dialCtx, cancel := context.WithTimeout(ctx, setupTimeout)
	conn, err := exit.dialTCP(dialCtx, target.address)
	cancel()
	if errors.Is(err, errDenied) {
		v2WriteError(w, http.StatusForbidden, "policy_denied", index)
		return
	}
	if err != nil {
		v2WriteError(w, http.StatusBadGateway, "target_failed", index)
		return
	}
	serveTCPStream(w, r, conn)
}

func v2RouteString(items []string) string {
	hops := make([]string, len(items))
	for i, hop := range items {
		name, link, ok := strings.Cut(hop, "@")
		switch link {
		case "public-v4":
			link = "h24"
		case "public-v6":
			link = "h26"
		case "photon":
			link = "h2p"
		}
		if ok {
			hops[i] = name + "@" + link
		} else {
			hops[i] = hop
		}
	}
	return strings.Join(hops, ",")
}
