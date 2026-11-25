package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

const (
	directRefresh   = 5 * time.Second
	directProbePath = "/_photon_proxy_link_ready"
)

type directLinks struct {
	namespace string
	snapshot  atomic.Pointer[directSnapshot]
}

type directSnapshot struct {
	links []service.ProxyDirectLink
	until time.Time
}

func (d *directLinks) refresh(ctx context.Context, socket string) {
	reply, err := readProxyData(ctx, socket, service.ProxyReadRequest{Kind: service.ProxyReadLinks})
	if err == nil {
		links := slices.DeleteFunc(reply.Links, func(link service.ProxyDirectLink) bool {
			return link.NetNS != d.namespace || link.Interface == "" || link.ID == "" ||
				!link.Local.Is6() || !link.Local.IsLinkLocalUnicast() || link.Local.Zone() != "" ||
				!link.Remote.Is6() || !link.Remote.IsLinkLocalUnicast() || link.Remote.Zone() != ""
		})
		d.snapshot.Store(&directSnapshot{links: links, until: time.Now().Add(2 * directRefresh)})
	}
}

func (d *directLinks) run(ctx context.Context, socket string, afterRefresh func()) {
	ticker := time.NewTicker(directRefresh)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.refresh(ctx, socket)
			afterRefresh()
		}
	}
}

func (d *directLinks) current() []service.ProxyDirectLink {
	if d != nil {
		if view := d.snapshot.Load(); view != nil && view.until.After(time.Now()) {
			return view.links
		}
	}
	return nil
}

func v2DirectFamily(via string) string {
	switch via {
	case "link-local-v4":
		return "ipv4"
	case "link-local-v6":
		return "ipv6"
	default:
		return ""
	}
}

func (d *directLinks) accepts(local, remote string, peer zone.ZonePath, family string) bool {
	src, err := netip.ParseAddrPort(remote)
	if err != nil {
		return false
	}
	dst, err := netip.ParseAddrPort(local)
	if err != nil {
		return false
	}
	return slices.ContainsFunc(d.current(), func(link service.ProxyDirectLink) bool {
		return link.Family == family && (peer == "" || link.Peer == peer) &&
			src.Addr().WithZone("") == link.Remote && dst.Addr().WithZone("") == link.Local
	})
}

type directCandidate struct {
	link service.ProxyDirectLink
	port uint16
}

func directCandidates(links []service.ProxyDirectLink, hop v2Hop, spec v2Endpoint) []directCandidate {
	var out []directCandidate
	family := v2DirectFamily(spec.via)
	for _, link := range links {
		if link.Peer != hop.Zone || link.Family != family {
			continue
		}
		for _, source := range spec.binding.Addresses {
			if !slices.Contains(source.Via, spec.via) {
				continue
			}
			ports := spec.binding.PortSets[source.PortSet]
			out = append(out, directCandidate{link, ports.Current.Port})
			if ports.Previous != nil {
				out = append(out, directCandidate{link, ports.Previous.Port})
			}
		}
	}
	slices.SortStableFunc(out, func(a, b directCandidate) int {
		if a.link.Staged != b.link.Staged {
			if a.link.Staged {
				return -1
			}
			return 1
		}
		return strings.Compare(a.link.ID, b.link.ID)
	})
	return slices.Compact(out)
}

func (c directCandidate) open(ctx context.Context, config *tls.Config) (net.Conn, error) {
	conn, err := inLinkNamespace(c.link.NetNS, func() (net.Conn, error) {
		iface, err := net.InterfaceByName(c.link.Interface)
		if err != nil {
			return nil, err
		}
		scope := strconv.Itoa(iface.Index)
		dialer := &net.Dialer{LocalAddr: net.TCPAddrFromAddrPort(netip.AddrPortFrom(c.link.Local.WithZone(scope), 0))}
		return dialer.DialContext(ctx, "tcp6", netip.AddrPortFrom(c.link.Remote.WithZone(scope), c.port).String())
	})
	if err != nil {
		return nil, err
	}
	secure := tls.Client(conn, config)
	if err := secure.HandshakeContext(ctx); err != nil {
		_ = conn.Close()
		return nil, err
	}
	return secure, nil
}

type directPoolKey struct {
	candidate directCandidate
	endpoint  string
	via       string
	pins      string
}

type directPoolEntry struct {
	client *tunnelClient
	done   chan struct{}
	ready  bool
	retry  time.Time
}

type directPool struct {
	ctx     context.Context
	mu      sync.Mutex
	entries map[directPoolKey]*directPoolEntry
}

func (p *directPool) probe(hop v2Hop, spec v2Endpoint, entry *directPoolEntry) {
	ctx, cancel := context.WithTimeout(p.ctx, 2*time.Second)
	defer cancel()
	url := fmt.Sprintf("http://%s%s", hop.Zone, directProbePath)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err == nil {
		request.Header.Set("Photon-Proxy-Endpoint", hop.Endpoint)
		request.Header.Set("Photon-Proxy-Via", spec.via)
		var response *http.Response
		response, err = entry.client.tcpTransport.RoundTrip(request)
		if err == nil {
			defer response.Body.Close()
			if response.ProtoMajor != 2 || response.StatusCode != http.StatusNoContent {
				err = errors.New("direct Photon endpoint is not ready")
			}
		}
	}
	p.mu.Lock()
	entry.ready = err == nil
	entry.retry = time.Now().Add(directRefresh)
	close(entry.done)
	entry.done = nil
	if !entry.ready {
		entry.client.closeIdleConnections()
	}
	p.mu.Unlock()
}

func (p *directPool) selectClient(ctx context.Context, hop v2Hop, spec v2Endpoint, candidates []directCandidate) (*directPoolEntry, error) {
	for {
		var waiting <-chan struct{}
		p.mu.Lock()
		for _, candidate := range candidates {
			entry := p.prepareLocked(hop, spec, candidate)
			if entry != nil && entry.ready {
				p.mu.Unlock()
				return entry, nil
			}
			if waiting == nil && entry != nil {
				waiting = entry.done
			}
		}
		p.mu.Unlock()
		if waiting == nil {
			return nil, &v2HopError{code: "no_candidate", index: -1}
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-waiting:
		}
	}
}

func (p *directPool) prepareLocked(hop v2Hop, spec v2Endpoint, candidate directCandidate) *directPoolEntry {
	key := directPoolKey{candidate, hop.Endpoint, spec.via, strings.Join(spec.tls.Pins, ",")}
	key.candidate.link.Staged = false
	entry := p.entries[key]
	if entry == nil {
		if len(p.entries) >= 512 {
			for staleKey, stale := range p.entries {
				if stale.done == nil {
					stale.client.closeIdleConnections()
					delete(p.entries, staleKey)
					break
				}
			}
			if len(p.entries) >= 512 {
				return nil
			}
		}
		tlsConfig := v2HopTLS(spec)
		entry = &directPoolEntry{client: newTunnelClientWithDial(hop.Zone.String(), func(ctx context.Context, _, _ string) (net.Conn, error) {
			return candidate.open(ctx, tlsConfig)
		})}
		p.entries[key] = entry
	}
	if !entry.ready && entry.done == nil && !time.Now().Before(entry.retry) {
		entry.done = make(chan struct{})
		go p.probe(hop, spec, entry)
	}
	return entry
}

func (p *directPool) warmStaged(view service.ProxyDirectory, links []service.ProxyDirectLink) {
	if !slices.ContainsFunc(links, func(link service.ProxyDirectLink) bool { return link.Staged }) {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	hops := make(map[v2Hop]struct{})
	for key := range p.entries {
		link := "h2l4"
		if key.candidate.link.Family == "ipv6" {
			link = "h2l6"
		}
		hops[v2Hop{Zone: key.candidate.link.Peer, Endpoint: key.endpoint, Link: link}] = struct{}{}
	}
	for hop := range hops {
		role := "exit"
		if hop.Endpoint == "relay" {
			role = "relay"
		}
		now := time.Now()
		spec, ok := resolveV2Endpoint(view, hop, "tcp", role, now)
		if !ok {
			spec, ok = resolveV2Endpoint(view, hop, "udp", role, now)
		}
		if !ok {
			continue
		}
		for _, candidate := range directCandidates(links, hop, spec) {
			if !candidate.link.Staged {
				break
			}
			p.prepareLocked(hop, spec, candidate)
		}
	}
}

func (p *directPool) invalidate(entry *directPoolEntry) {
	p.mu.Lock()
	defer p.mu.Unlock()
	entry.ready = false
	entry.retry = time.Time{}
	entry.client.closeIdleConnections()
}

func (p *directPool) close() {
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, entry := range p.entries {
		entry.client.closeIdleConnections()
	}
}

func (p *v2DialPool) connectDirect(ctx context.Context, hop v2Hop, spec v2Endpoint, headers http.Header, udp bool) (*tunnelStream, error) {
	if p.direct == nil {
		return nil, &v2HopError{code: "no_candidate", index: -1, inner: errors.New("direct Photon links are disabled")}
	}
	setup, cancel := context.WithTimeout(ctx, setupTimeout)
	entry, err := p.direct.selectClient(setup, hop, spec, directCandidates(p.directLinks.current(), hop, spec))
	cancel()
	if err != nil {
		return nil, err
	}
	stream, err := entry.client.connect(ctx, v2Authority, headers, udp)
	var hopError *v2HopError
	if err != nil && ctx.Err() == nil && !errors.As(err, &hopError) && !errors.Is(err, errDenied) {
		p.direct.invalidate(entry)
	}
	return stream, err
}
