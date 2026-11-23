package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
)

type tunnelClient struct {
	server        string
	authorization string
	tcpTransport  *http.Transport
	udpTransport  *http.Transport
}

func newTunnelClient(server string, config *tls.Config) *tunnelClient {
	return newTunnelClientWithRelay(server, config, nil)
}

func newTunnelClientWithRelay(server string, config *tls.Config, connect func(context.Context) (net.Conn, error)) *tunnelClient {
	tlsConfig := config.Clone()
	tlsConfig.NextProtos = []string{"h2"}
	dialer := tls.Dialer{NetDialer: &net.Dialer{Timeout: setupTimeout}, Config: tlsConfig}
	dial := dialer.DialContext
	if connect != nil {
		dial = func(ctx context.Context, _, _ string) (net.Conn, error) {
			ctx, cancel := context.WithTimeout(ctx, setupTimeout)
			defer cancel()
			conn, err := connect(ctx)
			if err != nil {
				return nil, err
			}
			secure := tls.Client(conn, tlsConfig)
			if err := secure.HandshakeContext(ctx); err != nil {
				_ = conn.Close()
				return nil, err
			}
			return secure, nil
		}
	}
	return newTunnelClientWithDial(server, dial)
}

func newTunnelClientWithDial(server string, dial func(context.Context, string, string) (net.Conn, error)) *tunnelClient {
	protocols := new(http.Protocols)
	// Use HTTP/2 framing over the TLS connection established by the dialer.
	// This also handles peers that expect HTTP/2 but omit ALPN in their reply.
	protocols.SetUnencryptedHTTP2(true)
	transport := &http.Transport{
		Protocols:             protocols,
		DialContext:           dial,
		ResponseHeaderTimeout: setupTimeout,
		IdleConnTimeout:       time.Minute,
	}
	// Keep UDP and bulk TCP traffic off the same underlying TCP connections.
	return &tunnelClient{server: server, tcpTransport: transport, udpTransport: transport.Clone()}
}

func (c *tunnelClient) closeIdleConnections() {
	c.tcpTransport.CloseIdleConnections()
	c.udpTransport.CloseIdleConnections()
}

type tunnelStream struct {
	io.ReadCloser
	*io.PipeWriter
	cancel  context.CancelFunc
	closeIO func() error
}

func (s *tunnelStream) CloseWrite() error { return s.PipeWriter.Close() }

func (s *tunnelStream) Close() error {
	s.cancel()
	return s.closeIO()
}

func (c *tunnelClient) open(ctx context.Context, target string) (*tunnelStream, error) {
	return c.connect(ctx, target, nil, target == trusttunnel.UDPAuthority)
}

func (c *tunnelClient) connect(ctx context.Context, target string, headers http.Header, udp bool) (*tunnelStream, error) {
	ctx, cancel := context.WithCancel(ctx)
	reader, writer := io.Pipe()
	request := (&http.Request{
		Method:        http.MethodConnect,
		URL:           &url.URL{Scheme: "http", Host: c.server},
		Host:          target,
		Header:        http.Header{"User-Agent": {"photon-proxy"}},
		Body:          reader,
		ContentLength: -1,
	}).WithContext(ctx)
	if c.authorization != "" {
		request.Header.Set("Proxy-Authorization", c.authorization)
	}
	for name, values := range headers {
		request.Header[name] = values
	}
	transport := c.tcpTransport
	if udp {
		transport = c.udpTransport
	}
	response, err := transport.RoundTrip(request)
	if err == nil && response.StatusCode == http.StatusOK && response.ProtoMajor == 2 {
		closeIO := sync.OnceValue(func() error {
			_ = writer.Close()
			return response.Body.Close()
		})
		// CONNECT streams can be idle in both directions when authorization is
		// revoked. Close both halves explicitly to unblock any pending reads.
		context.AfterFunc(ctx, func() { _ = closeIO() })
		return &tunnelStream{ReadCloser: response.Body, PipeWriter: writer, cancel: cancel, closeIO: closeIO}, nil
	}
	cancel()
	_ = writer.Close()
	_ = reader.Close()
	if err != nil {
		return nil, err
	}
	_ = response.Body.Close()
	if code := response.Header.Get(v2ErrorHeader); target == v2Authority && code != "" {
		index, parseErr := strconv.Atoi(response.Header.Get(v2FailedHopHeader))
		if parseErr != nil {
			index = -1
		}
		return nil, &v2HopError{code: code, index: index}
	}
	if response.StatusCode == http.StatusForbidden {
		return nil, errDenied
	}
	return nil, fmt.Errorf("proxy returned %s over %s", response.Status, response.Proto)
}

var errDenied = errors.New("destination is outside the permitted prefixes")

type tunnelHandler struct {
	allowed        []netip.Prefix
	allowTarget    func(string, netip.AddrPort) bool
	slots          chan struct{}
	access         *zoneAccess
	relay          relayTargets
	verifier       *delegationVerifier
	delegatedRelay *delegatedRelay
	chain          *chainServer
}

func serveTunnel(ctx context.Context, listener net.Listener, config *tls.Config, handler *tunnelHandler) error {
	handler.slots = make(chan struct{}, sessionLimit)
	server := &http.Server{
		Handler:           handler,
		TLSConfig:         config.Clone(),
		Protocols:         http2Only(),
		ReadHeaderTimeout: setupTimeout,
		IdleTimeout:       time.Minute,
		MaxHeaderBytes:    16 << 10,
		BaseContext:       func(net.Listener) context.Context { return ctx },
	}
	defer server.Close()
	stop := context.AfterFunc(ctx, func() { _ = server.Close() })
	defer stop()
	err := server.ServeTLS(listener, "", "")
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func (h *tunnelHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	if r.ProtoMajor != 2 || r.Method != http.MethodConnect {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if h.chain != nil {
		h.serveChain(w, r)
		return
	}
	if r.TLS == nil || len(r.TLS.VerifiedChains) == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	var source proxyPeer
	delegationHeaders := r.Header.Values(delegationHeader)
	if len(delegationHeaders) > 1 || (len(delegationHeaders) == 1 && len(delegationHeaders[0]) > delegationHeaderLimit) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	var udpScope []netip.Prefix
	if h.access != nil {
		identity, ok := h.access.match(r.TLS.PeerCertificates[0])
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if len(delegationHeaders) != 0 && len(h.relay) == 0 {
			identity.role = proxyRelay
		}
		ctx, release, ok := h.access.directory.watch(r.Context(), identity)
		if !ok {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		defer release()
		source = identity
		r = r.WithContext(ctx)
		if len(delegationHeaders) != 0 && len(h.relay) == 0 {
			if h.verifier == nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			origin, scope, err := h.verifier.verify(h.access, source.zone, r.Host, delegationHeaders[0], time.Now())
			if err != nil {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			originContext, releaseOrigin, ok := h.access.directory.watch(r.Context(), origin)
			if !ok {
				w.WriteHeader(http.StatusForbidden)
				return
			}
			defer releaseOrigin()
			udpScope = scope
			r = r.WithContext(originContext)
		} else if !slices.Contains(h.access.allowed, source.zone) {
			w.WriteHeader(http.StatusForbidden)
			return
		}
	} else if len(delegationHeaders) != 0 {
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
	if r.Host == "_check" {
		w.WriteHeader(http.StatusOK)
		return
	}
	if len(h.relay) != 0 {
		h.serveRelay(w, r, source.zone)
		return
	}
	if r.Host == relayAuthority {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	h.serveDestination(w, r, r.Host, udpScope)
}

func (h *tunnelHandler) serveDestination(w http.ResponseWriter, r *http.Request, target string, udpScope []netip.Prefix) {
	if target == trusttunnel.UDPAuthority {
		h.serveUDP(w, r, udpScope)
		return
	}
	if _, err := splitTarget(target); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	dialCtx, cancel := context.WithTimeout(r.Context(), setupTimeout)
	conn, err := h.dialTCP(dialCtx, target)
	cancel()
	if err != nil {
		status := http.StatusBadGateway
		if errors.Is(err, errDenied) {
			status = http.StatusForbidden
		}
		w.WriteHeader(status)
		return
	}
	serveTCPStream(w, r, conn)
}

type duplexStream interface {
	io.ReadWriteCloser
	CloseWrite() error
}

func serveTCPStream(w http.ResponseWriter, r *http.Request, conn duplexStream) {
	defer conn.Close()
	stop := context.AfterFunc(r.Context(), func() { _ = conn.Close() })
	defer stop()
	stream, err := startResponse(w)
	if err != nil {
		return
	}
	uploadDone := make(chan struct{})
	go func() {
		defer close(uploadDone)
		if _, err := io.Copy(conn, r.Body); err != nil {
			_ = conn.Close()
			return
		}
		_ = conn.CloseWrite()
	}()
	_, _ = io.Copy(stream, conn)
	_ = r.Body.Close()
	_ = conn.Close()
	<-uploadDone
}

func (h *tunnelHandler) dialTCP(ctx context.Context, target string) (*net.TCPConn, error) {
	host, port, _ := net.SplitHostPort(target)
	portNumber, _ := strconv.ParseUint(port, 10, 16)
	addresses, err := resolveAddresses(ctx, host)
	if err != nil {
		return nil, err
	}
	var failures []error
	for _, ip := range addresses {
		if !h.permitsTarget("tcp", netip.AddrPortFrom(ip, uint16(portNumber))) {
			continue
		}
		conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(ip.String(), port))
		if err == nil {
			return conn.(*net.TCPConn), nil
		}
		failures = append(failures, err)
	}
	if len(failures) == 0 {
		return nil, errDenied
	}
	return nil, errors.Join(failures...)
}

func (h *tunnelHandler) permitsTarget(protocol string, target netip.AddrPort) bool {
	if h.allowTarget != nil {
		return h.allowTarget(protocol, target)
	}
	return h.permits(target.Addr())
}

func (h *tunnelHandler) permits(ip netip.Addr) bool {
	if !ip.IsValid() || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() || ip == netip.AddrFrom4([4]byte{255, 255, 255, 255}) {
		return false
	}
	return withinPrefixes(ip, h.allowed)
}

func withinPrefixes(ip netip.Addr, prefixes []netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(ip.Unmap()) {
			return true
		}
	}
	return false
}

func resolveAddresses(ctx context.Context, host string) ([]netip.Addr, error) {
	if ip, err := netip.ParseAddr(host); err == nil {
		return []netip.Addr{ip.Unmap()}, nil
	}
	return net.DefaultResolver.LookupNetIP(ctx, "ip", host)
}

func splitTarget(target string) (string, error) {
	host, port, err := net.SplitHostPort(target)
	if err != nil || !validHost(host) {
		return "", fmt.Errorf("invalid host:port %q", target)
	}
	if number, err := strconv.ParseUint(port, 10, 16); err != nil || number == 0 {
		return "", fmt.Errorf("invalid port in %q", target)
	}
	return host, nil
}

func validHost(host string) bool {
	return host != "" && !strings.ContainsAny(host, "[]/%?#\\@ \t\n\r\x00")
}

type flushedResponse struct {
	writer     http.ResponseWriter
	controller *http.ResponseController
}

func startResponse(w http.ResponseWriter) (io.Writer, error) {
	w.WriteHeader(http.StatusOK)
	controller := http.NewResponseController(w)
	return flushedResponse{writer: w, controller: controller}, controller.Flush()
}

func (w flushedResponse) Write(p []byte) (int, error) {
	n, err := w.writer.Write(p)
	if err != nil {
		return n, err
	}
	return n, w.controller.Flush()
}
