package photonproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/netip"
	"slices"
	"strconv"
	"sync/atomic"
	"time"

	"github.com/HiggsNet/photon/pkg/service"
)

type v2ListenerKey struct {
	group string
	port  uint16
}

type v2Listener struct {
	listener net.Listener
	http     *http.Server
	enabled  atomic.Bool
}

const v2ReadyPath = "/_photon_proxy_ready"

func (n *v2Node) listen(key v2ListenerKey) ([]*v2Listener, error) {
	var listeners []*v2Listener
	group := n.config.PortGroups[key.group]
	addresses := group.Bind
	if group.LinkLocal {
		addresses = []string{"::"}
	}
	for _, ip := range addresses {
		address := net.JoinHostPort(ip, strconv.Itoa(int(key.port)))
		config := &net.ListenConfig{}
		var listener net.Listener
		var err error
		if group.LinkLocal && n.host.ListenDirect != nil {
			listener, err = n.host.ListenDirect(n.ctx, key.port)
		} else if group.LinkLocal {
			listener, err = inLinkNamespace(n.pool.directLinks.namespace, func() (net.Listener, error) {
				return config.Listen(n.ctx, "tcp6", address)
			})
		} else {
			listener, err = config.Listen(n.ctx, "tcp", address)
		}
		if err != nil {
			for _, started := range listeners {
				_ = started.http.Close()
			}
			return nil, err
		}
		binding := &v2Listener{listener: listener}
		binding.http = &http.Server{
			TLSConfig: v2ServerTLS(&n.certificate), Protocols: http2Only(), ReadHeaderTimeout: setupTimeout,
			IdleTimeout: time.Minute, MaxHeaderBytes: 16 << 10,
			BaseContext: func(net.Listener) context.Context { return n.ctx },
			Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == v2ReadyPath && r.Method == http.MethodGet && r.ProtoMajor == 2 {
					if address, err := netip.ParseAddrPort(r.RemoteAddr); !group.LinkLocal || err == nil && address.Addr().IsLoopback() {
						w.WriteHeader(http.StatusNoContent)
					} else {
						w.WriteHeader(http.StatusForbidden)
					}
					return
				}
				if group.LinkLocal && r.URL.Path == directProbePath && r.Method == http.MethodGet && r.ProtoMajor == 2 {
					via := r.Header.Get("Photon-Proxy-Via")
					endpoint := n.server.endpoints[r.Header.Get("Photon-Proxy-Endpoint")]
					family := v2DirectFamily(via)
					local, _ := r.Context().Value(http.LocalAddrContextKey).(net.Addr)
					if binding.enabled.Load() && family != "" && local != nil && slices.Contains(endpoint.groups[key.group], via) &&
						n.pool.directLinks.accepts(local.String(), r.RemoteAddr, "", family) {
						w.WriteHeader(http.StatusNoContent)
					} else {
						w.WriteHeader(http.StatusServiceUnavailable)
					}
					return
				}
				n.server.serve(w, r, key.group, group.LinkLocal, binding.enabled.Load)
			}),
		}
		n.workers.Go(func() {
			defer listener.Close()
			err := binding.http.ServeTLS(listener, "", "")
			if err != nil && !errors.Is(err, http.ErrServerClosed) && !errors.Is(err, net.ErrClosed) {
				n.report(err)
			}
		})
		ctx, cancel := context.WithTimeout(n.ctx, 2*time.Second)
		var dial func(context.Context, string, string) (net.Conn, error)
		if group.LinkLocal && n.host.ListenDirect == nil {
			dial = func(ctx context.Context, _, address string) (net.Conn, error) {
				return inLinkNamespace(n.pool.directLinks.namespace, func() (net.Conn, error) {
					return (&net.Dialer{}).DialContext(ctx, "tcp6", address)
				})
			}
		}
		err = v2CheckListener(ctx, binding.listener, n.certificate.Load(), dial)
		cancel()
		if err != nil {
			_ = binding.http.Close()
			_ = binding.listener.Close()
			for _, started := range listeners {
				_ = started.http.Close()
			}
			return nil, err
		}
		listeners = append(listeners, binding)
	}
	return listeners, nil
}

func v2CheckListener(ctx context.Context, listener net.Listener, cert *tls.Certificate, dial func(context.Context, string, string) (net.Conn, error)) error {
	dialAddress := v2ProbeBindAddress(listener.Addr())
	pin := service.ProxyPublicKeyID(cert.Leaf)
	transport := &http.Transport{
		ForceAttemptHTTP2: true,
		DialContext:       dial,
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS13, InsecureSkipVerify: true,
			VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 || service.ProxyPublicKeyID(state.PeerCertificates[0]) != pin {
					return errors.New("local proxy listener has the wrong certificate")
				}
				return nil
			}},
	}
	defer transport.CloseIdleConnections()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, "https://"+dialAddress+v2ReadyPath, nil)
	if err != nil {
		return err
	}
	response, err := transport.RoundTrip(request)
	if err != nil {
		return fmt.Errorf("verify TLS/HTTP2 listener %s: %w", dialAddress, err)
	}
	defer response.Body.Close()
	_, _ = io.Copy(io.Discard, response.Body)
	if response.ProtoMajor != 2 || response.StatusCode != http.StatusNoContent {
		return fmt.Errorf("listener %s failed HTTP/2 readiness", dialAddress)
	}
	return nil
}

func (n *v2Node) retire(listeners []*v2Listener) {
	for _, binding := range listeners {
		binding.enabled.Store(false)
		n.workers.Go(func() {
			stop := context.AfterFunc(n.ctx, func() { _ = binding.http.Close() })
			defer stop()
			_ = binding.http.Shutdown(n.ctx)
		})
	}
}

func (n *v2Node) checkMeshAddresses(ports map[string]service.ProxyV2Ports) map[string]bool {
	view := n.directory.snapshotV2()
	if !view.ValidUntil.After(time.Now()) {
		return nil
	}
	var local []string
	interfaces, _ := net.InterfaceAddrs()
	for _, addr := range interfaces {
		prefix, err := netip.ParsePrefix(addr.String())
		if err == nil && slices.Contains(view.V2[view.ManagedZone].Mesh, prefix.Addr().String()) {
			local = append(local, prefix.Addr().String())
		}
	}
	if len(local) == 0 {
		return nil
	}
	ready := make(map[string]bool)
	for group, set := range ports {
		if n.config.PortGroups[group].LinkLocal {
			continue
		}
		for _, listener := range n.listeners[v2ListenerKey{group, set.Current.Port}] {
			ip := listener.listener.Addr().(*net.TCPAddr).AddrPort().Addr()
			if ip.IsUnspecified() || slices.Contains(local, ip.Unmap().String()) {
				ready[group] = true
			}
		}
	}
	return ready
}
