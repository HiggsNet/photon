package photonwindows

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/service"
)

func TestProxyDirectHTTP2IsScopedToItsLink(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	t.Cleanup(cancel)
	const port = 24540
	local := netip.MustParseAddr("fe80::1234")
	remote := netip.MustParseAddr("fe80::5678")
	sample := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	certificates := sample.TLS.Certificates
	sample.Close()
	for _, family := range []string{"ipv4", "ipv6"} {
		t.Run(family, func(t *testing.T) {
			t.Parallel()
			link := service.ProxyDirectLink{Family: family, Interface: family + "-1", Local: local, Remote: remote}
			client, err := newProxyDirectStack(ctx, link, 1280)
			if err != nil {
				t.Fatal(err)
			}
			defer client.close()
			link.Local, link.Remote = link.Remote, link.Local
			server, err := newProxyDirectStack(ctx, link, 1280)
			if err != nil {
				t.Fatal(err)
			}
			defer server.close()
			connect := func(from, to *proxyDirectStack) {
				from.readOutbound(func(packet []byte) {
					if proxyDirectPacket(from.link, packet, true) && proxyDirectPacket(to.link, packet, false) {
						to.inject(packet)
					}
				})
			}
			go connect(client, server)
			go connect(server, client)

			listener, err := server.listen(port)
			if err != nil {
				t.Fatal(err)
			}
			defer listener.Close()
			httpServer := &http.Server{
				TLSConfig: &tls.Config{Certificates: certificates},
				Protocols: new(http.Protocols),
				Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					remote, err := netip.ParseAddrPort(r.RemoteAddr)
					if err != nil || remote.Addr().Zone() != family+"-1" || r.ProtoMajor != 2 {
						w.WriteHeader(http.StatusBadRequest)
						return
					}
					w.WriteHeader(http.StatusNoContent)
				}),
			}
			httpServer.Protocols.SetHTTP2(true)
			defer httpServer.Close()
			go func() { _ = httpServer.ServeTLS(scopedTestListener{listener, link.Interface}, "", "") }()
			transport := &http.Transport{
				ForceAttemptHTTP2: true, TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
				DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) { return client.dial(ctx, port) },
			}
			defer transport.CloseIdleConnections()
			r, err := http.NewRequestWithContext(ctx, http.MethodGet, fmt.Sprintf("https://[%s]:%d/", remote, port), nil)
			if err != nil {
				t.Fatal(err)
			}
			response, err := transport.RoundTrip(r)
			if err != nil {
				t.Fatal(err)
			}
			response.Body.Close()
			if response.StatusCode != http.StatusNoContent || response.ProtoMajor != 2 {
				t.Fatalf("direct response %s %s", response.Proto, response.Status)
			}
		})
	}
}

type scopedTestListener struct {
	net.Listener
	scope string
}

func (l scopedTestListener) Accept() (net.Conn, error) {
	conn, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	return proxyScopedConn{Conn: conn, scope: l.scope}, nil
}
