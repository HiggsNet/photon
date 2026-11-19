package main

import (
	"context"
	"crypto/x509"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

func TestZoneTunnelPortUpdateAndRevocation(t *testing.T) {
	clientZone, serverZone := zone.ZonePath("client.example."), zone.ZonePath("exit.example.")
	serverConfig, clientTLS := testTLS(t)
	certPin := func(der []byte) string {
		t.Helper()
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return service.ProxyPublicKeyID(cert)
	}
	now := time.Now()
	proof := func(address, pin string) service.ProxyCapability {
		return service.ProxyCapability{Active: true, Address: address, Transport: service.ProxyTransport, SPKI: pin, ExpiresAt: now.Add(time.Hour)}
	}
	newView := func(path zone.ZonePath, value service.ProxyCapability) service.ProxyDirectory {
		return service.ProxyDirectory{ValidUntil: now.Add(time.Minute), Peers: map[zone.ZonePath]service.ProxyCapability{path: value}}
	}
	serverDirectory := &proxyDirectory{
		view: newView(clientZone, proof("", certPin(clientTLS.Certificates[0].Certificate[0]))), sessions: make(map[*watchedSession]struct{}),
	}
	access := &zoneAccess{directory: serverDirectory, allowed: []zone.ZonePath{clientZone}}
	serverConfig.VerifyConnection = access.verify
	old, staged := localTCP(t), localTCP(t)
	allowed := []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
	startTestServer(t, func(ctx context.Context) error {
		return serveTunnel(ctx, old, serverConfig, &tunnelHandler{allowed: allowed, access: access})
	})
	startTestServer(t, func(ctx context.Context) error {
		return serveTunnel(ctx, staged, serverConfig, &tunnelHandler{allowed: allowed, access: access})
	})

	target := localTCP(t)
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				var buf [256]byte
				for {
					n, err := conn.Read(buf[:])
					if err != nil {
						return
					}
					if _, err := conn.Write(buf[:n]); err != nil {
						return
					}
				}
			}()
		}
	}()
	serverPin := certPin(serverConfig.Certificates[0].Certificate[0])
	clientDirectory := &proxyDirectory{
		view: newView(serverZone, proof(old.Addr().String(), serverPin)), sessions: make(map[*watchedSession]struct{}),
	}
	client := &zoneTunnelClient{directory: clientDirectory, tls: clientTLS, zone: serverZone}
	t.Cleanup(client.closeIdleConnections)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	open := func() *tunnelStream {
		t.Helper()
		stream, err := client.open(ctx, target.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stream.Close() })
		return stream
	}
	echored := func(stream *tunnelStream, data string) {
		t.Helper()
		if _, err := io.WriteString(stream, data); err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, len(data))
		if _, err := io.ReadFull(stream, buf); err != nil || string(buf) != data {
			t.Fatalf("echo = %q, %v", buf, err)
		}
	}
	original := open()
	echored(original, "old port")
	updated := newView(serverZone, proof(staged.Addr().String(), serverPin))
	clientDirectory.update(&updated, time.Now())
	rotated := open()
	if client.address != staged.Addr().String() {
		t.Fatalf("new session used %v, expected staged port %v", client.address, staged.Addr())
	}
	echored(rotated, "new port")
	echored(original, "old session remains active")
	badPin := newView(serverZone, proof(staged.Addr().String(), strings.Repeat("20", 32)))
	wrong := &zoneTunnelClient{directory: &proxyDirectory{view: badPin, sessions: make(map[*watchedSession]struct{})}, tls: clientTLS, zone: serverZone}
	defer wrong.closeIdleConnections()
	if stream, err := wrong.open(ctx, target.Addr().String()); err == nil {
		_ = stream.Close()
		t.Fatal("trusted TLS CA bypassed the signed server public key")
	}
	withdrawn := service.ProxyDirectory{ValidUntil: now.Add(time.Minute)}
	serverDirectory.update(&withdrawn, time.Now())
	for _, stream := range []*tunnelStream{original, rotated} {
		if _, err := stream.Read(make([]byte, 1)); err == nil || ctx.Err() != nil {
			t.Fatalf("revoked session did not close promptly: %v", err)
		}
	}
	if stream, err := client.open(ctx, target.Addr().String()); err == nil {
		_ = stream.Close()
		t.Fatal("withdrawn client established a new session")
	}
}
