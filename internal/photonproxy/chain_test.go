package photonproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"maps"
	"net"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

func TestSignedChainAndEndpointCutover(t *testing.T) {
	const origin zone.ZonePath = "a.example."
	const endpoint = "public-v4"
	path := []zone.ZonePath{"b.example.", "c.example.", "d.example.", "e.example.", "f.example."}
	started := time.Now()
	public, key, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	peers := map[zone.ZonePath]service.ProxyCapability{origin: {
		Active: true, ExpiresAt: started.Add(time.Hour), DelegationKey: delegationEncoding.EncodeToString(public),
	}}
	roots := x509.NewCertPool()
	listeners := make([]net.Listener, len(path))
	certificates := make([]*tls.Config, len(path))
	var hops []chainHop
	for index, id := range path {
		listeners[index] = localTCP(t)
		config, _ := testTLS(t)
		config.ClientAuth = tls.NoClientCert
		root, err := x509.ParseCertificate(config.Certificates[0].Certificate[1])
		if err != nil {
			t.Fatal(err)
		}
		roots.AddCert(root)
		leaf, err := x509.ParseCertificate(config.Certificates[0].Certificate[0])
		if err != nil {
			t.Fatal(err)
		}
		certificates[index] = config
		hops = append(hops, chainHop{chainSelector: chainSelector{zone: id, name: endpoint}})
		peers[id] = service.ProxyCapability{
			Active: true, ExpiresAt: started.Add(time.Hour), SPKI: service.ProxyPublicKeyID(leaf),
			Relay: index != len(path)-1, Transport: service.ProxyTransport,
			Endpoints: map[string]string{endpoint: listeners[index].Addr().String()},
		}
	}
	dialTLS := &tls.Config{MinVersion: tls.VersionTLS13, RootCAs: roots}
	directories := make(map[zone.ZonePath]*proxyDirectory)
	view := func(id zone.ZonePath) service.ProxyDirectory {
		return service.ProxyDirectory{ManagedZone: id, ValidUntil: started.Add(time.Minute), Peers: maps.Clone(peers)}
	}
	for _, id := range append([]zone.ZonePath{origin}, path...) {
		directories[id] = &proxyDirectory{view: view(id), sessions: make(map[*watchedSession]struct{})}
	}
	serve := func(index int, listener net.Listener) {
		id := path[index]
		server := &chainServer{
			directory: directories[id], origins: []zone.ZonePath{origin},
			local: map[string]string{endpoint: listener.Addr().String()}, replay: delegationVerifier{started: started},
		}
		var allowed []netip.Prefix
		if index < len(path)-1 {
			server.pool = &chainPool{tls: dialTLS}
			server.next = map[chainSelector]struct{}{hops[index+1].chainSelector: {}}
			t.Cleanup(server.pool.closeIdleConnections)
		} else {
			allowed = []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}
		}
		startTestServer(t, func(ctx context.Context) error {
			return serveTunnel(ctx, listener, certificates[index], &tunnelHandler{chain: server, allowed: allowed})
		})
	}
	for index, listener := range listeners {
		serve(index, listener)
	}
	target := localTCP(t)
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				_, _ = io.Copy(conn, conn)
			}()
		}
	}()
	pool := &chainPool{tls: dialTLS}
	t.Cleanup(pool.closeIdleConnections)
	client := &chainClient{directory: directories[origin], hops: hops, key: key, udp: "127.0.0.1/32", pool: pool}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	openTCP := func() *tunnelStream {
		t.Helper()
		stream, err := client.open(ctx, target.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		return stream
	}
	echo := func(stream *tunnelStream, message string) {
		t.Helper()
		if _, err := io.WriteString(stream, message); err != nil {
			t.Fatal(err)
		}
		data := make([]byte, len(message))
		if _, err := io.ReadFull(stream, data); err != nil || string(data) != message {
			t.Fatalf("echo = %q, %v", data, err)
		}
	}
	old := openTCP()
	defer old.Close()
	echo(old, "before cutover")
	udp, err := client.open(ctx, trusttunnel.UDPAuthority)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	request := trusttunnel.Datagram{Source: netip.MustParseAddrPort("127.0.0.1:50000"), Destination: udpEcho(t, "127.0.0.1"), Payload: []byte("five hops")}
	if err := trusttunnel.WriteRequest(udp, request); err != nil {
		t.Fatal(err)
	}
	if response, err := trusttunnel.ReadResponse(udp); err != nil || response.Source != request.Destination || string(response.Payload) != "five hops" {
		t.Fatalf("UDP over chain: %+v, %v", response, err)
	}

	exit := path[len(path)-1]
	staged := localTCP(t)
	serve(len(path)-1, staged)
	capability := peers[exit]
	capability.Endpoints = map[string]string{endpoint: staged.Addr().String()}
	peers[exit] = capability
	for id, directory := range directories {
		updated := view(id)
		directory.update(&updated, time.Now())
	}
	current := openTCP()
	defer current.Close()
	echo(old, "old stream survived")
	echo(current, "new stream after rotation")

	resolved, _, err := resolveChain(directories[origin], origin, hops)
	if err != nil {
		t.Fatal(err)
	}
	var parts []string
	for _, hop := range resolved {
		parts = append(parts, hop.zone.String()+"/"+hop.name+"="+hop.address)
	}
	route := strings.Join(parts, ",")
	ticket, err := issueDelegation(key, origin, delegationBinding{route: route, target: target.Addr().String()}, "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	entry := pool.client(resolved[0], peers[path[0]].SPKI)
	expectDenied := func(route, destination string) {
		t.Helper()
		stream, err := entry.connect(ctx, chainAuthority, chainHeaders(route, destination, ticket), false)
		if !errors.Is(err, errDenied) {
			if stream != nil {
				_ = stream.Close()
			}
			t.Fatalf("expected authorization denial, got %v", err)
		}
	}
	tampered := parts[0] + "," + strings.Join(parts[2:], ",")
	expectDenied(tampered, target.Addr().String())
	expectDenied(route, "127.0.0.1:1")
	valid, err := entry.connect(ctx, chainAuthority, chainHeaders(route, target.Addr().String(), ticket), false)
	if err != nil {
		t.Fatal(err)
	}
	defer valid.Close()
	expectDenied(route, target.Addr().String())
}
