package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"maps"
	"net"
	"net/http"
	"net/netip"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

func TestOneHopRelayKeepsSourceTLSIdentity(t *testing.T) {
	t.Run("nested", func(t *testing.T) { testOneHopRelay(t, false) })
	t.Run("signed", func(t *testing.T) { testOneHopRelay(t, true) })
}

func testOneHopRelay(t *testing.T, signed bool) {
	const source, relay, exit = zone.ZonePath("a.example."), zone.ZonePath("b.example."), zone.ZonePath("c.example.")
	cConfig, aConfig := testTLS(t)
	bConfig, bClient := testTLSWithServerUsage(t, x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth)
	parse := func(der []byte) *x509.Certificate {
		t.Helper()
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	pool := aConfig.RootCAs.Clone()
	pool.AddCert(parse(bConfig.Certificates[0].Certificate[1]))
	aConfig.RootCAs, bClient.RootCAs = pool, pool
	bConfig.ClientCAs, cConfig.ClientCAs = pool, pool
	b, c, target := localTCP(t), localTCP(t), localTCP(t)
	now := time.Now()
	capability := func(der []byte, address string, isRelay bool) service.ProxyCapability {
		return service.ProxyCapability{Active: true, SPKI: service.ProxyPublicKeyID(parse(der)), ExpiresAt: now.Add(time.Hour),
			Address: address, Transport: service.ProxyTransport, Relay: isRelay}
	}
	peers := map[zone.ZonePath]service.ProxyCapability{
		source: capability(aConfig.Certificates[0].Certificate[0], "", false),
		relay:  capability(bConfig.Certificates[0].Certificate[0], b.Addr().String(), true),
		exit:   capability(cConfig.Certificates[0].Certificate[0], c.Addr().String(), false),
	}
	public, signingKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if signed {
		value := peers[source]
		value.DelegationKey = delegationEncoding.EncodeToString(public)
		peers[source] = value
	}
	directory := func(local zone.ZonePath) *proxyDirectory {
		return &proxyDirectory{
			view:     service.ProxyDirectory{ManagedZone: local, ValidUntil: now.Add(time.Minute), Peers: maps.Clone(peers)},
			sessions: make(map[*watchedSession]struct{}),
		}
	}
	bAccess := &zoneAccess{directory: directory(relay), allowed: []zone.ZonePath{source}}
	cAccess := &zoneAccess{directory: directory(exit), allowed: []zone.ZonePath{source}}
	var verifier *delegationVerifier
	var forwarded *delegatedRelay
	if signed {
		cAccess.delegates = []zone.ZonePath{relay}
		verifier = &delegationVerifier{endpoint: c.Addr().String(), started: now}
		forwarded = &delegatedRelay{tls: &tls.Config{MinVersion: tls.VersionTLS13, Certificates: bConfig.Certificates, RootCAs: pool}}
		t.Cleanup(forwarded.closeIdleConnections)
	}
	bConfig.VerifyConnection, cConfig.VerifyConnection = bAccess.verify, cAccess.verify
	startTestServer(t, func(ctx context.Context) error {
		allowed := relayTargets{{zone: exit, address: c.Addr().String()}: {}}
		return serveTunnel(ctx, b, bConfig, &tunnelHandler{access: bAccess, relay: allowed, delegatedRelay: forwarded})
	})
	startTestServer(t, func(ctx context.Context) error {
		return serveTunnel(ctx, c, cConfig, &tunnelHandler{access: cAccess, allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.0/8")}, verifier: verifier})
	})
	go func() {
		conn, err := target.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		var packet [8]byte
		if _, err := io.ReadFull(conn, packet[:]); err == nil {
			_, _ = conn.Write(packet[:])
		}
		_, _ = io.Copy(io.Discard, conn)
	}()
	aDirectory := directory(source)
	client := &zoneTunnelClient{directory: aDirectory, zone: exit, via: relay, tls: aConfig}
	if signed {
		client.delegation = signingKey
		client.delegationUDP = "127.0.0.1/32"
	}
	t.Cleanup(client.closeIdleConnections)
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	stream, err := client.open(ctx, target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if _, err := io.WriteString(stream, "over-hop"); err != nil {
		t.Fatal(err)
	}
	var packet [8]byte
	if _, err := io.ReadFull(stream, packet[:]); err != nil || string(packet[:]) != "over-hop" {
		t.Fatalf("TCP over relay: %q, %v", packet[:], err)
	}
	udp, err := client.open(ctx, trusttunnel.UDPAuthority)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	request := trusttunnel.Datagram{Source: netip.MustParseAddrPort("127.0.0.1:50001"), Destination: udpEcho(t, "127.0.0.1"), Payload: []byte("udp-over-hop")}
	if err := trusttunnel.WriteRequest(udp, request); err != nil {
		t.Fatal(err)
	}
	if response, err := trusttunnel.ReadResponse(udp); err != nil || response.Source != request.Destination || string(response.Payload) != "udp-over-hop" {
		t.Fatalf("UDP over relay: %+v, %v", response, err)
	}

	outer := newTunnelClient(b.Addr().String(), pinnedProxyTLS(aConfig, peers[relay]))
	defer outer.closeIdleConnections()
	if unauthorized, err := outer.connect(ctx, relayAuthority, http.Header{
		relayZoneHeader: {exit.String()}, relayAddressHeader: {target.Addr().String()},
	}, false); !errors.Is(err, errDenied) {
		if unauthorized != nil {
			_ = unauthorized.Close()
		}
		t.Fatalf("relay accepted a substituted endpoint: %v", err)
	}
	if unauthorized, err := outer.open(ctx, target.Addr().String()); !errors.Is(err, errDenied) {
		if unauthorized != nil {
			_ = unauthorized.Close()
		}
		t.Fatalf("relay accepted a final destination: %v", err)
	}
	other := newTunnelClient(c.Addr().String(), pinnedProxyTLS(bClient, peers[exit]))
	defer other.closeIdleConnections()
	negativeCtx, stopNegative := context.WithTimeout(t.Context(), time.Second)
	defer stopNegative()
	if unexpected, err := other.open(negativeCtx, "_check"); err == nil {
		_ = unexpected.Close()
		t.Fatal("exit accepted a different CA-signed client instead of A")
	}
	if signed {
		bClient.Certificates = bConfig.Certificates
		assertDelegatedExitChecks(t, ctx, newTunnelClient(c.Addr().String(), pinnedProxyTLS(bClient, peers[exit])), signingKey,
			delegationBinding{relay: relay, exit: exit, endpoint: c.Addr().String(), target: trusttunnel.UDPAuthority}, source, target.Addr().String())
	}

	updated := maps.Clone(peers)
	if signed {
		value := updated[source]
		value.DelegationKey = ""
		updated[source] = value
		cAccess.directory.update(&service.ProxyDirectory{ManagedZone: exit, Peers: updated, ValidUntil: now.Add(time.Minute)}, time.Now())
	} else {
		delete(updated, relay)
		aDirectory.update(&service.ProxyDirectory{ManagedZone: source, Peers: updated, ValidUntil: now.Add(time.Minute)}, time.Now())
	}
	if _, err := stream.Read(packet[:]); err == nil || ctx.Err() != nil {
		t.Fatalf("TCP stayed open after withdrawal: %v", err)
	}
	if _, err := trusttunnel.ReadResponse(udp); err == nil || ctx.Err() != nil {
		t.Fatalf("UDP stayed open after withdrawal: %v", err)
	}
	if unexpected, err := client.open(ctx, target.Addr().String()); err == nil {
		_ = unexpected.Close()
		t.Fatal("withdrawn authority accepted a new connection")
	}
}

func assertDelegatedExitChecks(t *testing.T, ctx context.Context, exit *tunnelClient, signer ed25519.PrivateKey, binding delegationBinding, origin zone.ZonePath, otherTarget string) {
	t.Helper()
	defer exit.closeIdleConnections()
	if stream, err := exit.open(ctx, "_check"); !errors.Is(err, errDenied) {
		if stream != nil {
			_ = stream.Close()
		}
		t.Fatalf("delegate obtained direct access: %v", err)
	}
	grant, err := issueDelegation(signer, origin, binding, "127.0.0.1/32", time.Now())
	if err != nil || len(grant) > 256 {
		t.Fatalf("grant length = %d, %v", len(grant), err)
	}
	t.Logf("short-lived UDP delegation header value: %d bytes", len(grant))
	header := http.Header{delegationHeader: {grant}}
	if stream, err := exit.connect(ctx, otherTarget, header, false); !errors.Is(err, errDenied) {
		if stream != nil {
			_ = stream.Close()
		}
		t.Fatalf("a grant could change its target: %v", err)
	}
	stream, err := exit.connect(ctx, trusttunnel.UDPAuthority, header, true)
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	if duplicated, err := exit.connect(ctx, trusttunnel.UDPAuthority, header, true); !errors.Is(err, errDenied) {
		if duplicated != nil {
			_ = duplicated.Close()
		}
		t.Fatalf("an already used grant was accepted: %v", err)
	}
	denied, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	defer denied.Close()
	sourceAddr := netip.MustParseAddrPort("127.0.0.1:50002")
	allowedTarget := udpEcho(t, "127.0.0.1")
	for _, address := range []netip.AddrPort{denied.LocalAddr().(*net.UDPAddr).AddrPort(), allowedTarget} {
		if err := trusttunnel.WriteRequest(stream, trusttunnel.Datagram{Source: sourceAddr, Destination: address, Payload: []byte("scoped")}); err != nil {
			t.Fatal(err)
		}
	}
	if packet, err := trusttunnel.ReadResponse(stream); err != nil || packet.Source != allowedTarget || string(packet.Payload) != "scoped" {
		t.Fatalf("signed UDP scope: %+v, %v", packet, err)
	}
	if err := denied.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	if _, err := denied.Read(make([]byte, 16)); err == nil {
		t.Fatal("UDP target allowed locally but outside A's signed scope was forwarded")
	}
}
