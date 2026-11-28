package photonproxy

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"io"
	"math/big"
	"net"
	"net/netip"
	"strconv"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
)

func TestSOCKS5ThroughMutualTLSTrustTunnel(t *testing.T) {
	serverKey, clientConfig := testTLS(t)
	tcp := localTCP(t)
	go func() {
		conn, err := tcp.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write([]byte("ready"))
		data, err := io.ReadAll(conn)
		if err == nil {
			_, _ = conn.Write(data)
		}
	}()
	proxy := localTCP(t)
	startTestServer(t, func(ctx context.Context) error {
		return serveTunnel(ctx, proxy, serverKey, &tunnelHandler{allowed: []netip.Prefix{netip.MustParsePrefix("127.0.0.1/32")}})
	})
	socks := localTCP(t)
	client := newTunnelClient(proxy.Addr().String(), clientConfig)
	t.Cleanup(client.closeIdleConnections)
	startTestServer(t, func(ctx context.Context) error { return serveSOCKS(ctx, socks, client) })

	conn, status, _ := socksRequest(t, socks, socksConnect, netip.MustParseAddrPort(tcp.Addr().String()))
	if status != socksSucceeded {
		t.Fatalf("TCP request returned status %d", status)
	}
	var banner [5]byte
	if _, err := io.ReadFull(conn, banner[:]); err != nil || string(banner[:]) != "ready" {
		t.Fatalf("server data before client upload: %q, %v", banner, err)
	}
	if _, err := conn.Write([]byte("cross-site TCP")); err != nil {
		t.Fatal(err)
	}
	if err := conn.CloseWrite(); err != nil {
		t.Fatal(err)
	}
	if reply, err := io.ReadAll(conn); err != nil || string(reply) != "cross-site TCP" {
		t.Fatalf("TCP reply after closing upload: %q, %v", reply, err)
	}

	_, status, _ = socksRequest(t, socks, socksConnect, netip.MustParseAddrPort("127.0.0.2:80"))
	if status != socksDenied {
		t.Fatalf("denied destination returned status %d, want %d", status, socksDenied)
	}

	udp1 := udpEcho(t, "127.0.0.1")
	udp2 := udpEcho(t, "127.0.0.1")
	control, status, associateAddr := socksRequest(t, socks, socksAssociate, netip.AddrPort{})
	if status != socksSucceeded {
		t.Fatalf("UDP associate returned status %d", status)
	}
	udp, err := net.DialUDP("udp4", nil, net.UDPAddrFromAddrPort(associateAddr))
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	if err := udp.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	for _, target := range []netip.AddrPort{udp1, udp2, udp1} {
		request := appendSOCKSAddress([]byte{0, 0, 0}, target)
		if _, err := udp.Write(append(request, []byte("cross-site UDP")...)); err != nil {
			t.Fatal(err)
		}
		var packet [256]byte
		n, err := udp.Read(packet[:])
		if err != nil {
			t.Fatal(err)
		}
		if want := append(request, []byte("cross-site UDP")...); !bytes.Equal(packet[:n], want) {
			t.Fatalf("UDP reply %x, want %x", packet[:n], want)
		}
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}

	// A signed client can open a UDP stream, but that does not grant it access
	// to destinations outside the allowlist. A later allowed datagram still works.
	deniedListener, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP("127.0.0.2")})
	if err != nil {
		t.Fatal(err)
	}
	defer deniedListener.Close()
	denied := deniedListener.LocalAddr().(*net.UDPAddr).AddrPort()
	raw, err := client.open(t.Context(), trusttunnel.UDPAuthority)
	if err != nil {
		t.Fatal(err)
	}
	defer raw.Close()
	source := netip.MustParseAddrPort("127.0.0.1:50000")
	for _, target := range []netip.AddrPort{denied, udp1} {
		if err := trusttunnel.WriteRequest(raw, trusttunnel.Datagram{Source: source, Destination: target, Payload: []byte("payload")}); err != nil {
			t.Fatal(err)
		}
	}
	packet, err := trusttunnel.ReadResponse(raw)
	if err != nil || packet.Source != udp1 || packet.Destination != source || string(packet.Payload) != "payload" {
		t.Fatalf("UDP authorization on a shared stream: %+v, %v", packet, err)
	}
	if err := deniedListener.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatal(err)
	}
	var deniedPayload [16]byte
	if _, _, err := deniedListener.ReadFromUDP(deniedPayload[:]); err == nil {
		t.Fatal("an unauthorized UDP packet reached its destination")
	}
}

func TestTrustTunnelRejectsMissingAndUntrustedClientCertificate(t *testing.T) {
	serverConfig, trusted := testTLS(t)
	_, other := testTLS(t)
	listener := localTCP(t)
	startTestServer(t, func(ctx context.Context) error { return serveTunnel(ctx, listener, serverConfig, &tunnelHandler{}) })
	for name, certificates := range map[string][]tls.Certificate{"missing": nil, "untrusted": other.Certificates} {
		t.Run(name, func(t *testing.T) {
			config := trusted.Clone()
			config.Certificates = certificates
			client := newTunnelClient(listener.Addr().String(), config)
			defer client.closeIdleConnections()
			if stream, err := client.open(t.Context(), "_check"); err == nil {
				stream.Close()
				t.Fatal("invalid client was admitted")
			}
		})
	}
	t.Run("untrusted-server", func(t *testing.T) {
		config := trusted.Clone()
		config.RootCAs = other.RootCAs
		client := newTunnelClient(listener.Addr().String(), config)
		defer client.closeIdleConnections()
		if stream, err := client.open(t.Context(), "_check"); err == nil {
			stream.Close()
			t.Fatal("untrusted server was accepted")
		}
	})
}

func localTCP(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	return listener
}

func startTestServer(t *testing.T, serve func(context.Context) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	done := make(chan error, 1)
	go func() { done <- serve(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Error(err)
			}
		case <-time.After(3 * time.Second):
			t.Error("server shutdown timed out")
		}
	})
}

func socksRequest(t *testing.T, listener net.Listener, command byte, target netip.AddrPort) (*net.TCPConn, byte, netip.AddrPort) {
	t.Helper()
	connection, err := net.DialTimeout("tcp", listener.Addr().String(), 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	conn := connection.(*net.TCPConn)
	t.Cleanup(func() { _ = conn.Close() })
	if err := conn.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	var hello [2]byte
	if _, err := io.ReadFull(conn, hello[:]); err != nil || hello != [2]byte{5, 0} {
		t.Fatalf("SOCKS5 greeting %v, %v", hello, err)
	}
	if _, err := conn.Write(appendSOCKSAddress([]byte{5, command, 0}, target)); err != nil {
		t.Fatal(err)
	}
	var reply [3]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || reply[0] != 5 {
		t.Fatalf("SOCKS5 reply %v, %v", reply, err)
	}
	host, port, err := readSOCKSAddress(conn)
	if err != nil {
		t.Fatal(err)
	}
	return conn, reply[1], netip.MustParseAddrPort(net.JoinHostPort(host, strconv.Itoa(int(port))))
}

func udpEcho(t *testing.T, host string) netip.AddrPort {
	t.Helper()
	conn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.ParseIP(host)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	go func() {
		var buffer [65535]byte
		for {
			n, peer, err := conn.ReadFromUDPAddrPort(buffer[:])
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDPAddrPort(buffer[:n], peer)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr).AddrPort()
}

func testTLS(t *testing.T) (*tls.Config, *tls.Config) {
	t.Helper()
	return testTLSWithServerUsage(t, x509.ExtKeyUsageServerAuth)
}

func testTLSWithServerUsage(t *testing.T, serverUsage ...x509.ExtKeyUsage) (*tls.Config, *tls.Config) {
	t.Helper()
	caPub, caKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ca := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "proxy test CA"}, IsCA: true,
		BasicConstraintsValid: true, NotAfter: time.Now().Add(time.Hour), KeyUsage: x509.KeyUsageCertSign}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, caPub, caKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root)

	leaf := func(serial int64, usages ...x509.ExtKeyUsage) tls.Certificate {
		pub, private, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		cert := &x509.Certificate{SerialNumber: big.NewInt(serial), NotAfter: ca.NotAfter, KeyUsage: x509.KeyUsageDigitalSignature,
			IPAddresses: []net.IP{net.IPv4(127, 0, 0, 1)}, ExtKeyUsage: usages}
		der, err := x509.CreateCertificate(rand.Reader, cert, root, pub, caKey)
		if err != nil {
			t.Fatal(err)
		}
		return tls.Certificate{Certificate: [][]byte{der, root.Raw}, PrivateKey: private}
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf(2, serverUsage...)}, ClientAuth: tls.RequireAndVerifyClientCert, ClientCAs: pool},
		&tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{leaf(3, x509.ExtKeyUsageClientAuth)}, RootCAs: pool}
}

func TestSOCKSAddressDomain(t *testing.T) {
	data := binary.BigEndian.AppendUint16(append([]byte{socksDomain, 11}, "example.org"...), 443)
	if host, port, err := readSOCKSAddress(bytes.NewReader(data)); err != nil || host != "example.org" || port != 443 {
		t.Fatalf("domain address: %q:%d, %v", host, port, err)
	}
}
