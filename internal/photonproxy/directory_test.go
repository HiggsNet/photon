package photonproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/pkg/core/zone"
	photoncrypto "github.com/HiggsNet/photon/pkg/crypto"
	"github.com/HiggsNet/photon/pkg/service"
)

func TestDirectoryRefreshKeepsCachedRevisionAndExpiresLeaseLocally(t *testing.T) {
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	now := time.Now()
	leaseUntil := now.Add(2 * time.Second).Truncate(time.Second)
	network := zone.NewNetworkState()
	rootPublic, rootKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	peerPublic, peerKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	root := zone.RootZone
	peer := zone.ZonePath("test.")
	network.Zones[root] = zone.NewZoneState(root, &zone.ZoneAuthority{Zone: root, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{Key: rootPublic}}})
	authority := zone.ZoneAuthority{Zone: peer, Epoch: 1, Threshold: 1, Keys: []zone.AuthorizedKey{{
		Key: peerPublic, Capabilities: []zone.Capability{{Permissions: []zone.Permission{zone.PermWrite}}},
	}}}
	delegation := &zone.Delegation{ZoneName: peer, Authority: authority}
	if err := photoncrypto.SignDelegation(delegation, root, rootKey); err != nil {
		t.Fatal(err)
	}
	network.Zones[root].Delegations[peer] = delegation
	network.Zones[peer] = zone.NewZoneState(peer, &authority)
	body, err := json.Marshal(service.ProxyV2Identity{
		ProxyV2Lease: service.ProxyV2Lease{Active: true, ExpiresAt: leaseUntil.Unix()},
		PublicKey:    delegationEncoding.EncodeToString(peerPublic),
	})
	if err != nil {
		t.Fatal(err)
	}
	record := &zone.Record{Zone: peer, Key: service.ProxyV2IdentityKey, Type: service.ProxyV2IdentityType, Version: 1, Value: body}
	if err := photoncrypto.SignRecord(record, peerKey); err != nil {
		t.Fatal(err)
	}
	network.Zones[peer].Records[record.Key] = record
	socket := filepath.Join(t.TempDir(), "read.sock")
	listener, err := net.Listen("unix", socket)
	if err != nil {
		t.Fatal(err)
	}
	requests := make(chan service.ProxyReadRequest, 10)
	defer listener.Close()
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			var request service.ProxyReadRequest
			if json.NewDecoder(conn).Decode(&request) == nil {
				requests <- request
				reply := service.ProxyReadResponse{Epoch: "test-epoch", Revision: 7}
				if request.Epoch == "" {
					reply.ManagedZone, reply.Network = peer, network
				}
				_ = json.NewEncoder(conn).Encode(reply)
			}
			_ = conn.Close()
		}
	}()
	dir, err := openProxyDirectoryWithRefresh(ctx, socket, 250*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if first := <-requests; first.Kind != service.ProxyReadDirectory || first.Epoch != "" {
		t.Fatalf("initial request = %+v", first)
	}
	watch, release, ok := dir.watchV2(ctx, func(view service.ProxyDirectory, now time.Time) bool {
		identity := view.V2[peer].Identity
		return identity != nil && identity.ValidAt(now)
	})
	if !ok {
		t.Fatal("initial signed record was unavailable")
	}
	defer release()
	select {
	case next := <-requests:
		if next.Epoch != "test-epoch" || next.Revision != 7 {
			t.Fatalf("next request = %+v", next)
		}
	case <-time.After(time.Second):
		t.Fatal("no conditional refresh")
	}
	select {
	case <-watch.Done():
		if time.Now().Before(leaseUntil) || dir.snapshotV2().V2[peer].Identity != nil {
			t.Fatal("lease did not expire locally at its boundary")
		}
	case <-time.After(time.Until(leaseUntil) + time.Second):
		t.Fatal("expired lease retained the active session")
	}
}

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
