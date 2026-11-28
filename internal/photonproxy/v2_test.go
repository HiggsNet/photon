package photonproxy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

func TestV2CompactSignedRoute(t *testing.T) {
	public, key, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1800000000, 0)
	origin := zone.ZonePath("quark.catofes.")
	route := "less@h26,child/truenas@h2p"
	target := "tcp=192.168.50.10:443"
	header, err := signV2Route(key, origin, route, target, now)
	if err != nil {
		t.Fatal(err)
	}
	size := len(":method") + len("CONNECT") + len(":authority") + len(v2Authority)
	for name, values := range header {
		size += len(name) + len(values[0])
	}
	if size != 292 {
		t.Fatalf("header budget got %d bytes", size)
	}
	grant, err := parseV2Grant(header.Get(v2AuthHeader))
	if err != nil {
		t.Fatal(err)
	}
	encoded := delegationEncoding.EncodeToString(public)
	if !grant.verifies(encoded, route, target, now) {
		t.Fatal("valid signed route was rejected")
	}
	if grant.verifies(encoded, strings.Replace(route, "h26", "h24", 1), target, now) ||
		grant.verifies(encoded, route, "tcp=192.168.50.10:445", now) ||
		grant.verifies(encoded, route, target, now.Add(v2Lifetime+v2ClockSkew)) {
		t.Fatal("mutated or expired request verified")
	}
	if !grant.verifies(encoded, route, target, now.Add(-v2ClockSkew)) ||
		!grant.verifies(encoded, route, target, now.Add(v2ClockSkew)) ||
		grant.verifies(encoded, route, target, now.Add(-v2ClockSkew-time.Millisecond)) {
		t.Fatal("clock-skew boundary was not enforced")
	}
	hops, err := v2Hops("less@h26,remote.other./truenas@h2p", origin)
	if err != nil || hops[0].Zone != "less.catofes." || hops[0].Endpoint != "relay" || hops[1].Zone != "remote.other." {
		t.Fatalf("bad expansion: %+v %v", hops, err)
	}
	if _, err := v2Hops("less/forward@h26,child@h2p", origin); err == nil {
		t.Fatal("middle hop accepted an extra relay ID")
	}
	if _, err := v2Hops("less@h26,less.catofes.@h2p", origin); err == nil {
		t.Fatal("accepted repeated absolute Zone")
	}
}

type v2Fixture struct {
	mu    sync.Mutex
	peers map[zone.ZonePath]service.ProxyV2Peer
}

func (f *v2Fixture) view(path zone.ZonePath) service.ProxyDirectory {
	f.mu.Lock()
	defer f.mu.Unlock()
	copy := make(map[zone.ZonePath]service.ProxyV2Peer)
	for name, peer := range f.peers {
		copy[name] = peer
	}
	if _, ok := copy[path]; !ok {
		copy[path] = service.ProxyV2Peer{Mesh: []string{"127.0.0.1"}}
	}
	return service.ProxyDirectory{ManagedZone: path, ValidUntil: time.Now().Add(time.Minute), V2: copy}
}

func (f *v2Fixture) publisher(conn net.Conn, path zone.ZonePath) {
	defer conn.Close()
	var publication service.ProxyV2Publication
	if json.NewDecoder(conn).Decode(&publication) != nil {
		return
	}
	peer := service.ProxyV2Peer{Mesh: []string{"127.0.0.1"}, TLS: map[string]service.ProxyV2TLS{}, Endpoints: map[string]service.ProxyV2Endpoint{}}
	for _, item := range publication.Records {
		record, _, err := service.ParseProxyV2Record(item)
		if err != nil {
			_ = json.NewEncoder(conn).Encode(service.ProxyV2PublicationResult{Error: err.Error()})
			return
		}
		switch value := record.(type) {
		case *service.ProxyV2Identity:
			peer.Identity = value
		case *service.ProxyV2Endpoint:
			peer.Endpoints[strings.TrimPrefix(item.Key, service.ProxyV2EndpointPrefix)] = *value
		case *service.ProxyV2TLS:
			peer.TLS[strings.TrimPrefix(item.Key, service.ProxyV2TLSPrefix)] = *value
		}
	}
	f.mu.Lock()
	f.peers[path] = peer
	f.mu.Unlock()
	_ = json.NewEncoder(conn).Encode(service.ProxyV2PublicationResult{OK: true})
}

func newV2FixtureNode(t *testing.T, f *v2Fixture, path zone.ZonePath, config v2Config, dir string) (*v2Node, func()) {
	t.Helper()
	ctx, cancel := context.WithCancel(t.Context())
	if dir == "" {
		dir = t.TempDir()
	}
	config.StateDir = dir
	config.PublishSocket = filepath.Join(dir, "daemon-write.sock")
	config.DirectorySocket = filepath.Join(dir, "daemon-read.sock")
	var fixtureWorkers sync.WaitGroup
	if config.TLS.Lifetime == 0 {
		config.TLS = v2TLSConfig{Lifetime: 365 * 24 * time.Hour, RenewBefore: 30 * 24 * time.Hour, Overlap: time.Minute}
	}
	listener, err := net.Listen("unix", config.PublishSocket)
	if err != nil {
		t.Fatal(err)
	}
	fixtureWorkers.Go(func() {
		defer listener.Close()
		stop := context.AfterFunc(ctx, func() { _ = listener.Close() })
		defer stop()
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			f.publisher(conn, path)
		}
	})
	db, _, err := openRouteState(filepath.Join(dir, "state.db"), nil)
	if err != nil {
		t.Fatal(err)
	}
	state, err := db.loadV2()
	if err != nil {
		t.Fatal(err)
	}
	directory := &proxyDirectory{view: f.view(path)}
	node := &v2Node{ctx: ctx, config: config, db: db, state: state, directory: directory, pool: &v2DialPool{},
		host: Host{Publish: func(ctx context.Context, publication service.ProxyV2Publication) error {
			return sendV2Publication(ctx, config.PublishSocket, publication)
		}},
		listeners: map[v2ListenerKey][]*v2Listener{}, errors: make(chan error, 1)}
	if namespace, ok := config.directNamespace(); ok {
		node.pool.directLinks = &directLinks{namespace: namespace}
		node.pool.direct = &directPool{ctx: ctx, entries: make(map[directPoolKey]*directPoolEntry)}
	}
	var once sync.Once
	stopNode := func() {
		once.Do(func() {
			cancel()
			for _, listeners := range node.listeners {
				for _, listener := range listeners {
					_ = listener.http.Close()
					_ = listener.listener.Close()
				}
			}
			node.workers.Wait()
			fixtureWorkers.Wait()
			node.pool.close()
			_ = db.Close()
			_ = os.Remove(config.PublishSocket)
			_ = os.Remove(config.DirectorySocket)
		})
	}
	t.Cleanup(stopNode)
	if err := node.start(); err != nil {
		t.Fatal(err)
	}
	return node, stopNode
}

func v2TestPortRange(t *testing.T, width uint16) uint16 {
	t.Helper()
	for range 32 {
		first, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		base := uint16(first.Addr().(*net.TCPAddr).Port)
		listeners := []net.Listener{first}
		fits := true
		for offset := uint16(1); offset < width; offset++ {
			listener, err := net.Listen("tcp4", fmt.Sprintf("127.0.0.1:%d", base+offset))
			if err != nil {
				fits = false
				break
			}
			listeners = append(listeners, listener)
		}
		for _, listener := range listeners {
			_ = listener.Close()
		}
		if fits {
			return base
		}
	}
	t.Fatal("no test port range")
	return 0
}

func TestV2RelayExitAndRotation(t *testing.T) {
	fixture := &v2Fixture{peers: map[zone.ZonePath]service.ProxyV2Peer{}}
	origin, relay, exit := zone.ZonePath("a.example."), zone.ZonePath("b.example."), zone.ZonePath("c.example.")
	base := v2TestPortRange(t, 3)
	portGroups := map[string]v2PortConfig{"mesh": {Bind: []string{"127.0.0.1"}, Range: []uint16{base, base + 2}}}
	binding := service.ProxyV2Binding{Addresses: []service.ProxyV2Address{{Source: "route-local", Via: []string{"photon"}, PortSet: "mesh"}}}
	policy := service.ProxyV2ZonePolicy{AcceptFrom: []string{origin.String()}}
	exitPolicy := service.ProxyV2ExitPolicy{ProxyV2ZonePolicy: policy, AcceptTo: []service.ProxyV2Destination{{CIDR: "127.0.0.1/32"}}}
	b, stopB := newV2FixtureNode(t, fixture, relay, v2Config{Client: &v2ClientConfig{},
		Relay: &v2RelayConfig{Bindings: []service.ProxyV2Binding{binding}, ProxyV2RelayPolicy: service.ProxyV2RelayPolicy{
			ProxyV2ZonePolicy: policy, AcceptTo: []string{"re:c\\.example\\."},
		}}, Exits: map[string]v2ExitConfig{"truenas": {Bindings: []service.ProxyV2Binding{binding}, ProxyV2ExitPolicy: exitPolicy}}, PortGroups: portGroups,
	}, "")
	exitPort := v2TestPortRange(t, 1)
	c, _ := newV2FixtureNode(t, fixture, exit, v2Config{
		Exits: map[string]v2ExitConfig{"truenas": {
			Bindings: []service.ProxyV2Binding{binding}, AdvertisePolicy: true,
			ProxyV2ExitPolicy: service.ProxyV2ExitPolicy{
				ProxyV2ZonePolicy: service.ProxyV2ZonePolicy{AcceptFrom: []string{origin.String(), relay.String()}},
				AcceptTo:          exitPolicy.AcceptTo,
			},
		}},
		PortGroups: map[string]v2PortConfig{"mesh": {Bind: []string{"127.0.0.1"}, Port: exitPort}},
	}, "")
	a, _ := newV2FixtureNode(t, fixture, origin, v2Config{Client: &v2ClientConfig{
		DefaultListen: "0.0.0.0:0", AllowedSources: []string{"127.0.0.1/32"},
		Admin: v2AdminConfig{Token: "test-secret", Web: true},
	}}, "")
	refresh := func() {
		for path, node := range map[zone.ZonePath]*v2Node{origin: a, relay: b, exit: c} {
			view := fixture.view(path)
			node.directory.update(&view, time.Now())
		}
	}
	refresh()
	client := &v2Client{directory: a.directory, pool: a.pool, key: a.key, route: "b@h2p,c/truenas@h2p"}
	target, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	go func() {
		for {
			conn, err := target.Accept()
			if err != nil {
				return
			}
			go func() { defer conn.Close(); _, _ = io.Copy(conn, conn) }()
		}
	}()
	ctx, cancel := context.WithTimeout(t.Context(), 15*time.Second)
	defer cancel()
	stream, err := client.open(ctx, target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer stream.Close()
	assertEcho := func(stream *tunnelStream) {
		t.Helper()
		if _, err := stream.Write([]byte("hello")); err != nil {
			t.Fatal(err)
		}
		reply := make([]byte, 5)
		if _, err := io.ReadFull(stream, reply); err != nil || string(reply) != "hello" {
			t.Fatalf("echo %q, %v", reply, err)
		}
	}
	assertEcho(stream)
	probeSite := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/generate_204":
			w.WriteHeader(http.StatusNoContent)
		case "/__down":
			_, _ = w.Write(make([]byte, v2DownloadBytes))
		default:
			http.NotFound(w, r)
		}
	}))
	defer probeSite.Close()
	testTLS := probeSite.Client().Transport.(*http.Transport).TLSClientConfig
	var connectivity, download v2ProbeResult
	if err := probeV2HTTPS(ctx, client, probeSite.URL+"/generate_204", http.StatusNoContent, 0, testTLS, &connectivity); err != nil ||
		connectivity.HTTPStatus != http.StatusNoContent {
		t.Fatalf("HTTPS connectivity probe: %+v, %v", connectivity, err)
	}
	if err := probeV2HTTPS(ctx, client, probeSite.URL+"/__down", http.StatusOK, v2DownloadBytes, testTLS, &download); err != nil ||
		download.Bytes != v2DownloadBytes || download.DownloadMbps <= 0 {
		t.Fatalf("HTTPS download probe: %+v, %v", download, err)
	}
	socksManager, err := b.startClient(map[string]clientRoute{"local": {Listen: "127.0.0.1:0", Hops: []string{"c/truenas@photon"}}})
	if err != nil {
		t.Fatal(err)
	}
	defer socksManager.close()
	viaSOCKS, status, _ := socksRequest(t, socksManager.listeners["local"].listener, socksConnect, target.Addr().(*net.TCPAddr).AddrPort())
	if status != socksSucceeded {
		t.Fatalf("relay's own SOCKS5 Client returned %d", status)
	}
	if _, err := viaSOCKS.Write([]byte("socks")); err != nil {
		t.Fatal(err)
	}
	echo := make([]byte, 5)
	if _, err := io.ReadFull(viaSOCKS, echo); err != nil || string(echo) != "socks" {
		t.Fatalf("SOCKS5 echo %q: %v", echo, err)
	}
	_ = viaSOCKS.Close()
	socksManager.close()
	direct := *client
	direct.route = "b/truenas@h2p"
	viaLocalExit, err := direct.open(ctx, target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	assertEcho(viaLocalExit)
	_ = viaLocalExit.Close()

	for i := 0; i < 2; i++ {
		if err := b.stagePort("mesh"); err != nil {
			t.Fatal(err)
		}
		if err := b.publish(); err != nil {
			t.Fatal(err)
		}
		refresh()
		got := fixture.view(origin).V2[relay].Endpoints["relay"].Bindings[0].PortSets["mesh"]
		if got.Current.Port != base+1+uint16(i) || got.Previous.Port != base+uint16(i) {
			t.Fatalf("unexpected generations %+v", got)
		}
		previous := b.listeners[v2ListenerKey{"mesh", got.Previous.Port}]
		for _, listener := range previous {
			listener.enabled.Store(false)
		}
		fresh, err := client.open(ctx, target.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		assertEcho(fresh)
		_ = fresh.Close()
		for _, listener := range previous {
			listener.enabled.Store(true)
		}
		assertEcho(stream)
	}
	ports, err := b.db.loadV2()
	if err != nil || ports.Ports["mesh"].Current.Port != base+2 || ports.Pending != nil {
		t.Fatalf("rotation not persisted: %+v %v", ports.Ports, err)
	}
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	go func() {
		var payload [64]byte
		for {
			length, from, err := udp.ReadFromUDP(payload[:])
			if err != nil {
				return
			}
			reply := payload[:length]
			if length == 29 {
				reply[2] |= 0x80
				reply[7] = 1
				reply = append(reply, 0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1)
			}
			_, _ = udp.WriteToUDP(reply, from)
		}
	}()
	datagrams, err := client.open(ctx, trusttunnel.UDPAuthority)
	if err != nil {
		t.Fatal(err)
	}
	defer datagrams.Close()
	packet := trusttunnel.Datagram{Source: netip.MustParseAddrPort("127.0.0.1:41000"), Destination: udp.LocalAddr().(*net.UDPAddr).AddrPort(), Payload: []byte("udp")}
	if err := trusttunnel.WriteRequest(datagrams, packet); err != nil {
		t.Fatal(err)
	}
	reply, err := trusttunnel.ReadResponse(datagrams)
	if err != nil || string(reply.Payload) != "udp" || reply.Source != packet.Destination {
		t.Fatalf("UDP echo: %+v, %v", reply, err)
	}
	list := v2ListCandidates(fixture.view(origin), "tcp", target.Addr().(*net.TCPAddr).AddrPort(), time.Now())
	if len(list.Paths) != 2 {
		t.Fatalf("unexpected direct and relay paths: %v", list.Paths)
	}

	manager, err := a.startClient(nil)
	if err != nil {
		t.Fatal(err)
	}
	defer manager.close()
	handler := a.v2AdminHandler(manager, "127.0.0.1:1234", true)
	callAdmin := func(method, path, body string) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		request.Header.Set("Authorization", "Bearer test-secret")
		if body != "" {
			request.Header.Set("Content-Type", "application/json")
		}
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		return response
	}
	admin := callAdmin(http.MethodGet, "/v1/admin", "")
	if admin.Code != http.StatusOK || !strings.Contains(admin.Body.String(), `"socks5_default_listen":"0.0.0.0:0"`) ||
		!strings.Contains(admin.Body.String(), `"socks5_allowed_sources":["127.0.0.1/32"]`) {
		t.Fatalf("admin settings %d: %s", admin.Code, admin.Body)
	}
	request := httptest.NewRequest(http.MethodGet, "/v1/endpoints", nil)
	request.Header.Set("Authorization", "Bearer test-secret")
	result := httptest.NewRecorder()
	handler.ServeHTTP(result, request)
	var peers v2EndpointDirectory
	if err := json.Unmarshal(result.Body.Bytes(), &peers); err != nil || result.Code != http.StatusOK {
		t.Fatalf("endpoints response %d: %s, %v", result.Code, result.Body, err)
	}
	if !peers.Ready || peers.Origin != origin || len(peers.Relays) != 1 || peers.Relays[0].Zone != relay ||
		len(peers.Exits) != 2 || peers.Exits[0].Zone != relay || peers.Exits[0].Discoverable ||
		peers.Exits[1].Zone != exit || !peers.Exits[1].Discoverable || strings.Contains(result.Body.String(), `"paths"`) {
		t.Fatalf("directory mixed path suggestions with announced endpoints: %s", result.Body)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/routes", strings.NewReader(`{"name":"test","hops":["b@h2p","c/truenas@h2p"]}`))
	request.Header.Set("Content-Type", "application/json")
	result = httptest.NewRecorder()
	handler.ServeHTTP(result, request)
	if result.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated API returned %d", result.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/v1/routes", strings.NewReader(`{"name":"test","hops":["b@h2p","c/truenas@h2p"]}`))
	request.Header.Set("Content-Type", "application/json")
	request.Header.Set("Authorization", "Bearer test-secret")
	result = httptest.NewRecorder()
	handler.ServeHTTP(result, request)
	if result.Code != http.StatusCreated {
		t.Fatalf("create %d %s", result.Code, result.Body)
	}
	before := manager.list()[0].Listen
	listen, err := netip.ParseAddrPort(before)
	if err != nil || listen.Addr() != netip.IPv4Unspecified() || listen.Port() == 0 {
		t.Fatalf("expected IPv4 wildcard bind with an allocated port, got %s (%v)", before, err)
	}
	loopback := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), listen.Port()).String()
	if conn, err := net.DialTimeout("tcp4", loopback, time.Second); err != nil {
		t.Fatalf("IPv4 wildcard listener: %v", err)
	} else {
		_ = conn.Close()
	}
	const probePath = "/v1/routes/test/probe"
	dns := callAdmin(http.MethodPost, probePath, fmt.Sprintf(`{"protocol":"udp","target":%q}`, udp.LocalAddr().String()))
	var dnsResult v2ProbeResult
	if err := json.Unmarshal(dns.Body.Bytes(), &dnsResult); err != nil || dns.Code != http.StatusOK || !dnsResult.OK {
		t.Fatalf("saved-route UDP DNS probe %d: %s (%v)", dns.Code, dns.Body, err)
	}
	if response := callAdmin(http.MethodPost, "/v1/probe", `{"kind":"download"}`); response.Code != http.StatusBadRequest {
		t.Fatalf("preset without a saved route: %d %s", response.Code, response.Body)
	}
	if _, err := manager.replace("test", clientRoute{Hops: []string{"c/truenas@h2p"}}); err != nil || manager.list()[0].Listen != before {
		t.Fatalf("replace failed: %v", err)
	}
	fixed := fmt.Sprintf("127.0.0.1:%d", v2TestPortRange(t, 1))
	response := callAdmin(http.MethodPost, "/v1/routes", fmt.Sprintf(`{"name":"fixed","listen":%q,"hops":["c/truenas@h2p"]}`, fixed))
	if response.Code != http.StatusCreated || manager.listeners["fixed"].listener.Addr().String() != fixed {
		t.Fatalf("fixed listener %s returned %d %s", fixed, response.Code, response.Body)
	}
	if response := callAdmin(http.MethodDelete, "/v1/routes/test", ""); response.Code != http.StatusNoContent {
		t.Fatalf("delete %d %s", response.Code, response.Body)
	}
	if conn, err := net.DialTimeout("tcp4", loopback, time.Second); err == nil {
		_ = conn.Close()
		t.Fatal("deleted route still accepts connections")
	}
	if response := callAdmin(http.MethodPost, probePath, `{"kind":"dns"}`); response.Code != http.StatusNotFound {
		t.Fatalf("deleted route still eligible for testing: %d %s", response.Code, response.Body)
	}
	result = httptest.NewRecorder()
	handler.ServeHTTP(result, httptest.NewRequest(http.MethodGet, "/ui", nil))
	if result.Code != http.StatusOK || !strings.Contains(result.Body.String(), "Photon Proxy") {
		t.Fatalf("UI status %d", result.Code)
	}

	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	view := fixture.view(origin)
	peer := view.V2[relay]
	bad := peer.TLS["node"]
	fake := service.ProxyV2TLS{ProxyV2Lease: bad.ProxyV2Lease, Pins: []string{fmt.Sprintf("%064x", other)}}
	peer.TLS = map[string]service.ProxyV2TLS{"node": fake}
	view.V2[relay] = peer
	a.directory.update(&view, time.Now())
	_, err = client.open(ctx, target.Addr().String())
	var hop *v2HopError
	if !errors.As(err, &hop) || hop.code != "dial_failed" || hop.index != 0 {
		t.Fatalf("bad pin result %v", err)
	}

	// Restart the publisher with its durable key and both port generations.
	_ = stream.Close()
	_ = datagrams.Close()
	beforePin := fixture.view(origin).V2[relay].TLS["node"].Pins[0]
	beforeKey := fixture.view(origin).V2[relay].Identity.PublicKey
	config := b.config
	stopB()
	b, _ = newV2FixtureNode(t, fixture, relay, config, config.StateDir)
	refresh()
	restored := fixture.view(origin).V2[relay]
	if restored.TLS["node"].Pins[0] != beforePin || restored.Identity.PublicKey != beforeKey ||
		b.state.Ports["mesh"].Current.Port != base+2 || b.state.Ports["mesh"].Previous.Port != base+1 {
		t.Fatal("restart lost persisted proxy identity or previous port")
	}
	fresh, err := client.open(ctx, target.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	assertEcho(fresh)
	_ = fresh.Close()
	if err := requestV2Rotation(config.StateDir, v2RotationRequest{ID: "test-key-change", TLS: true}); err != nil {
		t.Fatal(err)
	}
	if err := b.tick(); err != nil {
		t.Fatal(err)
	}
	dual := fixture.view(origin).V2[relay].TLS["node"].Pins
	if len(dual) != 2 || dual[0] != beforePin || dual[1] == beforePin {
		t.Fatalf("rotation must publish overlapping pins: %v", dual)
	}
	b.state.TLS.ActivateAt = time.Now().Add(-time.Second)
	if err := b.tick(); err != nil {
		t.Fatal(err)
	}
	if pin := service.ProxyPublicKeyID(b.certificate.Load().Leaf); pin != dual[1] {
		t.Fatal("staged TLS key did not activate")
	}
	b.state.TLS.RetireAt = time.Now().Add(-time.Second)
	if err := b.tick(); err != nil {
		t.Fatal(err)
	}
	remaining := fixture.view(origin).V2[relay].TLS["node"].Pins
	if len(remaining) != 1 || remaining[0] != dual[1] {
		t.Fatalf("old TLS pin not retired: %v", remaining)
	}
}
