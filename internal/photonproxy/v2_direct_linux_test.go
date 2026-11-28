package photonproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/trusttunnel"
	"github.com/HiggsNet/photon/pkg/core/zone"
	"github.com/HiggsNet/photon/pkg/service"
)

func TestV2DirectLinkRotation(t *testing.T) {
	if os.Getenv("PHOTON_PROXY_DIRECT_SMOKE") != "1" {
		t.Skip("set PHOTON_PROXY_DIRECT_SMOKE=1 inside a private mount and network namespace")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	suffix := strconv.Itoa(os.Getpid())
	nsA, nsB := "photon-proxy-a-"+suffix, "photon-proxy-b-"+suffix
	ip := func(args ...string) {
		t.Helper()
		if out, err := exec.CommandContext(ctx, "ip", args...).CombinedOutput(); err != nil {
			t.Fatalf("ip %v: %v: %s", args, err, out)
		}
	}
	for _, ns := range []string{nsA, nsB} {
		ip("netns", "add", ns)
		t.Cleanup(func() { _ = exec.Command("ip", "netns", "del", ns).Run() })
		ip("-n", ns, "link", "set", "lo", "up")
	}
	ip("link", "add", "underlay-a", "netns", nsA, "type", "veth", "peer", "name", "underlay-b", "netns", nsB)
	for index, ns := range []string{nsA, nsB} {
		device := []string{"underlay-a", "underlay-b"}[index]
		ip("-n", ns, "link", "set", device, "up")
		ip("-n", ns, "addr", "add", fmt.Sprintf("192.0.2.%d/30", index+1), "dev", device)
		ip("-n", ns, "-6", "addr", "add", fmt.Sprintf("fd00:ffff::%d/64", index+1), "dev", device, "nodad")
	}

	from, to := zone.ZonePath("from.catofes."), zone.ZonePath("to.catofes.")
	makeLink := func(gen int, family string, staged bool) (service.ProxyDirectLink, service.ProxyDirectLink) {
		t.Helper()
		a, b := fmt.Sprintf("phxa%d", gen), fmt.Sprintf("phxb%d", gen)
		local := netip.MustParseAddr(fmt.Sprintf("fe80::%d:1", gen))
		remote := netip.MustParseAddr(fmt.Sprintf("fe80::%d:2", gen))
		devices := []string{a, b}
		inner := []string{local.String(), remote.String()}
		outer := []string{"192.0.2.1", "192.0.2.2"}
		if family == "ipv6" {
			outer = []string{"fd00:ffff::1", "fd00:ffff::2"}
		}
		ifID := strconv.Itoa(gen)
		for side, ns := range []string{nsA, nsB} {
			ip("-n", ns, "link", "add", devices[side], "type", "xfrm", "if_id", ifID)
			ip("-n", ns, "link", "set", devices[side], "addrgenmode", "none")
			ip("-n", ns, "-6", "addr", "add", inner[side]+"/64", "dev", devices[side], "nodad")
			ip("-n", ns, "link", "set", devices[side], "up")
			for from := range outer {
				dest := 1 - from
				ip("-n", ns, "xfrm", "state", "add", "src", outer[from], "dst", outer[dest],
					"proto", "esp", "spi", strconv.Itoa(256*gen+from), "reqid", ifID, "mode", "tunnel",
					"sel", "src", inner[from]+"/128", "dst", inner[dest]+"/128", "if_id", ifID,
					"auth", "hmac(sha256)", "0x1111111111111111111111111111111111111111111111111111111111111111",
					"enc", "cbc(aes)", "0x22222222222222222222222222222222")
				direction := "out"
				if from != side {
					direction = "in"
				}
				ip("-n", ns, "xfrm", "policy", "add", "dir", direction, "if_id", ifID,
					"src", inner[from]+"/128", "dst", inner[dest]+"/128", "tmpl",
					"src", outer[from], "dst", outer[dest], "proto", "esp", "reqid", ifID, "mode", "tunnel")
			}
		}
		ip("netns", "exec", nsA, "ping", "-6", "-c", "1", "-W", "2", remote.String()+"%"+a)
		left := service.ProxyDirectLink{ID: family, Peer: to, NetNS: nsA, Interface: a, Local: local, Remote: remote,
			Family: family, Generation: uint64(gen), Staged: staged}
		right := left
		right.Peer, right.NetNS, right.Interface, right.Local, right.Remote = from, nsB, b, remote, local
		return left, right
	}
	oldA, oldB := makeLink(1, "ipv4", false)
	newA, newB := makeLink(2, "ipv4", true)
	v6A, v6B := makeLink(3, "ipv6", false)

	fixture := &v2Fixture{peers: make(map[zone.ZonePath]service.ProxyV2Peer)}
	target := localTCP(t)
	defer target.Close()
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
	port := reserveTCPPort(t)
	b, _ := newV2FixtureNode(t, fixture, to, v2Config{
		LinkNamespace: nsB,
		PortGroups:    map[string]v2PortConfig{"direct": {LinkLocal: true, Port: port}},
		Exits: map[string]v2ExitConfig{"exit": {
			Bindings: []service.ProxyV2Binding{{Addresses: []service.ProxyV2Address{{
				Source: "link-local", Via: []string{"link-local-v4", "link-local-v6"}, PortSet: "direct",
			}}}},
			ProxyV2ExitPolicy: service.ProxyV2ExitPolicy{
				ProxyV2ZonePolicy: service.ProxyV2ZonePolicy{AcceptFrom: []string{from.String()}},
				AcceptTo:          []service.ProxyV2Destination{{CIDR: "127.0.0.1/32"}},
			},
		}},
	}, "")
	a, _ := newV2FixtureNode(t, fixture, from, v2Config{LinkNamespace: nsA, Client: &v2ClientConfig{DefaultListen: "127.0.0.1:0"}}, "")
	for _, node := range []*v2Node{a, b} {
		view := fixture.view(node.directory.managedZone())
		node.directory.update(&view, time.Now())
	}
	load := func(node *v2Node, links ...service.ProxyDirectLink) {
		node.pool.directLinks.snapshot.Store(&directSnapshot{links: links, until: time.Now().Add(time.Minute)})
	}
	load(a, oldA, v6A)
	load(b, oldB, v6B)
	client := &v2Client{directory: a.directory, pool: a.pool, key: a.key, route: "to@h2l4"}
	open := func() *tunnelStream {
		t.Helper()
		stream, err := client.open(ctx, target.Addr().String())
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = stream.Close() })
		return stream
	}
	echo := func(stream *tunnelStream) {
		t.Helper()
		if _, err := stream.Write([]byte("x")); err != nil {
			t.Fatal(err)
		}
		var data [1]byte
		if _, err := io.ReadFull(stream, data[:]); err != nil || data[0] != 'x' {
			t.Fatalf("echo = %q (%v)", data, err)
		}
	}
	ip("-n", nsA, "-6", "route", "replace", oldA.Remote.String()+"/128", "dev", newA.Interface, "proto", "12", "metric", "1")
	route, err := exec.CommandContext(ctx, "ip", "-n", nsA, "-6", "route", "get", oldA.Remote.String()).CombinedOutput()
	if err != nil || !strings.Contains(string(route), "dev "+newA.Interface+" ") {
		t.Fatalf("unscoped route = %s (%v)", route, err)
	}
	existing := open()
	echo(existing)
	load(a, newA, oldA, v6A)
	// B has not installed the staged generation yet. A can continue on old.
	echo(open())
	load(b, newB, oldB, v6B)
	var ready bool
	for !ready && ctx.Err() == nil {
		a.pool.direct.warmStaged(a.directory.snapshotV2(), a.pool.directLinks.current())
		a.pool.direct.mu.Lock()
		for key, entry := range a.pool.direct.entries {
			if key.candidate.link.Generation == 2 && entry.ready {
				ready = true
			}
		}
		a.pool.direct.mu.Unlock()
		if !ready {
			time.Sleep(50 * time.Millisecond)
		}
	}
	if !ready {
		t.Fatal("staged generation never became ready")
	}
	newStream := open()
	echo(existing)
	load(a, newA, v6A)
	load(b, newB, v6B)
	ip("-n", nsA, "link", "del", oldA.Interface)
	echo(newStream)

	load(a, v6A)
	if _, err := client.open(ctx, target.Addr().String()); err == nil {
		t.Fatal("h2l4 silently used IPv6")
	}
	client.route = "to@h2l6"
	echo(open())

	udpTarget, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udpTarget.Close()
	go func() {
		var packet [128]byte
		count, address, err := udpTarget.ReadFromUDP(packet[:])
		if err == nil {
			_, _ = udpTarget.WriteToUDP(packet[:count], address)
		}
	}()
	udpStream, err := client.open(ctx, trusttunnel.UDPAuthority)
	if err != nil {
		t.Fatal(err)
	}
	defer udpStream.Close()
	packet := trusttunnel.Datagram{Source: netip.MustParseAddrPort("127.0.0.1:12345"),
		Destination: udpTarget.LocalAddr().(*net.UDPAddr).AddrPort(), Payload: []byte("link-local UDP")}
	if err := trusttunnel.WriteRequest(udpStream, packet); err != nil {
		t.Fatal(err)
	}
	response, err := trusttunnel.ReadResponse(udpStream)
	if err != nil || !bytes.Equal(response.Payload, packet.Payload) {
		t.Fatalf("UDP echo = %q (%v)", response.Payload, err)
	}
}

func reserveTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener := localTCP(t)
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}
