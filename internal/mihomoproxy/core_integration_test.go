package mihomoproxy

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"runtime"
	"strconv"
	"testing"
	"time"

	"github.com/HiggsNet/photon/internal/photonwindows"
)

func TestMihomoOwnsPortAndWithdrawsExpiredOutlet(t *testing.T) {
	executable := os.Getenv("PHOTON_TEST_MIHOMO")
	if executable == "" {
		t.Skip("set PHOTON_TEST_MIHOMO to a standalone Mihomo executable")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 25*time.Second)
	defer cancel()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "ordinary")
	}))
	defer target.Close()
	template, err := ParseTemplate([]byte(`
proxy-groups:
  - {name: Manual, type: select, proxies: [REJECT, DIRECT]}
rules:
  - DOMAIN,photon-probe.invalid,Photon
  - MATCH,Manual
`))
	if err != nil {
		t.Fatal(err)
	}
	port := freeTCPPort(t)
	var core Core
	t.Cleanup(func() {
		if err := core.Stop(); err != nil {
			t.Error(err)
		}
	})
	if err := core.Start(ctx, executable, port, template); err != nil {
		t.Fatal(err)
	}
	proxy, _ := url.Parse("http://127.0.0.1:" + strconv.Itoa(int(port)))
	client := &http.Client{Timeout: time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy), DisableKeepAlives: true}}
	if err := core.Select(ctx, "Manual", "DIRECT"); err != nil {
		t.Fatal(err)
	}
	assertResponse(t, client, target.URL, "ordinary")
	if runtime.GOOS != "windows" {
		outlet, err := net.Listen("tcp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		defer outlet.Close()
		go serveFixtureOutlet(outlet)
		now := time.Now()
		directory := &photonwindows.ServiceDirectory{
			AdapterName: "lo", ObservedAt: now, ValidUntil: now.Add(2 * time.Second),
			Services: []photonwindows.ServiceEntry{{
				Owner: "probe.example.", Status: "active", Endpoints: []photonwindows.ServiceEndpoint{{
					Address: "127.0.0.1", Port: uint16(outlet.Addr().(*net.TCPAddr).Port), Region: "test",
				}},
			}},
		}
		if err := core.Sync(ctx, directory); err != nil {
			t.Fatal(err)
		}
		status, err := core.Status(ctx)
		if err != nil || !status.PhotonOnline {
			t.Fatalf("online status: %+v, %v", status, err)
		}
		assertResponse(t, client, "http://photon-probe.invalid/", "photon")
		deadline := time.NewTimer(time.Until(directory.ValidUntil.Add(3 * time.Second)))
		defer deadline.Stop()
		tick := time.NewTicker(50 * time.Millisecond)
		defer tick.Stop()
		for {
			status, err := core.Status(ctx)
			if err != nil {
				t.Fatal(err)
			}
			for _, group := range status.Groups {
				if group.Name == "Photon" && group.Selected == "REJECT" {
					goto withdrawn
				}
			}
			select {
			case <-deadline.C:
				t.Fatal("expired Photon outlet did not switch to REJECT")
			case <-tick.C:
			}
		}
	withdrawn:
		response, err := client.Get("http://photon-probe.invalid/")
		if err == nil {
			response.Body.Close()
			if response.StatusCode < 400 {
				t.Fatalf("expired outlet returned HTTP %d", response.StatusCode)
			}
		}
		// Mihomo may reset selectors on reload. The manager must keep the
		// ordinary user's explicit selection.
		assertResponse(t, client, target.URL, "ordinary")
	}
	if err := core.Stop(); err != nil {
		t.Fatal(err)
	}
	listener, err := net.Listen("tcp4", proxy.Host)
	if err != nil {
		t.Fatalf("owned proxy port was not released: %v", err)
	}
	listener.Close()
}

func freeTCPPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	return uint16(listener.Addr().(*net.TCPAddr).Port)
}

func assertResponse(t *testing.T, client *http.Client, target, want string) {
	t.Helper()
	response, err := client.Get(target)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(io.LimitReader(response.Body, 256))
	if response.StatusCode != 200 || string(body) != want || err != nil {
		t.Fatalf("proxy response: %s %q %v", response.Status, body, err)
	}
}

func serveFixtureOutlet(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer conn.Close()
			_ = conn.SetDeadline(time.Now().Add(time.Second))
			reader := bufio.NewReader(conn)
			greeting := make([]byte, 2)
			if _, err := io.ReadFull(reader, greeting); err != nil || greeting[0] != 5 {
				return
			}
			_, _ = io.CopyN(io.Discard, reader, int64(greeting[1]))
			_, _ = conn.Write([]byte{5, 0})
			var header [5]byte
			if _, err := io.ReadFull(reader, header[:]); err != nil || header[3] != 3 {
				return
			}
			_, _ = io.CopyN(io.Discard, reader, int64(header[4])+2)
			_, _ = conn.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 0})
			if _, err := http.ReadRequest(reader); err == nil {
				_, _ = fmt.Fprint(conn, "HTTP/1.1 200 OK\r\nContent-Length: 6\r\nConnection: close\r\n\r\nphoton")
			}
		}()
	}
}
