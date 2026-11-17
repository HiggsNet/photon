package main

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

func startPlainMihomo(t *testing.T, kind string, auth proxyAuthConfig) string {
	t.Helper()
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	dir := t.TempDir()
	resolver, _ := normalizeResolver(resolverConfig{})
	path := filepath.Join(dir, "config.yaml")
	config := plainMihomoConfig(kind, uint16(port), resolver, auth)
	if err := writeYAMLMode(path, config, 0600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "mihomo.log"))
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Getenv("PHOTON_MIHOMO_TEST_BINARY"), "-d", dir, "-f", path)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		log.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		log.Close()
		if t.Failed() {
			data, _ := os.ReadFile(log.Name())
			t.Log(string(data))
		}
	})
	address := net.JoinHostPort("127.0.0.1", strconv.Itoa(port))
	readyTarget := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusNoContent) }))
	defer readyTarget.Close()
	scheme := "http"
	if kind == "socks" {
		scheme = "socks5"
	}
	proxy := &url.URL{Scheme: scheme, Host: address}
	if auth.Username != "" {
		proxy.User = url.UserPassword(auth.Username, auth.Password)
	}
	transport := &http.Transport{Proxy: http.ProxyURL(proxy)}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: time.Second}
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		response, err := client.Get(readyTarget.URL)
		if err == nil {
			response.Body.Close()
			if response.StatusCode == http.StatusNoContent {
				return address
			}
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("Mihomo listener not ready")
	return ""
}

func TestMihomoPlainProxyInterop(t *testing.T) {
	if os.Getenv("PHOTON_MIHOMO_TEST_BINARY") == "" {
		t.Skip("opt-in real Mihomo HTTP/SOCKS5 listeners")
	}
	const body = "photon-mihomo-interop"
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(body)) })
	plain := httptest.NewServer(handler)
	defer plain.Close()
	target := httptest.NewTLSServer(handler)
	defer target.Close()
	certs := x509.NewCertPool()
	certs.AddCert(target.Certificate())
	socks := startPlainMihomo(t, "socks", proxyAuthConfig{})
	for _, entry := range []struct {
		kind, scheme string
		auth         proxyAuthConfig
	}{{"socks", "socks5", proxyAuthConfig{}}, {"http", "http", proxyAuthConfig{}}, {"http", "http", proxyAuthConfig{Username: "custom", Password: "private"}}} {
		address := socks
		if entry.kind == "http" {
			address = startPlainMihomo(t, "http", entry.auth)
		}
		_, proxyPort, _ := net.SplitHostPort(address)
		for _, proxyHost := range []string{"127.0.0.1", "::1"} {
			proxy := &url.URL{Scheme: entry.scheme, Host: net.JoinHostPort(proxyHost, proxyPort)}
			if entry.auth.Username != "" {
				proxy.User = url.UserPassword(entry.auth.Username, entry.auth.Password)
			}
			transport := &http.Transport{Proxy: http.ProxyURL(proxy), TLSClientConfig: &tls.Config{RootCAs: certs}}
			client := &http.Client{Transport: transport, Timeout: 5 * time.Second}
			for _, u := range []string{plain.URL, target.URL} {
				response, err := client.Get(u)
				if err != nil {
					t.Fatal(entry.kind, u, err)
				}
				data, err := io.ReadAll(response.Body)
				response.Body.Close()
				if err != nil || response.StatusCode != 200 || string(data) != body {
					t.Fatalf("%s TCP payload %s: status=%d body=%q error=%v", entry.kind, u, response.StatusCode, data, err)
				}
			}
			transport.CloseIdleConnections()
		}
		if entry.auth.Username != "" {
			host, port, _ := net.SplitHostPort(address)
			n, _ := strconv.Atoi(port)
			if err := checkHTTPProxy(resolvedEndpoint{Address: host, Port: uint16(n)}, proxyAuthConfig{}, plain.URL); err == nil {
				t.Fatal("Mihomo accepted missing HTTP credentials")
			}
		}
	}
	var targets []*net.UDPAddr
	for _, ip := range []string{"127.0.0.1", "127.0.0.1", "::1"} {
		network := "udp4"
		if ip == "::1" {
			network = "udp6"
		}
		listener, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		targets = append(targets, listener.LocalAddr().(*net.UDPAddr))
		go func() {
			packet := make([]byte, 65535)
			for {
				n, from, err := listener.ReadFromUDP(packet)
				if err != nil {
					return
				}
				_, _ = listener.WriteToUDP(packet[:n], from)
			}
		}()
	}
	probeMihomoDatagrams(t, socks, targets)
	_, port, _ := net.SplitHostPort(socks)
	probeMihomoDatagrams(t, net.JoinHostPort("::1", port), targets)
	t.Log("actual Mihomo HTTP forward/CONNECT, private HTTP auth, SOCKS5 TCP, and multi-target IPv4/IPv6 UDP through 8192 bytes passed")
}
