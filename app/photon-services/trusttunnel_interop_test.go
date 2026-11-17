package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// An opt-in real Mihomo client/server check. Targets are temporary listeners
// on this test host, and the server can be local or the selected pilot.
func TestTrustTunnelMihomoInterop(t *testing.T) {
	address := os.Getenv("PHOTON_TT_TEST_ADDRESS")
	if address == "" {
		t.Skip("opt-in real HTTP/3 server")
	}
	host, rawPort, err := net.SplitHostPort(address)
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := resolvedEndpoint{Address: host, Port: uint16(port)}
	name, cert := os.Getenv("PHOTON_TT_TEST_NAME"), os.Getenv("PHOTON_TT_TEST_CERT")
	if err := checkTrustTunnelHTTP3(endpoint, name, cert); err != nil {
		t.Fatal(err)
	}
	reserve, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	mixedPort := reserve.Addr().(*net.TCPAddr).Port
	reserve.Close()
	dir := t.TempDir()
	config := map[string]any{"mixed-port": mixedPort, "bind-address": "127.0.0.1", "allow-lan": false, "ipv6": true, "proxies": []any{map[string]any{"name": "pilot", "type": "trusttunnel", "server": host, "port": port, "username": "photon", "password": "", "quic": true, "udp": true, "sni": name, "fingerprint": os.Getenv("PHOTON_TT_TEST_PIN")}}, "rules": []string{"MATCH,pilot"}}
	data, _ := yaml.Marshal(config)
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	log, err := os.Create(filepath.Join(dir, "mihomo.log"))
	if err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	cmd := exec.Command(os.Getenv("PHOTON_TT_TEST_MIHOMO"), "-d", dir, "-f", configPath)
	cmd.Stdout, cmd.Stderr = log, log
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
		if t.Failed() {
			data, _ := os.ReadFile(log.Name())
			t.Log(string(data))
		}
	})
	proxy := net.JoinHostPort("127.0.0.1", strconv.Itoa(mixedPort))
	ready := false
	for until := time.Now().Add(5 * time.Second); time.Now().Before(until); {
		c, err := net.DialTimeout("tcp", proxy, 100*time.Millisecond)
		if err == nil {
			c.Close()
			ready = true
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !ready {
		t.Fatal("Mihomo client not ready")
	}
	targetURL := os.Getenv("PHOTON_TT_TEST_TCP_URL")
	if targetURL == "" {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("trusttunnel-tcp-ok")) }))
		defer server.Close()
		targetURL = server.URL
	}
	output, err := exec.Command("curl", "--noproxy", "", "--silent", "--show-error", "--max-time", "8", "--proxy", "socks5h://"+proxy, targetURL).CombinedOutput()
	if err != nil || string(output) != "trusttunnel-tcp-ok" {
		t.Fatalf("TCP through real HTTP/3: %v %s", err, output)
	}
	var targets []*net.UDPAddr
	for _, family := range []string{"4", "6"} {
		if raw := os.Getenv("PHOTON_TT_TEST_UDP" + family); raw != "" {
			target, err := net.ResolveUDPAddr("udp"+family, raw)
			if err != nil {
				t.Fatal(err)
			}
			targets = append(targets, target)
		}
	}
	for _, ip := range []string{"127.0.0.1", os.Getenv("PHOTON_TT_TEST_IPV6")} {
		if ip == "127.0.0.1" && os.Getenv("PHOTON_TT_TEST_UDP4") != "" {
			continue
		}
		if ip == "" {
			continue
		}
		network := "udp4"
		if net.ParseIP(ip).To4() == nil {
			network = "udp6"
		}
		listener, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(ip)})
		if err != nil {
			t.Fatal(err)
		}
		defer listener.Close()
		target := listener.LocalAddr().(*net.UDPAddr)
		targets = append(targets, target)
		go func() {
			packet := make([]byte, 65535)
			for {
				n, source, err := listener.ReadFromUDP(packet)
				if err != nil {
					return
				}
				_, _ = listener.WriteToUDP(packet[:n], source)
			}
		}()
	}
	for _, target := range targets {
		for _, size := range []int{32, 1200, 2048, 8192} {
			payload := bytes.Repeat([]byte{byte(size / 32)}, size)
			response, err := trustTunnelUDPExchange(endpoint, name, cert, target, payload, 6*time.Second)
			if err != nil || !bytes.Equal(response, payload) {
				t.Fatalf("direct H3 UDP %s %d bytes: %v", target, size, err)
			}
		}
	}
	probeMihomoDatagrams(t, proxy, targets)
	t.Log("TCP and multi-destination IPv4/IPv6 UDP payloads up to 8192 bytes passed through actual Mihomo HTTP/3 client/server")
}

func probeMihomoDatagrams(t *testing.T, proxy string, targets []*net.UDPAddr) {
	t.Helper()
	control, err := net.DialTimeout("tcp", proxy, 3*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer control.Close()
	control.SetDeadline(time.Now().Add(20 * time.Second))
	if _, err := control.Write([]byte{5, 1, 0}); err != nil {
		t.Fatal(err)
	}
	method := make([]byte, 2)
	if _, err := io.ReadFull(control, method); err != nil || !bytes.Equal(method, []byte{5, 0}) {
		t.Fatal(method, err)
	}
	if _, err := control.Write([]byte{5, 3, 0, 1, 0, 0, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	relay, err := readSOCKS5Reply(control)
	if err != nil {
		t.Fatal(err)
	}
	if relay.IP.IsUnspecified() {
		relay.IP = control.RemoteAddr().(*net.TCPAddr).IP
	}
	family := "udp4"
	if relay.IP.To4() == nil {
		family = "udp6"
	}
	udp, err := net.ListenUDP(family, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	for round := 0; round < 2; round++ {
		for _, target := range targets {
			for _, size := range []int{32, 1200, 2048, 8192} {
				payload := bytes.Repeat([]byte(fmt.Sprintf("udp-%d-", round)), size/6+1)[:size]
				udp.SetDeadline(time.Now().Add(6 * time.Second))
				if _, err := udp.WriteToUDP(append(socks5UDPHeader(target), payload...), relay); err != nil {
					t.Fatal(err)
				}
				packet := make([]byte, 65535)
				n, source, err := udp.ReadFromUDP(packet)
				if err != nil {
					t.Fatalf("Mihomo UDP %s %d: %v", target, size, err)
				}
				from, response, err := parseSOCKS5UDPDatagram(packet[:n])
				if err != nil || !source.IP.Equal(relay.IP) || source.Port != relay.Port || !from.IP.Equal(target.IP) || from.Port != target.Port || !bytes.Equal(response, payload) {
					t.Fatalf("UDP response mismatch: source=%v target=%v decoded=%v err=%v", source, target, from, err)
				}
			}
		}
	}
}
