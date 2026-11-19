package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func trustTunnelFixture(t *testing.T) resolvedManifest {
	t.Helper()
	v := manifest{Version: 1, OutputDir: t.TempDir(), Networks: map[string]networkConfig{"main": {IPv6: "auto;::/112;::100/120;::1"}}, TrustTunnel: trustTunnelConfig{Publish: publishConfig{"main": "local"}, Networks: map[string]string{"main": "::22"}, AllowZones: []string{"*.catofes."}}}
	r, err := resolveManifest(v, []runtimeAssignment{{Prefix: "fd42:1::/64"}})
	if err != nil {
		t.Fatal(err)
	}
	r.ManagedZone = "node.catofes."
	return r
}

func TestTrustTunnelRenderPreservesTLSIdentity(t *testing.T) {
	v := trustTunnelFixture(t)
	if err := renderArtifacts(v); err != nil {
		t.Fatal(err)
	}
	lock, err := loadTrustTunnelLock(v.OutputDir, "resolved.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(lock.Fingerprint) != 64 || lock.Endpoints[0].Address != "fd42:1::22" {
		t.Fatal(lock)
	}
	data, _ := os.ReadFile(filepath.Join(v.OutputDir, "trusttunnel", "config.yaml"))
	var config map[string]any
	if err := yaml.Unmarshal(data, &config); err != nil {
		t.Fatal(err)
	}
	listener := config["listeners"].([]any)[0].(map[string]any)
	network := listener["network"].([]any)
	if len(network) != 1 || network[0] != "udp" || listener["type"] != "trusttunnel" {
		t.Fatal(listener)
	}
	if listener["congestion-controller"] != "bbr" {
		t.Fatalf("TrustTunnel listener must use BBR: %v", listener)
	}
	data, err = os.ReadFile(filepath.Join(v.OutputDir, "trusttunnel", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	var compose composeFile
	if err := yaml.Unmarshal(data, &compose); err != nil {
		t.Fatal(err)
	}
	if compose.Services["main"].Labels["io.photon.trusttunnel.congestion-controller"] != "bbr" {
		t.Fatal("Compose service must detect the switch to BBR")
	}
	if config["proxies"].([]any)[0].(map[string]any)["ip-version"] != "ipv4-prefer" || config["dns"].(map[string]any)["ipv6"] != true {
		t.Fatal("IPv4 preference must preserve IPv6 fallback", config)
	}
	keyPath := filepath.Join(v.OutputDir, "trusttunnel", "tls", "server.key")
	key, _ := os.ReadFile(keyPath)
	if err := renderArtifacts(v); err != nil {
		t.Fatal(err)
	}
	next, _ := loadTrustTunnelLock(v.OutputDir, "resolved.json")
	keyAgain, _ := os.ReadFile(keyPath)
	if next.Fingerprint != lock.Fingerprint || string(keyAgain) != string(key) {
		t.Fatal("render rotated active TLS identity")
	}
	info, _ := os.Stat(keyPath)
	if info.Mode().Perm() != 0o600 {
		t.Fatal(info.Mode())
	}
	if err := os.WriteFile(keyPath, []byte("bad key"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := renderArtifacts(v); err == nil {
		t.Fatal("invalid existing key overwritten")
	}
}

func TestTrustTunnelRejectsUnsafeManifest(t *testing.T) {
	v := trustTunnelFixture(t)
	base := trustTunnelConfig{Publish: publishConfig{"main": "local"}, Networks: map[string]string{"main": "::22"}, AllowZones: []string{"*."}}
	for _, change := range []func(*trustTunnelConfig){func(c *trustTunnelConfig) { c.AllowZones = nil }, func(c *trustTunnelConfig) { c.Publish = publishConfig{"main": "global"} }, func(c *trustTunnelConfig) { c.Networks = map[string]string{"main": "::100"} }, func(c *trustTunnelConfig) { c.Networks = map[string]string{"main": "::1"} }} {
		c := base
		change(&c)
		if _, err := resolveTrustTunnel(c, v.Networks); err == nil {
			t.Fatal("unsafe configuration accepted", c)
		}
	}
	network := v.Networks["main"]
	ipam := *network.IPv6
	ipam.Shared = true
	network.IPv6 = &ipam
	if _, err := resolveTrustTunnel(base, map[string]resolvedNetwork{"main": network}); err == nil {
		t.Fatal("shared assignment accepted")
	}
}

func TestTrustTunnelAndSOCKSBridgeFamilies(t *testing.T) {
	v := trustTunnelFixture(t)
	v.SOCKS5.Endpoints = []resolvedEndpoint{{Network: "main", Address: "172.30.0.20"}}
	if err := renderNetworkCompose(v); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(v.OutputDir, "networks", "docker-compose.yml"))
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		if !strings.Contains(string(data), "gateway_mode_"+family+": nat-unprotected") {
			t.Fatalf("%s service is unreachable through its Docker bridge: %s", family, data)
		}
	}
}

func TestTrustTunnelPublishWithdrawOrdering(t *testing.T) {
	v := trustTunnelFixture(t)
	if err := renderArtifacts(v); err != nil {
		t.Fatal(err)
	}
	bin := t.TempDir()
	curl := filepath.Join(bin, "curl")
	if err := os.WriteFile(curl, []byte("#!/bin/sh\nprintf '200 3'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("PATH", bin+string(os.PathListSeparator)+os.Getenv("PATH"))
	log := filepath.Join(t.TempDir(), "calls")
	photon := writeFakePhoton(t, log)
	probe := func(endpoint resolvedEndpoint, name, cert string, _ resolverConfig) error {
		return checkTrustTunnelHTTP3(endpoint, name, cert)
	}
	if err := publishTrustTunnelWithProbe(photon, v, probe); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(log)
	calls := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(calls) != 2 || !strings.HasPrefix(calls[0], "firewall endpoint apply trusttunnel-main") || !strings.HasPrefix(calls[1], "service publish --type trusttunnel") {
		t.Fatal(calls)
	}
	if err := withdrawTrustTunnel(photon, v.OutputDir); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(log)
	calls = strings.Split(strings.TrimSpace(string(data)), "\n")
	if calls[2] != "service withdraw --type trusttunnel" || calls[3] != "firewall endpoint remove trusttunnel-main" {
		t.Fatal(calls)
	}
	if err := os.WriteFile(curl, []byte("#!/bin/sh\nprintf '200 2'\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := publishTrustTunnelWithProbe(photon, v, probe); err == nil {
		t.Fatal("HTTP/2 fallback accepted")
	}
	after, _ := os.ReadFile(log)
	if string(after) != string(data) {
		t.Fatal("published without H3 readiness")
	}
}
